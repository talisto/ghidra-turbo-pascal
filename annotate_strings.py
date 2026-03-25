#!/usr/bin/env python3
"""
annotate_strings.py — Post-process decompiled.c to inline string annotations.

Borland Pascal stores strings as length-prefixed (Pascal) bytes in the code/data
segment. In decompiled 16-bit DOS code, display functions receive strings as
(segment, offset) integer pairs — so Ghidra outputs raw numbers with no hint of
what text is actually being displayed.

This script:
  1. Scans the EXE and OVR binaries for Pascal-format strings (1-byte length + text)
  2. Builds a map: { ghidra_linear_address -> string_text }
  3. For every line in decompiled.c that contains a constant (seg, off) pair
     matching a known string, adds an inline comment: /* "string text" */

Usage:
  python3 annotate_strings.py <decompiled.c> <exe-file> [ovr-file] [-o outfile]

If -o is omitted, writes <decompiled.annotated.c> alongside the input file.
"""

import sys
import re
import os
import struct

# ── Address mapping helpers ──────────────────────────────────────────────────

def exe_file_offset(ghidra_linear: int, exe_header_size: int) -> int:
    """Ghidra linear address → EXE file offset.
    Ghidra loads DOS MZ executables with base segment 0x1000 (linear 0x10000).
    """
    return ghidra_linear - 0x10000 + exe_header_size

def ovr_file_offset(ghidra_linear: int) -> int:
    """Ghidra OVR linear address → OVR file offset.
    OVR loaded at segment 0x8000 (linear 0x80000). FBOV header is 8 bytes.
    """
    return ghidra_linear - 0x80000 + 8

# ── String reading ───────────────────────────────────────────────────────────

def _is_lord_printable(b: int) -> bool:
    """Byte counts as printable for a LORD display string.
    Includes standard ASCII, LORD backtick colour codes, CP437 high bytes.
    """
    return (0x20 <= b <= 0x7e) or (0x80 <= b <= 0xfe) or b in (0x09, 0x0a, 0x0d)

def _render(raw: bytes) -> str:
    """Render raw Pascal string bytes to a human-readable summary.
    LORD uses backtick colour codes like `2, `0, `%, `4, `5, `c.
    Control bytes 0x01-0x1f with printable context are format markers.
    """
    out = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x60 and i + 1 < len(raw):          # backtick colour code
            out.append(f'`{chr(raw[i+1])}')
            i += 2
            continue
        if 0x20 <= b <= 0x7e:
            out.append(chr(b))
        elif b == 0x0a:
            out.append('\\n')
        elif b == 0x0d:
            out.append('\\r')
        elif b == 0x09:
            out.append('\\t')
        elif b == 0x01:
            out.append(' ')               # common separator in LORD
        elif 0x02 <= b <= 0x1f:
            out.append(f'\\x{b:02x}')    # other control; keep visible
        else:
            out.append(chr(b))           # CP437 high byte
        i += 1
    return ''.join(out)

def try_read_pascal(data: bytes, offset: int, min_len: int = 3, max_len: int = 200,
                    min_letter_ratio: float = 0.50):
    """Try to read a Pascal length-prefixed string at data[offset].
    Returns (rendered_string, length_byte) on success, None otherwise.

    The returned length_byte lets callers skip past the string to avoid
    creating overlapping entries in the string database.

    Validation rules:
    - The length byte must indicate min_len..max_len content bytes
    - At least 60% of content bytes must be letter/digit/space/punctuation
    - At least 50% must be standard printable ASCII
    - The first 3 content bytes must all be "displayable" (printable ASCII,
      backtick colour code, or LORD control byte 0x01-0x1F that a display
      function could interpret) — this catches false positives where machine
      code bytes precede a real string in memory
    """
    if offset < 0 or offset + 1 >= len(data):
        return None
    plen = data[offset]
    if plen < min_len or plen > max_len:
        return None
    if offset + 1 + plen > len(data):
        return None
    raw = data[offset + 1: offset + 1 + plen]

    # --- Clean-start check ---
    # Byte 0 (first content byte) must be printable ASCII (0x20-0x7e).
    # LORD strings always start with visible text, a space, or a backtick colour
    # code.  Control bytes 0x01-0x1f appear as placeholder tokens WITHIN strings
    # but never at position 0.
    b0 = raw[0]
    if not (0x20 <= b0 <= 0x7e):
        return None

    # Bytes 1 through 5 must be printable ASCII (0x20-0x7e).  Real LORD
    # strings consist of text, spaces, and backtick colour codes — all
    # printable.  Allowing control codes (0x01-0x1f) here was too permissive
    # and let machine-code bytes like 0x17, 0x1e pass, creating false long
    # strings that swallowed real adjacent strings.
    for i in range(1, min(6, plen)):
        b = raw[i]
        if not (0x20 <= b <= 0x7e):
            return None

    # --- Clean-tail check ---
    # The last 5 bytes must also be free of high CP437 bytes (0x80-0xFF).
    # Real strings end with text; a span that ends in machine code means the
    # length byte overshot the actual string boundary.
    tail_start = max(0, plen - 5)
    for i in range(tail_start, plen):
        if raw[i] >= 0x80:
            return None

    # Count "letter-like" bytes: ASCII letters, digits, space, common punctuation
    letter_bytes = sum(1 for b in raw
                       if (0x41 <= b <= 0x5a)   # A-Z
                       or (0x61 <= b <= 0x7a)    # a-z
                       or (0x30 <= b <= 0x39)    # 0-9
                       or b in (0x20, 0x21, 0x22, 0x27, 0x28, 0x29,  # space ! " ' ( )
                                0x2c, 0x2e, 0x3a, 0x3f,               # , . : ?
                                0x60))                                  # backtick (LORD color)
    if letter_bytes < plen * min_letter_ratio:
        return None

    # Also require overall printability to catch truly garbled data
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    if printable < plen * 0.50:
        return None

    return (_render(raw), plen)

# ── String database builder ────────────────────────────────────────────────

def build_string_db(exe_data: bytes, exe_header: int,
                    ovr_data: bytes | None) -> dict[int, str]:
    """Scan EXE and OVR for Pascal strings.
    Returns { ghidra_linear_address: rendered_string }.

    After finding a valid Pascal string at offset N with length L, skips to
    offset N+1+L (the next byte after the string content).  This avoids
    creating thousands of false substring entries where content bytes within
    a real string look like valid length bytes for overlapping "sub-strings".
    Packed adjacent strings are still found because the skip lands exactly
    on the next string's length byte.
    """
    db: dict[int, str] = {}

    # Scan EXE code+data (everything after the MZ header)
    exe_code_start = exe_header
    fo = exe_code_start
    while fo < len(exe_data) - 2:
        result = try_read_pascal(exe_data, fo)
        if result is not None:
            text, plen = result
            ghidra_linear = (fo - exe_code_start) + 0x10000
            db[ghidra_linear] = text
            fo += 1 + plen          # skip past this string
        else:
            fo += 1

    # Scan OVR data (skip 8-byte FBOV header)
    if ovr_data is not None and len(ovr_data) > 8:
        fo = 8
        while fo < len(ovr_data) - 2:
            result = try_read_pascal(ovr_data, fo)
            if result is not None:
                text, plen = result
                ghidra_linear = (fo - 8) + 0x80000
                db[ghidra_linear] = text
                fo += 1 + plen      # skip past this string
            else:
                fo += 1

    return db

# ── Call-pattern matching ─────────────────────────────────────────────────

# Matches a hex constant like 0x1234 or 0X1234
_HEX = r'0[xX][0-9a-fA-F]+'
# Matches a decimal integer (possibly negative)
_DEC = r'-?\d+'
# Any constant
_CONST = r'(?:' + _HEX + r'|' + _DEC + r')'

# Pattern: two adjacent constants as call arguments: CONST , CONST
# We capture them and check if (seg, off) yields a string.
_PAIR_RE = re.compile(
    r'(' + _CONST + r')'       # group 1: first constant
    r'\s*,\s*'
    r'(' + _CONST + r')'       # group 2: second constant
)

def _parse_int(s: str) -> int | None:
    try:
        return int(s, 0)
    except ValueError:
        return None

# ── Address mapping for Borland Pascal DOS EXEs ────────────────────────────
#
# Ghidra loads MZ EXEs at base segment 0x1000 (linear 0x10000).  The string
# database keys are:  image_offset + 0x10000  (where image_offset = file_offset
# minus the MZ header size).
#
# In Borland Pascal decompiled output, display functions like
#   FUN_265c_0002(0x2f, 0x32e9)
# pass TWO constants: the first is the string's *image offset* within the EXE
# code+data area; the second is the Borland Pascal unit's data-segment selector
# (which Ghidra rebased by +0x1000).  The segment value is NOT part of the
# address calculation — it's an artefact of the far-call ABI.
#
# Therefore the DB lookup key is simply:  first_arg + 0x10000
# (or second_arg + 0x10000 — we try both in case Ghidra swaps argument order).
#
# For overlays loaded at segment 0x8000, the key is:  arg + 0x80000.

_EXE_IMAGE_BASE = 0x10000
_OVR_IMAGE_BASE = 0x80000

def _is_segment_like(v: int) -> bool:
    """Plausible 16-bit Borland Pascal segment selector: 0x1000 – 0x7FFF for EXE,
    or 0x8000 – 0xA000 for overlay."""
    return (0x1000 <= v <= 0x7FFF) or (0x8000 <= v <= 0xA000)

def annotate_line(line: str, db: dict[int, str]) -> str:
    """Given one C source line, return it with any string annotations appended.

    For each pair of hex constants (a, b) in the line, if one looks like a
    Borland Pascal segment selector, treat the OTHER as a direct image offset
    and look up (image_offset + image_base) in the string database.

    Falls back to single-constant matching: any hex constant on the line is
    tried against the string DB (with EXE and OVR image bases).  This catches
    cases where Ghidra decompiles the calling convention differently (e.g.,
    stack-push patterns in startup code, or WriteLn calls in simple programs).
    """
    found: list[str] = []
    seen_addrs: set[int] = set()

    # --- Pass 1: paired constants (original logic) ---
    for m in _PAIR_RE.finditer(line):
        a = _parse_int(m.group(1))
        b = _parse_int(m.group(2))
        if a is None or b is None:
            continue

        # Build candidates: (image_offset, image_base)
        # When both values are segment-like, prefer the ordering where the
        # LARGER value is the segment (BP data segments like 0x32e9 are always
        # larger than the string offsets they pair with).
        candidates: list[tuple[int, int]] = []

        b_is_seg = _is_segment_like(b) and 0 <= a <= 0xFFFF
        a_is_seg = _is_segment_like(a) and 0 <= b <= 0xFFFF

        if b_is_seg and a_is_seg:
            # Both look like segments — try the larger one as segment first
            if b >= a:
                base = _OVR_IMAGE_BASE if b >= 0x8000 else _EXE_IMAGE_BASE
                candidates.append((a, base))
                base = _OVR_IMAGE_BASE if a >= 0x8000 else _EXE_IMAGE_BASE
                candidates.append((b, base))
            else:
                base = _OVR_IMAGE_BASE if a >= 0x8000 else _EXE_IMAGE_BASE
                candidates.append((b, base))
                base = _OVR_IMAGE_BASE if b >= 0x8000 else _EXE_IMAGE_BASE
                candidates.append((a, base))
        elif b_is_seg:
            base = _OVR_IMAGE_BASE if b >= 0x8000 else _EXE_IMAGE_BASE
            candidates.append((a, base))
        elif a_is_seg:
            base = _OVR_IMAGE_BASE if a >= 0x8000 else _EXE_IMAGE_BASE
            candidates.append((b, base))

        for img_off, base in candidates:
            addr = img_off + base
            if addr in seen_addrs:
                continue
            s = db.get(addr)
            if s is not None:
                seen_addrs.add(addr)
                display = s[:120] + ('…' if len(s) > 120 else '')
                display = display.replace('*/', '*\\/')
                found.append(f'/* "{display}" */')
                break  # one match per constant pair is enough

    # --- Pass 2: single-constant fallback ---
    # When no pair match is found, try every hex constant on the line.
    # This catches Ghidra output where stack pushes or direct arguments
    # don't appear as clean (a, b) pairs.
    # Skip very small constants (0x0-0x10) as they produce false positives
    # (common in pointer/size arithmetic, not string references).
    # Also skip lines that are comments or contain WARNING.
    if not found and '/* WARNING' not in line:
        for m in re.finditer(_HEX, line):
            v = _parse_int(m.group(0))
            if v is None or v > 0xFFFF or v < 0x11:
                continue
            # Skip constants in pointer arithmetic contexts:
            #   puVar8 + -0x10a,  *(type *)(var + 0xNN),  var - 0xNN
            # These are stack/struct offsets, not string literal offsets.
            prefix = line[max(0, m.start() - 4):m.start()]
            if re.search(r'[+\-]\s*-?\s*$', prefix):
                continue
            for base in (_EXE_IMAGE_BASE, _OVR_IMAGE_BASE):
                addr = v + base
                if addr in seen_addrs:
                    continue
                s = db.get(addr)
                if s is not None:
                    seen_addrs.add(addr)
                    display = s[:120] + ('…' if len(s) > 120 else '')
                    display = display.replace('*/', '*\\/')
                    found.append(f'/* "{display}" */')
                    break

    if not found:
        return line
    stripped = line.rstrip('\n')
    annotation = '  ' + '  '.join(found)
    return stripped + annotation + '\n'

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    # Parse args
    src_file = None
    exe_file = None
    ovr_file = None
    out_file = None
    i = 0
    while i < len(args):
        if args[i] == '-o' and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        elif src_file is None:
            src_file = args[i]; i += 1
        elif exe_file is None:
            exe_file = args[i]; i += 1
        elif ovr_file is None:
            ovr_file = args[i]; i += 1
        else:
            i += 1

    if not src_file or not exe_file:
        print("Usage: annotate_strings.py <decompiled.c> <exe-file> [ovr-file] [-o outfile]",
              file=sys.stderr)
        sys.exit(1)

    if out_file is None:
        base, ext = os.path.splitext(src_file)
        out_file = base + '.annotated' + ext

    # Load binaries
    with open(exe_file, 'rb') as f:
        exe_data = f.read()
    e_cparhdr = struct.unpack_from('<H', exe_data, 8)[0]
    exe_header = e_cparhdr * 16

    ovr_data = None
    if ovr_file and os.path.exists(ovr_file):
        with open(ovr_file, 'rb') as f:
            ovr_data = f.read()
        if ovr_data[:4] != b'FBOV':
            print(f"Warning: {ovr_file} does not have FBOV magic — skipping OVR",
                  file=sys.stderr)
            ovr_data = None

    # Build string database
    print(f"Building string database from {exe_file}", end='', flush=True)
    if ovr_data:
        print(f" + {ovr_file}", end='', flush=True)
    print(" ...", flush=True)
    db = build_string_db(exe_data, exe_header, ovr_data)
    print(f"  {len(db):,} string candidates found")

    # Annotate
    with open(src_file, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    annotated = 0
    out_lines = []
    for line in lines:
        new_line = annotate_line(line, db)
        if new_line != line:
            annotated += 1
        out_lines.append(new_line)

    with open(out_file, 'w', encoding='utf-8') as f:
        f.writelines(out_lines)

    print(f"  {annotated:,} lines annotated")
    print(f"  Written to: {out_file}")

if __name__ == '__main__':
    main()
