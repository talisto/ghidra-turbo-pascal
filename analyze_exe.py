#!/usr/bin/env python3
"""
analyze_exe.py — Extract structural information from Borland Pascal DOS EXEs.

Produces a detailed report including:
  - EXE header fields
  - Relocation table dump with segment→Ghidra mapping
  - Borland Pascal unit/segment map
  - Complete string table with image offsets
  - Display-function cross-reference (which strings are used where)
  - Function prologue analysis

Usage:
  python3 analyze_exe.py <exe-file> [--strings] [--relocs] [--xref <decompiled.c>] [--all]

Flags:
  --strings   Emit the complete string table
  --relocs    Emit the full relocation table
  --xref FILE Cross-reference strings with display calls in decompiled.c
  --all       Enable all outputs
  -o FILE     Write output to file (default: stdout)
"""

import sys
import os
import struct
import re
from collections import defaultdict

# ── Pascal string reader ─────────────────────────────────────────────────────

def _is_displayable_start(b: int) -> bool:
    return 0x20 <= b <= 0x7e

def try_read_pascal(data: bytes, offset: int, min_len: int = 3, max_len: int = 200):
    """Read a Pascal length-prefixed string. Returns (text, length) or None."""
    if offset < 0 or offset + 1 >= len(data):
        return None
    plen = data[offset]
    if plen < min_len or plen > max_len:
        return None
    if offset + 1 + plen > len(data):
        return None
    raw = data[offset + 1: offset + 1 + plen]

    b0 = raw[0]
    if not (0x20 <= b0 <= 0x7e):
        return None
    for i in range(1, min(6, plen)):
        if not ((0x20 <= raw[i] <= 0x7e) or (0x01 <= raw[i] <= 0x1f)):
            return None
    for i in range(max(0, plen - 5), plen):
        if raw[i] >= 0x80:
            return None

    letter_bytes = sum(1 for b in raw
                       if (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a)
                       or (0x30 <= b <= 0x39)
                       or b in (0x20, 0x21, 0x22, 0x27, 0x28, 0x29,
                                0x2c, 0x2e, 0x3a, 0x3f, 0x60))
    if letter_bytes < plen * 0.50:
        return None
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    if printable < plen * 0.50:
        return None

    # Render
    out = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x60 and i + 1 < len(raw):
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
        else:
            out.append(f'\\x{b:02x}')
        i += 1
    return (''.join(out), plen)


# ── EXE Header Parser ───────────────────────────────────────────────────────

def parse_exe_header(data: bytes) -> dict:
    """Parse the MZ EXE header fields."""
    if len(data) < 28 or data[:2] not in (b'MZ', b'ZM'):
        raise ValueError("Not a valid MZ EXE file")

    fields = {}
    fields['magic'] = data[:2].decode('ascii')
    fields['last_page_bytes'] = struct.unpack_from('<H', data, 2)[0]
    fields['pages'] = struct.unpack_from('<H', data, 4)[0]
    fields['reloc_count'] = struct.unpack_from('<H', data, 6)[0]
    fields['header_paras'] = struct.unpack_from('<H', data, 8)[0]
    fields['header_bytes'] = fields['header_paras'] * 16
    fields['min_alloc'] = struct.unpack_from('<H', data, 10)[0]
    fields['max_alloc'] = struct.unpack_from('<H', data, 12)[0]
    fields['init_ss'] = struct.unpack_from('<H', data, 14)[0]
    fields['init_sp'] = struct.unpack_from('<H', data, 16)[0]
    fields['checksum'] = struct.unpack_from('<H', data, 18)[0]
    fields['init_ip'] = struct.unpack_from('<H', data, 20)[0]
    fields['init_cs'] = struct.unpack_from('<H', data, 22)[0]
    fields['reloc_offset'] = struct.unpack_from('<H', data, 24)[0]
    fields['overlay'] = struct.unpack_from('<H', data, 26)[0]

    # Compute image size
    img_size = (fields['pages'] - 1) * 512 + fields['last_page_bytes']
    if fields['last_page_bytes'] == 0:
        img_size = fields['pages'] * 512
    fields['image_size'] = img_size
    fields['code_data_size'] = img_size - fields['header_bytes']

    return fields


# ── Relocation Table Parser ─────────────────────────────────────────────────

def parse_relocations(data: bytes, header: dict) -> list[dict]:
    """Parse EXE relocation entries. Returns list of {offset, segment, image_off, original_value}."""
    relocs = []
    reloc_off = header['reloc_offset']
    hdr_bytes = header['header_bytes']

    for i in range(header['reloc_count']):
        entry_off = reloc_off + i * 4
        r_off = struct.unpack_from('<H', data, entry_off)[0]
        r_seg = struct.unpack_from('<H', data, entry_off + 2)[0]
        image_off = r_seg * 16 + r_off
        file_off = image_off + hdr_bytes

        orig_val = None
        if file_off + 1 < len(data):
            orig_val = struct.unpack_from('<H', data, file_off)[0]

        relocs.append({
            'reloc_seg': r_seg,
            'reloc_off': r_off,
            'image_off': image_off,
            'file_off': file_off,
            'original_value': orig_val,
        })

    return relocs


# ── Segment Map Builder ─────────────────────────────────────────────────────

GHIDRA_BASE_SEG = 0x1000

def build_segment_map(relocations: list[dict]) -> list[dict]:
    """Build a map of unique Borland Pascal segments from relocation entries.
    Returns sorted list of {original_seg, ghidra_seg, image_offset, ref_count}.
    """
    seg_counts: dict[int, int] = defaultdict(int)
    for r in relocations:
        if r['original_value'] is not None:
            seg_counts[r['original_value']] += 1

    segments = []
    for orig_seg, count in sorted(seg_counts.items()):
        segments.append({
            'original_seg': orig_seg,
            'ghidra_seg': orig_seg + GHIDRA_BASE_SEG,
            'image_offset': orig_seg * 16,
            'ref_count': count,
        })
    return segments


# ── String Table Builder ────────────────────────────────────────────────────

def build_string_table(data: bytes, hdr_bytes: int) -> list[dict]:
    """Scan EXE for Pascal strings. Returns list of {image_off, ghidra_addr, length, text}.
    Deduplicates overlapping strings by keeping only non-overlapping entries.
    """
    raw_strings = []
    i = hdr_bytes
    while i < len(data) - 1:
        result = try_read_pascal(data, i)
        if result is not None:
            text, plen = result
            img_off = i - hdr_bytes
            raw_strings.append({
                'image_off': img_off,
                'ghidra_addr': img_off + 0x10000,
                'file_off': i,
                'length': plen,
                'text': text,
            })
            # Skip past this string to avoid overlapping entries
            i += 1 + plen
        else:
            i += 1

    return raw_strings


# ── Cross-reference Builder ─────────────────────────────────────────────────

_HEX = r'0[xX][0-9a-fA-F]+'
_PAIR_RE = re.compile(r'(' + _HEX + r')\s*,\s*(' + _HEX + r')')
_FUNC_RE = re.compile(r'(FUN_[0-9a-f]+_[0-9a-f]+|_\w+)\s*\(')

# Known display/string functions by their offset within their segment
KNOWN_DISPLAY_FUNCS = {
    '0002': 'lw (write inline)',
    '02a8': 'lln (write line)',
    '054e': 'sln (blank line)',
}

KNOWN_STRING_FUNCS = {
    '3f4b': 'str_assign',
    '3f65': 'str_copy',
    '3fca': 'str_concat',
    '4067': 'char_to_str',
    # Borland Pascal RTL: assigns a constant string from segment data.
    # Called as _Delete_qm6String7Integert2(local_off, seg) where local_off
    # is a segment-relative offset into the unit's data area.  The string
    # lives at image_off = (seg - 0x1000) * 16 + local_off.
    '_delete_qm6string7integert2': 'bp_str_assign_const (segment-relative)',
}

def build_xref(decompiled_path: str, string_table: list[dict]) -> list[dict]:
    """Cross-reference decompiled.c display calls with string table entries.
    Returns list of {line_num, function, call_func, image_off, text}.
    """
    # Build image_off → text lookup
    str_lookup = {s['image_off']: s['text'] for s in string_table}

    xrefs = []
    current_func = "unknown"

    with open(decompiled_path, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            # Track current function
            func_match = re.match(r'.*?(\w+)\s*\(', line)
            if line.strip().startswith('//') and 'Function:' in line:
                parts = line.split('Function:')
                if len(parts) > 1:
                    current_func = parts[1].strip().split()[0]

            # Find constant pairs
            for m in _PAIR_RE.finditer(line):
                a = int(m.group(1), 16)
                b = int(m.group(2), 16)

                # Determine calling function name for the xref record
                call_func = "?"
                fm = _FUNC_RE.search(line[:m.start()])
                if fm:
                    call_func = fm.group(1)

                # Try a as image offset (b as segment selector)
                if a in str_lookup and 0x1000 <= b <= 0x7FFF:
                    xrefs.append({
                        'line_num': line_num,
                        'function': current_func,
                        'call_func': call_func,
                        'image_off': a,
                        'segment': b,
                        'text': str_lookup[a],
                    })
                # Try b as image offset (a as segment selector)
                # Ghidra may swap argument order in some calling conventions.
                elif b in str_lookup and 0x1000 <= a <= 0x7FFF:
                    xrefs.append({
                        'line_num': line_num,
                        'function': current_func,
                        'call_func': call_func,
                        'image_off': b,
                        'segment': a,
                        'text': str_lookup[b],
                    })
                else:
                    # Segment-relative path: for cross-unit string references
                    # (e.g. _Delete_qm6String7Integert2(local_off, seg)),
                    # local_off is an offset *within* the segment's data area.
                    # image_off = (seg - 0x1000) * 16 + local_off
                    for offset, seg in ((a, b), (b, a)):
                        if 0x1000 <= seg <= 0x7FFF:
                            img_off = (seg - 0x1000) * 16 + offset
                            if img_off in str_lookup:
                                xrefs.append({
                                    'line_num': line_num,
                                    'function': current_func,
                                    'call_func': call_func,
                                    'image_off': img_off,
                                    'segment': seg,
                                    'text': str_lookup[img_off],
                                })
                                break

    return xrefs


# ── Function Prologue Detector ──────────────────────────────────────────────

def find_function_prologues(data: bytes, hdr_bytes: int) -> list[dict]:
    """Find Borland Pascal function prologues in the code.
    Common patterns:
      55 89 E5    push bp; mov bp, sp  (standard frame setup)
      55 8B EC    push bp; mov bp, sp  (alternate encoding)
      C8 xx xx 00 enter xx, 0          (ENTER instruction)
    """
    prologues = []
    i = hdr_bytes
    end = len(data) - 3

    while i < end:
        # push bp; mov bp, sp (55 89 E5)
        if data[i] == 0x55 and data[i+1] == 0x89 and data[i+2] == 0xE5:
            prologues.append({
                'image_off': i - hdr_bytes,
                'type': 'push bp; mov bp, sp',
            })
            i += 3
            continue

        # push bp; mov bp, sp (55 8B EC)
        if data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
            prologues.append({
                'image_off': i - hdr_bytes,
                'type': 'push bp; mov bp, sp (alt)',
            })
            i += 3
            continue

        # ENTER instruction (C8 xx xx 00)
        if data[i] == 0xC8 and i + 3 < end and data[i+3] == 0x00:
            frame_size = struct.unpack_from('<H', data, i+1)[0]
            prologues.append({
                'image_off': i - hdr_bytes,
                'type': f'enter {frame_size}',
            })
            i += 4
            continue

        i += 1

    return prologues


# ── Report Generators ───────────────────────────────────────────────────────

def report_header(header: dict, out):
    print("=" * 72, file=out)
    print("EXE HEADER", file=out)
    print("=" * 72, file=out)
    print(f"  Magic:          {header['magic']}", file=out)
    print(f"  Image size:     {header['image_size']:,} bytes ({header['image_size']:#x})", file=out)
    print(f"  Header size:    {header['header_bytes']:,} bytes ({header['header_bytes']:#x})", file=out)
    print(f"  Code+data size: {header['code_data_size']:,} bytes ({header['code_data_size']:#x})", file=out)
    print(f"  Relocations:    {header['reloc_count']:,} (at file offset {header['reloc_offset']:#x})", file=out)
    print(f"  CS:IP           {header['init_cs']:#06x}:{header['init_ip']:#06x}", file=out)
    print(f"  SS:SP           {header['init_ss']:#06x}:{header['init_sp']:#06x}", file=out)
    print(f"  Min alloc:      {header['min_alloc']:#x} paragraphs", file=out)
    print(f"  Max alloc:      {header['max_alloc']:#x} paragraphs", file=out)
    print(f"  Ghidra base:    segment {GHIDRA_BASE_SEG:#06x} (linear {GHIDRA_BASE_SEG * 16:#x})", file=out)
    print(file=out)


def report_segments(segments: list[dict], header: dict, out):
    print("=" * 72, file=out)
    print("BORLAND PASCAL SEGMENT MAP", file=out)
    print("=" * 72, file=out)
    print(f"{'Orig Seg':>10} {'Ghidra Seg':>12} {'Image Offset':>14} {'File Offset':>14} {'Refs':>6}", file=out)
    print("-" * 60, file=out)
    for seg in segments:
        file_off = seg['image_offset'] + header['header_bytes']
        print(f"  {seg['original_seg']:#06x}   {seg['ghidra_seg']:#06x}   "
              f"  {seg['image_offset']:#010x}   {file_off:#010x}   {seg['ref_count']:5d}", file=out)
    print(f"\n  Total unique segments: {len(segments)}", file=out)

    # Identify likely segment roles
    if segments:
        print("\n  Segment roles (heuristic):", file=out)
        # Entry CS segment
        cs_orig = header['init_cs']
        ss_orig = header['init_ss']
        # Sort by ref count descending to identify system RTL (highest refs)
        by_refs = sorted(segments, key=lambda s: -s['ref_count'])
        most_refs_seg = by_refs[0]['original_seg'] if by_refs else None
        # The lowest segment address is usually the main program entry
        lowest_seg = min(segments, key=lambda s: s['original_seg'])
        # The highest segment is usually the data/BSS segment
        highest_seg = max(segments, key=lambda s: s['original_seg'])

        for seg in segments:
            roles = []
            if seg['original_seg'] == cs_orig:
                roles.append("ENTRY CS (main program code)")
            if seg['original_seg'] == ss_orig:
                roles.append("STACK SEGMENT")
            if seg['original_seg'] == most_refs_seg and seg['ref_count'] > 5:
                roles.append("most referenced (likely System RTL)")
            elif seg['ref_count'] > 100:
                roles.append("heavily referenced (likely core library)")
            if seg == highest_seg and seg != lowest_seg and len(segments) > 1:
                roles.append("highest segment (likely data/BSS)")
            if seg == lowest_seg and len(segments) > 1:
                if seg['original_seg'] != cs_orig:
                    roles.append("lowest segment (likely main program unit)")
            if roles:
                print(f"    {seg['ghidra_seg']:#06x}: {', '.join(roles)}", file=out)
    print(file=out)


def report_relocations(relocations: list[dict], out):
    print("=" * 72, file=out)
    print("RELOCATION TABLE", file=out)
    print("=" * 72, file=out)
    print(f"{'#':>5} {'Reloc Pos':>12} {'Image Off':>12} {'Orig Value':>12} {'Ghidra Seg':>12}", file=out)
    print("-" * 56, file=out)
    for i, r in enumerate(relocations):
        ghidra = (r['original_value'] + GHIDRA_BASE_SEG) if r['original_value'] is not None else 0
        print(f"  {i:4d}  {r['reloc_seg']:#06x}:{r['reloc_off']:#06x}  "
              f"{r['image_off']:#010x}  {r['original_value']:#06x}  {ghidra:#06x}", file=out)
    print(file=out)


def report_strings(string_table: list[dict], out):
    print("=" * 72, file=out)
    print("STRING TABLE", file=out)
    print("=" * 72, file=out)
    print(f"  Total strings: {len(string_table):,}", file=out)
    print(file=out)
    print(f"{'Image Off':>12} {'Ghidra Addr':>14} {'Len':>5}  {'Text'}", file=out)
    print("-" * 72, file=out)
    for s in string_table:
        text = s['text'][:100] + ('...' if len(s['text']) > 100 else '')
        print(f"  {s['image_off']:#010x}  {s['ghidra_addr']:#010x}  {s['length']:4d}  {text}", file=out)
    print(file=out)


def report_xref(xrefs: list[dict], out):
    print("=" * 72, file=out)
    print("STRING CROSS-REFERENCE", file=out)
    print("=" * 72, file=out)
    print(f"  Total references: {len(xrefs):,}", file=out)
    print(file=out)

    # Group by function
    by_func = defaultdict(list)
    for x in xrefs:
        by_func[x['function']].append(x)

    for func in sorted(by_func.keys()):
        refs = by_func[func]
        print(f"  {func}:", file=out)
        for r in refs:
            text = r['text'][:80] + ('...' if len(r['text']) > 80 else '')
            seg_str = f"seg={r['segment']:#06x}"
            print(f"    L{r['line_num']:5d}  {r['call_func']:30s}  "
                  f"img={r['image_off']:#08x}  {seg_str}  \"{text}\"", file=out)
        print(file=out)


def report_prologues(prologues: list[dict], out):
    print("=" * 72, file=out)
    print("FUNCTION PROLOGUES", file=out)
    print("=" * 72, file=out)
    print(f"  Total detected: {len(prologues):,}", file=out)
    type_counts = defaultdict(int)
    for p in prologues:
        type_counts[p['type']] += 1
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}", file=out)
    print(file=out)


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    exe_file = None
    out_file = None
    xref_file = None
    show_strings = False
    show_relocs = False
    show_all = False

    i = 0
    while i < len(args):
        if args[i] == '-o' and i + 1 < len(args):
            out_file = args[i + 1]; i += 2
        elif args[i] == '--xref' and i + 1 < len(args):
            xref_file = args[i + 1]; i += 2
        elif args[i] == '--strings':
            show_strings = True; i += 1
        elif args[i] == '--relocs':
            show_relocs = True; i += 1
        elif args[i] == '--all':
            show_all = True; i += 1
        elif exe_file is None:
            exe_file = args[i]; i += 1
        else:
            i += 1

    if not exe_file:
        print("Usage: analyze_exe.py <exe-file> [options]", file=sys.stderr)
        sys.exit(1)

    if show_all:
        show_strings = True
        show_relocs = True

    # Load binary
    with open(exe_file, 'rb') as f:
        data = f.read()

    header = parse_exe_header(data)
    hdr_bytes = header['header_bytes']

    out = sys.stdout
    out_fh = None
    if out_file:
        out_fh = open(out_file, 'w', encoding='utf-8')
        out = out_fh

    try:
        print(f"Analyzing: {exe_file}", file=out)
        print(f"File size: {len(data):,} bytes", file=out)
        print(file=out)

        # Always show header
        report_header(header, out)

        # Parse relocations (needed for segment map)
        relocations = parse_relocations(data, header)
        segments = build_segment_map(relocations)
        report_segments(segments, header, out)

        # Full relocation dump (optional)
        if show_relocs:
            report_relocations(relocations, out)

        # String table
        print("Scanning for strings...", file=sys.stderr, flush=True)
        string_table = build_string_table(data, hdr_bytes)
        if show_strings:
            report_strings(string_table, out)
        else:
            print(f"  String table: {len(string_table):,} entries "
                  f"(use --strings to show full table)", file=out)
            print(file=out)

        # Cross-reference
        if xref_file and os.path.exists(xref_file):
            print("Building cross-reference...", file=sys.stderr, flush=True)
            xrefs = build_xref(xref_file, string_table)
            report_xref(xrefs, out)

        # Function prologues
        print("Detecting function prologues...", file=sys.stderr, flush=True)
        prologues = find_function_prologues(data, hdr_bytes)
        report_prologues(prologues, out)

    finally:
        if out_fh:
            out_fh.close()
            print(f"Report written to: {out_file}", file=sys.stderr)


if __name__ == '__main__':
    main()
