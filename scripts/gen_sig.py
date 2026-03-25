#!/usr/bin/env python3
"""Generate IDA FLIRT .sig files directly from a DOS MZ executable.

Bypasses sigmake (which is non-functional in IDA Free 9.3) by writing
the .sig binary format directly. Uses the same CRC16 and FLIRT format
as parsed by ApplySigHeadless.py.

Function mappings are read from a .funcs file — a simple text format with
one "hex_offset flirt_name" pair per line. See sigs/ddplus.funcs for an
example.

Usage:
    python3 gen_sig.py <exe_path> <output.sig> <funcs_file> \\
        --segment 0x1095 [--name "Library Name"] [--ghidra-base 0x1000]

Arguments:
    exe_path     DOS MZ executable containing the library code
    output.sig   Output .sig file path
    funcs_file   Function mapping file (.funcs format)
    --segment    Ghidra segment address of the library (e.g., 0x1095)
    --name       Library name stored in the .sig header
    --ghidra-base  Ghidra base segment (default: 0x1000)
"""

import argparse
import struct
import sys
import zlib


# ── Binary writers ──────────────────────────────────────────────────────────

def write_u8(f, v):
    f.write(struct.pack('B', v & 0xFF))

def write_u16be(f, v):
    f.write(struct.pack('>H', v & 0xFFFF))

def write_u16le(f, v):
    f.write(struct.pack('<H', v & 0xFFFF))

def write_u32le(f, v):
    f.write(struct.pack('<L', v & 0xFFFFFFFF))

def write_max_2_bytes(f, v):
    """Encode a value using the FLIRT max-2-byte format."""
    if v < 0x80:
        write_u8(f, v)
    else:
        write_u8(f, 0x80 | ((v >> 8) & 0x7F))
        write_u8(f, v & 0xFF)

def write_multiple_bytes(f, v):
    """Encode a value using the FLIRT multi-byte format.

    Read side (ApplySigHeadless.py):
      0x00-0x7F: 1 byte, value = b
      0x80-0xBF: 2 bytes, value = ((b & 0x7F) << 8) | next
      0xC0-0xDF: 4 bytes, value = ((b & 0x3F) << 24) | next3
      0xE0-0xFF: 5 bytes, value = next4
    """
    if v < 0x80:
        write_u8(f, v)
    elif v < 0x4000:
        write_u8(f, 0x80 | ((v >> 8) & 0x3F))
        write_u8(f, v & 0xFF)
    elif v < 0x40000000:
        write_u8(f, 0xC0 | ((v >> 24) & 0x3F))
        write_u8(f, (v >> 16) & 0xFF)
        write_u8(f, (v >> 8) & 0xFF)
        write_u8(f, v & 0xFF)
    else:
        write_u8(f, 0xE0)
        write_u8(f, (v >> 24) & 0xFF)
        write_u8(f, (v >> 16) & 0xFF)
        write_u8(f, (v >> 8) & 0xFF)
        write_u8(f, v & 0xFF)


# ── CRC16 (FLIRT X.25 variant) ─────────────────────────────────────────────

POLY = 0x1021

def _rev8(n):
    return int('{:08b}'.format(n)[::-1], 2)

def _rev16(n):
    return int('{:016b}'.format(n)[::-1], 2)

_crc_table = []
def _init_crc_table():
    for i in range(256):
        ri = _rev8(i)
        crc = 0
        c = (ri << 8) & 0xFFFF
        for _ in range(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ POLY
            else:
                crc = (crc << 1)
            crc &= 0xFFFF
            c = (c << 1) & 0xFFFF
        _crc_table.append(_rev16(crc))
_init_crc_table()


def crc16(data, start_value=0xFFFF):
    out = start_value
    for b in data:
        tmp = (out ^ b) & 0xFF
        out = (out >> 8) ^ _crc_table[tmp]
    out ^= 0xFFFF
    out = ((out & 0xFF) << 8) | ((out >> 8) & 0xFF)
    return out


# ── MZ EXE parsing ─────────────────────────────────────────────────────────

def parse_mz(data):
    if data[:2] not in (b'MZ', b'ZM'):
        raise ValueError("Not a valid MZ executable")
    fields = struct.unpack_from('<HHHHHHHHHHHH', data, 2)
    hdr = {
        'e_cblp': fields[0], 'e_cp': fields[1], 'e_crlc': fields[2],
        'e_cparhdr': fields[3], 'e_lfarlc': fields[11],
    }
    load_start = hdr['e_cparhdr'] * 16
    # Read relocations
    reloc_set = set()
    pos = hdr['e_lfarlc']
    for _ in range(hdr['e_crlc']):
        off, seg = struct.unpack_from('<HH', data, pos)
        linear = seg * 16 + off
        reloc_set.add(linear)
        reloc_set.add(linear + 1)
        pos += 4
    return load_start, reloc_set


# ── Sig file generation ────────────────────────────────────────────────────

PATTERN_SIZE = 32  # Number of leading pattern bytes


def extract_pattern(data, load_start, actual_seg, offset, reloc_set):
    """Extract 32 pattern bytes with variant mask for relocated bytes."""
    file_off = load_start + actual_seg * 16 + offset
    pattern = []
    variant_bools = []
    for i in range(PATTERN_SIZE):
        linear = actual_seg * 16 + offset + i
        is_variant = linear in reloc_set
        variant_bools.append(is_variant)
        pattern.append(data[file_off + i] if not is_variant else 0)
    return pattern, variant_bools


def compute_variant_mask(variant_bools):
    """Convert list of bools to a bitmask (MSB first)."""
    mask = 0
    for b in variant_bools:
        mask = (mask << 1) | (1 if b else 0)
    return mask


def write_node_variant_mask(f, length, mask):
    """Write variant mask in the format expected by read_node_variant_mask."""
    if length < 0x10:
        write_max_2_bytes(f, mask)
    elif length <= 0x20:
        write_multiple_bytes(f, mask)
    elif length <= 0x40:
        high = (mask >> 32) & 0xFFFFFFFF
        low = mask & 0xFFFFFFFF
        write_multiple_bytes(f, high)
        write_multiple_bytes(f, low)


def write_public_function(f, name, offset, is_last):
    """Write a public function entry.

    Format: offset (multi-byte) + optional flags + name bytes + terminator flag
    """
    # Offset within module (relative to previous; first is absolute)
    write_multiple_bytes(f, offset)
    # Name bytes (each >= 0x20) followed by a flag byte (< 0x20)
    name_bytes = name.encode('ascii')
    for b in name_bytes:
        write_u8(f, b)
    # Terminator flags
    flags = 0x00  # no more public names, no tail bytes, no referenced functions
    if not is_last:
        flags |= 0x10  # PARSE_MORE_MODULES
    write_u8(f, flags)


SIG_VERSION = 5  # Use version 5 like tpdos.sig for compatibility


def write_leaf_node(f, pattern_bytes, variant_bools, func_length,
                    crc_val, crc_len, func_name, is_last_child):
    """Write a complete leaf node: pattern + 0 children + module."""
    length = len(pattern_bytes)
    mask = compute_variant_mask(variant_bools)

    # Node header
    write_u8(f, length)
    write_node_variant_mask(f, length, mask)
    # Pattern bytes (only non-variant bytes)
    for i in range(length):
        if not variant_bools[i]:
            write_u8(f, pattern_bytes[i])

    # Number of child nodes = 0 (this is a leaf)
    write_multiple_bytes(f, 0)

    # Module data: CRC group header
    write_u8(f, crc_len)       # crc_length (u8)
    write_u16be(f, crc_val)    # crc16 (u16be)

    # Module: function length (version < 9 uses max_2_bytes)
    write_max_2_bytes(f, func_length)

    # Public function: offset=0 (version < 9 uses max_2_bytes)
    write_max_2_bytes(f, 0)
    # Name bytes (each >= 0x20)
    name_bytes = func_name.encode('ascii')
    for b in name_bytes:
        write_u8(f, b)

    # Flags byte: no more public names, no tail bytes, no refs, no more modules
    write_u8(f, 0x00)


def generate_sig(exe_path, sig_path, functions, ghidra_seg, lib_name,
                 ghidra_base=0x1000):
    """Generate a .sig file from function mappings in a DOS MZ executable.

    Args:
        exe_path:    Path to the DOS MZ executable
        sig_path:    Output .sig file path
        functions:   Dict mapping segment offsets to FLIRT names
        ghidra_seg:  Ghidra segment address (e.g., 0x1095)
        lib_name:    Library name for the .sig header
        ghidra_base: Ghidra base segment (default 0x1000)
    """
    from io import BytesIO

    with open(exe_path, 'rb') as fp:
        data = fp.read()

    load_start, reloc_set = parse_mz(data)
    actual_seg = ghidra_seg - ghidra_base

    print(f"MZ load image at {load_start:#x}, segment {actual_seg:#06x}")
    print(f"Relocations affecting segment: "
          f"{sum(1 for x in reloc_set if actual_seg*16 <= x < (actual_seg+1)*16*256)}")

    # Sort functions by offset
    sorted_funcs = sorted(functions.items())

    # Build function entries
    entries = []
    for i, (offset, name) in enumerate(sorted_funcs):
        # Calculate function length
        if i + 1 < len(sorted_funcs):
            func_len = sorted_funcs[i + 1][0] - offset
        else:
            max_len = len(data) - load_start - actual_seg * 16 - offset
            func_len = min(0x200, max_len)

        # Extract pattern bytes
        pattern_bytes, variant_bools = extract_pattern(
            data, load_start, actual_seg, offset, reloc_set)

        # CRC of bytes after the pattern (bytes 33+)
        if func_len > PATTERN_SIZE:
            file_off = load_start + actual_seg * 16 + offset
            crc_len = min(func_len - PATTERN_SIZE, 0xFF)
            crc_data = data[file_off + PATTERN_SIZE:file_off + PATTERN_SIZE + crc_len]
            crc_val = crc16(crc_data)
        else:
            crc_len = 0
            crc_val = 0

        entries.append({
            'offset': offset,
            'name': name,
            'func_len': func_len,
            'pattern': pattern_bytes,
            'variant': variant_bools,
            'crc_val': crc_val,
            'crc_len': crc_len,
        })

        print(f"  {offset:04x} len={func_len:4d} crc={crc_val:04X}/{crc_len:02X}  {name}")

    # Write sig file
    tree_buf = BytesIO()

    # Root node: length=0, no pattern, N children
    write_multiple_bytes(tree_buf, len(entries))

    # Each child is a leaf node with its 32-byte pattern
    for i, entry in enumerate(entries):
        write_leaf_node(
            tree_buf,
            entry['pattern'], entry['variant'],
            entry['func_len'],
            entry['crc_val'], entry['crc_len'],
            entry['name'],
            is_last_child=(i == len(entries) - 1)
        )

    tree_data = tree_buf.getvalue()

    # Compress tree data
    compressed = zlib.compress(tree_data)
    # Remove zlib header (first 2 bytes) and checksum (last 4 bytes)
    # to get raw deflate — that's what FLIRT uses
    raw_deflate = compressed[2:-4]

    # Write the complete .sig file
    lib_name_bytes = lib_name.encode('ascii')

    with open(sig_path, 'wb') as fp:
        # Magic
        fp.write(b'IDASGN')
        # Version 5 (simplest format, same as tpdos.sig)
        write_u8(fp, SIG_VERSION)
        # Architecture: Intel 80x86
        write_u8(fp, 0)
        # File types: DOSEXE(OLD) | DOSCOM(OLD) | BIN | DOSDRV | OMF
        write_u32le(fp, 0x0000100F)
        # OS types: MSDOS
        write_u16le(fp, 0x0001)
        # App types: CONSOLE | GRAPHICS | EXE | 16BIT
        write_u16le(fp, 0x0087)
        # Features: COMPRESSED
        write_u16le(fp, 0x0010)
        # Old n_functions (u16)
        write_u16le(fp, min(len(entries), 0xFFFF))
        # CRC16 of tree data (before compression)
        write_u16le(fp, crc16(tree_data))
        # ctype (12 bytes, zeroed)
        fp.write(b'\x00' * 12)
        # Library name length
        write_u8(fp, len(lib_name_bytes))
        # ctypes_crc16
        write_u16le(fp, 0)
        # No n_functions field for version 5
        # No pattern_size field for version 5

        # Library name
        fp.write(lib_name_bytes)

        # Compressed tree data
        fp.write(raw_deflate)

    print(f"\nWrote {len(entries)} signatures to {sig_path}")
    print(f"  Tree: {len(tree_data)} bytes -> {len(raw_deflate)} bytes compressed")


# ── Function mapping file parser ───────────────────────────────────────────

def load_funcs_file(path):
    """Load a .funcs file.

    Format: lines of "hex_offset flirt_name", # comments, blank lines ignored.
    Returns dict mapping int offset -> str name.
    """
    functions = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            offset = int(parts[0], 16)
            name = parts[1]
            functions[offset] = name
    return functions


def main():
    parser = argparse.ArgumentParser(
        description='Generate IDA FLIRT .sig files from a DOS MZ executable.')
    parser.add_argument('exe_path', help='DOS MZ executable file')
    parser.add_argument('sig_path', help='Output .sig file path')
    parser.add_argument('funcs_file',
                        help='Function mapping file (.funcs format)')
    parser.add_argument('--segment', required=True, type=lambda x: int(x, 0),
                        help='Ghidra segment address (e.g., 0x1095)')
    parser.add_argument('--name', default='Unknown Library',
                        help='Library name for the .sig header')
    parser.add_argument('--ghidra-base', type=lambda x: int(x, 0),
                        default=0x1000,
                        help='Ghidra base segment (default: 0x1000)')

    args = parser.parse_args()

    functions = load_funcs_file(args.funcs_file)
    if not functions:
        print(f"Error: no functions found in {args.funcs_file}", file=sys.stderr)
        sys.exit(1)

    generate_sig(args.exe_path, args.sig_path, functions, args.segment,
                 args.name, args.ghidra_base)


if __name__ == '__main__':
    main()
