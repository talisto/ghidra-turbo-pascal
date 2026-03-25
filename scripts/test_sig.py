#!/usr/bin/env python3
"""Test FLIRT .sig file parsing — standalone (no Ghidra dependency)."""

import struct
import sys
import zlib
from io import BytesIO


def read_u8(f):
    return struct.unpack('B', f.read(1))[0]

def read_u16be(f):
    return struct.unpack('>H', f.read(2))[0]

def read_u16le(f):
    return struct.unpack('<H', f.read(2))[0]

def read_u32le(f):
    return struct.unpack('<L', f.read(4))[0]

def read_u24be(f):
    return struct.unpack('>I', b'\x00' + f.read(3))[0]

def read_u32be(f):
    return struct.unpack('>I', f.read(4))[0]

def read_max_2_bytes(f):
    b = read_u8(f)
    if b & 0x80:
        return ((b & 0x7F) << 8) | read_u8(f)
    return b

def read_multiple_bytes(f):
    b = read_u8(f)
    if b & 0x80 != 0x80:
        return b
    elif b & 0xC0 != 0xC0:
        return ((b & 0x7F) << 8) | read_u8(f)
    elif b & 0xE0 != 0xE0:
        return ((b & 0x3F) << 24) | read_u24be(f)
    else:
        return read_u32be(f)

def read_node_variant_mask(f, length):
    if length < 0x10:
        return read_max_2_bytes(f)
    elif length <= 0x20:
        return read_multiple_bytes(f)
    elif length <= 0x40:
        return (read_multiple_bytes(f) << 32) | read_multiple_bytes(f)

def read_node_bytes(f, length, variant_mask):
    mask_bit = 1 << (length - 1)
    variant_bools, pattern = [], []
    for _ in range(length):
        is_var = variant_mask & mask_bit != 0
        pattern.append(0 if is_var else read_u8(f))
        variant_bools.append(is_var)
        mask_bit >>= 1
    return variant_bools, pattern

def parse_public_function(f, version, offset):
    if version >= 9:
        offset += read_multiple_bytes(f)
    else:
        offset += read_max_2_bytes(f)
    b = read_u8(f)
    if b < 0x20:
        b = read_u8(f)
    name = []
    for _ in range(1024):
        if b < 0x20:
            break
        name.append(b)
        b = read_u8(f)
    return bytearray(name).decode('ascii'), offset, b

def parse_tree(f, version, is_root, depth=0):
    if is_root:
        length, variant_mask, pattern = 0, None, None
    else:
        length = read_u8(f)
        variant_mask = read_node_variant_mask(f, length)
        variant_mask, pattern = read_node_bytes(f, length, variant_mask)

    nodes = read_multiple_bytes(f)
    if nodes == 0:
        # Leaf — parse modules
        modules = []
        while True:
            crc_length = read_u8(f)
            crc16 = read_u16be(f)
            while True:
                if version >= 9:
                    func_length = read_multiple_bytes(f)
                else:
                    func_length = read_max_2_bytes(f)
                funcs = []
                fn_offset = 0
                while True:
                    name, fn_offset, flags = parse_public_function(f, version, fn_offset)
                    funcs.append((name, fn_offset))
                    if flags & 0x01 == 0:
                        break
                modules.append({
                    'crc_length': crc_length,
                    'crc16': crc16,
                    'length': func_length,
                    'funcs': funcs,
                    'flags': flags,
                })
                if flags & 0x08 == 0:
                    break
            if flags & 0x10 == 0:
                break

        pat_str = ''.join(
            '{:02X}'.format(p) if not v else '..'
            for p, v in zip(pattern, variant_mask)
        ) if pattern else 'ROOT'
        for mod in modules:
            names = ', '.join('{}@{}'.format(n, o) for n, o in mod['funcs'])
            print('{}{}  crc={:04X}/{:02X} len={} -> {}'.format(
                '  ' * depth, pat_str, mod['crc16'], mod['crc_length'],
                mod['length'], names))
        return len(modules)

    total = 0
    for _ in range(nodes):
        total += parse_tree(f, version, False, depth + 1)
    return total


def main():
    sig_path = sys.argv[1] if len(sys.argv) > 1 else 'sigs/ddplus.sig'

    with open(sig_path, 'rb') as fp:
        magic = fp.read(6)
        assert magic == b'IDASGN', "Bad magic: {}".format(magic)
        version = read_u8(fp)
        arch = read_u8(fp)
        file_types = read_u32le(fp)
        os_types = read_u16le(fp)
        app_types = read_u16le(fp)
        features = read_u16le(fp)
        old_n_functions = read_u16le(fp)
        crc16 = read_u16le(fp)
        ctype = fp.read(12)
        lib_name_len = read_u8(fp)
        ctypes_crc16 = read_u16le(fp)
        if version >= 6:
            n_functions = read_u32le(fp)
        if version >= 8:
            pat_size = read_u16le(fp)
        lib_name = fp.read(lib_name_len).decode('ascii')

        print('version={}, lib="{}", n_funcs={}'.format(version, lib_name, old_n_functions))
        print('features={:#06x} (compressed={})'.format(features, bool(features & 0x10)))

        if features & 0x10:
            f = BytesIO(zlib.decompress(fp.read(), -15))
        else:
            f = fp

        total = parse_tree(f, version, True)
        remaining = f.read()
        print('\nTotal modules parsed: {}'.format(total))
        print('Remaining bytes: {}'.format(len(remaining)))


if __name__ == '__main__':
    main()
