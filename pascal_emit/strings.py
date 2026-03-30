"""String database loading and EXE string reading."""
import json
import os
import struct


def load_strings(path):
    """Load strings.json and return dict mapping seg:off → string text."""
    if not path or not os.path.isfile(path):
        return {}
    with open(path, 'r') as f:
        data = json.load(f)
    result = {}
    for entry in data:
        result[entry['address']] = entry['string']
        # Also index by offset within the primary segment
        addr = entry['address']
        seg, off = addr.split(':')
        off_int = int(off, 16)
        result[off_int] = entry['string']
    return result


class ExeStringReader:
    """Read Pascal length-prefixed strings directly from a DOS MZ EXE file.

    Borland Pascal stores const strings as [len_byte][ascii_chars] packed
    at the start of code segments. The offsets in the decompiled C output
    (DAT_ values) are byte offsets from the start of the code/data area
    (immediately after the MZ header).
    """

    def __init__(self, exe_path):
        with open(exe_path, 'rb') as f:
            self._data = f.read()
        # MZ header: word at offset 8 = header size in paragraphs (16 bytes)
        self._code_start = struct.unpack_from('<H', self._data, 8)[0] * 16

    def read_string(self, offset):
        """Read a Pascal string at the given code-relative offset.

        Returns the string text, or None if invalid.
        """
        abs_off = self._code_start + offset
        if abs_off >= len(self._data):
            return None
        strlen = self._data[abs_off]
        if strlen == 0 or abs_off + 1 + strlen > len(self._data):
            return None
        raw = self._data[abs_off + 1 : abs_off + 1 + strlen]
        if all(0x20 <= b <= 0x7e for b in raw):
            return raw.decode('ascii')
        return None


def find_exe_for_decompiled(decompiled_path):
    """Try to find the EXE file corresponding to a decompiled.c output."""
    dir_path = os.path.dirname(os.path.abspath(decompiled_path))
    program_name = os.path.basename(dir_path)

    # Check in tests/data/ (standard test layout)
    # decompiled_path is like .../tests/output/PROGRAM/decompiled.c
    # EXE would be at .../tests/data/PROGRAM.EXE
    output_dir = os.path.dirname(dir_path)  # tests/output/
    tests_dir = os.path.dirname(output_dir)  # tests/
    data_dir = os.path.join(tests_dir, 'data')
    for ext in ['.EXE', '.exe', '']:
        candidate = os.path.join(data_dir, program_name + ext)
        if os.path.isfile(candidate):
            return candidate

    # Check alongside decompiled.c
    for ext in ['.EXE', '.exe', '']:
        candidate = os.path.join(dir_path, program_name + ext)
        if os.path.isfile(candidate):
            return candidate

    return None
