#!/usr/bin/env python3
"""pascal_emit.py — Convert decompiled C output to Pascal source.

Prototype C-to-Pascal transpiler for Borland Pascal 7 decompiled output.
Reads decompiled.c and strings.json, emits a .pas file.

Currently handles:
  - Application function conversion (procedures/functions)
  - Write/WriteLn sequence detection and conversion
  - Global variable declarations from memory addresses
  - Basic C→Pascal syntax conversion
  - Entry function main block extraction

Usage:
  python3 pascal_emit.py tests/output/HELLO/decompiled.c
  python3 pascal_emit.py tests/output/PROCFUNC/decompiled.c -o output.pas
"""
import json
import os
import re
import sys
from collections import OrderedDict


# ────────────────────────────────────────────────────────────────
# Function block parser
# ────────────────────────────────────────────────────────────────

FUNC_HEADER_RE = re.compile(
    r'\n// ={10,}\n// Function: (\S+) @ ([0-9a-f]+:[0-9a-f]+)\n// ={10,}\n'
)

LIBRARY_MARKER_RE = re.compile(r'^\s*// \[LIBRARY\]')


def parse_functions(text):
    """Parse decompiled.c into a list of function blocks.

    Returns list of dicts with keys:
      name, address, body, is_library, segment
    """
    parts = FUNC_HEADER_RE.split(text)
    # parts: [preamble, name1, addr1, body1, name2, addr2, body2, ...]
    functions = []
    i = 1
    while i < len(parts):
        name = parts[i]
        addr = parts[i + 1]
        body = parts[i + 2] if i + 2 < len(parts) else ''
        seg = addr.split(':')[0]
        is_library = bool(LIBRARY_MARKER_RE.search(body.split('\n')[0] if body else ''))
        functions.append({
            'name': name,
            'address': addr,
            'body': body.strip(),
            'is_library': is_library,
            'segment': seg,
        })
        i += 3
    return functions


# ────────────────────────────────────────────────────────────────
# String database
# ────────────────────────────────────────────────────────────────

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
        import struct
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


# ────────────────────────────────────────────────────────────────
# Function classification
# ────────────────────────────────────────────────────────────────

# Prefixes that indicate library functions (bodies already eliminated)
LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')

FLIRT_PATTERNS = [
    re.compile(r'^@\w+\$'),
    re.compile(r'^__[A-Z]'),
]


def classify_function(func):
    """Classify a function as 'library', 'entry', 'application', or 'system'.

    Returns the classification string.
    """
    name = func['name']

    if func['is_library']:
        return 'library'

    if name == 'entry':
        return 'entry'

    # Check if it's a library function that wasn't tagged
    if any(name.startswith(p) for p in LIBRARY_PREFIXES):
        return 'library'
    for pat in FLIRT_PATTERNS:
        if pat.match(name):
            return 'library'

    # Functions in the same segment as library functions are system helpers
    # (they're in the RTL segment, not the application segment)
    # We'll use a simple heuristic: FUN_SSSS_OOOO where SSSS != primary_seg
    return 'application'


def find_primary_segment(functions):
    """Find the primary application segment (usually 1000).

    The entry function is always in the primary segment.
    """
    for func in functions:
        if func['name'] == 'entry':
            return func['segment']
    # Default to first segment
    if functions:
        return functions[0]['segment']
    return '1000'


# ────────────────────────────────────────────────────────────────
# C signature parser
# ────────────────────────────────────────────────────────────────

C_SIG_RE = re.compile(
    r'^(\w[\w\s*]*?)\s+' +       # return type
    r'(\w+)\s*'                   # function name
    r'\(([^)]*)\)',               # parameters
    re.MULTILINE
)

C_PARAM_RE = re.compile(
    r'(\w[\w\s*]*?)\s*(\*?)\s*(\w+)$'
)


def parse_c_signature(body):
    """Parse a C function signature from the body text.

    Returns (return_type, func_name, params) where params is a list of
    (type, name, is_pointer) tuples. Returns None if parsing fails.
    """
    # Strip leading comments and blank lines
    lines = body.split('\n')
    sig_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('/*') or stripped.startswith('//'):
            continue
        sig_lines.append(stripped)
        if '{' in stripped or ')' in stripped:
            break

    if not sig_lines:
        return None

    sig_text = ' '.join(sig_lines).split('{')[0].strip()

    m = C_SIG_RE.match(sig_text)
    if not m:
        return None

    ret_type = m.group(1).strip()
    func_name = m.group(2).strip()
    param_text = m.group(3).strip()

    params = []
    if param_text and param_text != 'void':
        for p in param_text.split(','):
            p = p.strip()
            # Handle "int *param_1" or "int param_1" or "byte *param_1"
            pm = C_PARAM_RE.match(p)
            if pm:
                ptype = pm.group(1).strip()
                is_ptr = bool(pm.group(2))
                pname = pm.group(3).strip()
                params.append((ptype, pname, is_ptr))
            else:
                # Fallback: just use the whole thing
                params.append(('int', p.split()[-1] if p.split() else 'param', False))

    return ret_type, func_name, params


# ────────────────────────────────────────────────────────────────
# Type mapping
# ────────────────────────────────────────────────────────────────

C_TO_PASCAL_TYPE = {
    'void': '',
    'int': 'Integer',
    'uint': 'Word',
    'word': 'Word',
    'byte': 'Byte',
    'char': 'Char',
    'long': 'LongInt',
    'ulong': 'LongInt',
    'dword': 'LongInt',
    'bool': 'Boolean',
}


def c_type_to_pascal(ctype):
    """Convert a C type name to Pascal type name."""
    # Strip const, unsigned, etc.
    ctype = ctype.replace('unsigned ', '').replace('const ', '').strip()
    return C_TO_PASCAL_TYPE.get(ctype, ctype)


# ────────────────────────────────────────────────────────────────
# Pascal signature generator
# ────────────────────────────────────────────────────────────────

def make_pascal_signature(ret_type, func_name, params):
    """Generate a Pascal procedure/function signature.

    Returns (keyword, declaration, pascal_name, is_function).
    """
    pascal_name = func_name
    if func_name.startswith('FUN_'):
        pascal_name = 'Proc_' + func_name[4:]

    # Build parameter list
    pascal_params = []
    for ptype, pname, is_ptr in params:
        ptype_pascal = c_type_to_pascal(ptype)
        if is_ptr:
            pascal_params.append(f'var {pname}: {ptype_pascal}')
        else:
            pascal_params.append(f'{pname}: {ptype_pascal}')

    param_str = '; '.join(pascal_params)

    is_function = ret_type not in ('void', '')
    if is_function:
        ret_pascal = c_type_to_pascal(ret_type)
        pascal_name_func = pascal_name.replace('Proc_', 'Func_')
        return ('function', f'function {pascal_name_func}({param_str}): {ret_pascal};',
                pascal_name_func, True)
    else:
        return ('procedure', f'procedure {pascal_name}({param_str});',
                pascal_name, False)


# ────────────────────────────────────────────────────────────────
# Body conversion: Write/WriteLn sequence detection
# ────────────────────────────────────────────────────────────────

# Patterns for Write/WriteLn-related calls
# In app functions: FUN_xxxx_0670(width, string_offset, segment)
# In entry: bp_write_str() with DAT_ arg setup
WRITE_STR_CALL_RE = re.compile(
    r'(?:bp_write_str|FUN_\w+_0670)\s*\('
)
# Extract the string offset from bp_write_str/FUN_xxxx_0670(width, OFFSET, segment) calls
WRITE_STR_ARGS_RE = re.compile(
    r'(?:bp_write_str|FUN_\w+_0670)\s*\(\s*\d+\s*,\s*(0x[0-9a-f]+|\d+)\s*,\s*0x[0-9a-f]+\s*\)'
)
WRITE_INT_RE = re.compile(r'bp_write_int\s*\(')
WRITE_LONGINT_RE = re.compile(r'bp_write_longint\s*\(')
WRITELN_END_RE = re.compile(r'bp_write_char_flush\s*\(')
WRITE_END_RE = re.compile(r'bp_flush_text_cond\s*\(')
# Extract string annotation: /* "text" */
STRING_ANNOTATION_RE = re.compile(r'/\*\s*"((?:[^"\\]|\\.)*)"\s*\*/')

# Extract integer value from bp_write_int call in application functions
# bp_write_int(width, value, value >> 0xf)
WRITE_INT_ARGS_RE = re.compile(
    r'bp_write_int\s*\(\s*(\d+)\s*,\s*(.+?)\s*,\s*\1\s*>>\s*0xf\s*\)'
)
# Simpler: bp_write_int(width, value, sign_ext)
WRITE_INT_ARGS_SIMPLE_RE = re.compile(
    r'bp_write_int\s*\(\s*(\d+)\s*,\s*(.+?)\s*,'
)

# Extract integer value from DAT-based entry function
# DAT_xxxx = *(int *)0xNN  (reading a global variable for write_int)
DAT_VALUE_RE = re.compile(r'DAT_\w+ = (\*\(int \*\)0x[0-9a-f]+)')

# Global memory access: *(int *)0xNN or *(word *)0xNN or *(char *)0xNN
GLOBAL_ACCESS_RE = re.compile(
    r'\*\((?:int|uint|word|byte|char) \*\)(0x[0-9a-f]+)'
)


def extract_string_annotation(line):
    """Extract string text from inline /* "..." */ annotation."""
    m = STRING_ANNOTATION_RE.search(line)
    if m:
        return m.group(1)
    return None


def detect_write_sequences(lines, strings_db, exe_reader=None):
    """Detect and convert Write/WriteLn call sequences.

    Scans lines for patterns like:
      [optional string setup]
      bp_write_str() or FUN_xxxx_0670()    ← write string part
      bp_write_int()                       ← write integer part
      bp_write_char_flush()                ← WriteLn terminator
      bp_iocheck()                         ← skip

    Returns list of (start_idx, end_idx, pascal_statement) tuples.
    """
    def _is_stack_push(line):
        """Check if a line is a stack push (DAT_, puVar, or *puVar assignment)."""
        return (line.startswith('DAT_') or
                line.startswith('*(word *)(puVar') or
                bool(re.match(r'puVar\d+\[-?\d+\]\s*=', line)) or
                bool(re.match(r'\*puVar\d+\s*=', line)))

    sequences = []
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        # Look for start of a write sequence
        # Collect write parts until we hit a terminator
        parts = []
        start_idx = i
        found_write = False

        # Collect DAT_ annotations and values for position-based string lookup
        dat_annotations = []
        dat_values = []

        # Scan ahead to see if this is part of a write sequence
        j = i
        while j < len(lines):
            jline = lines[j].strip()

            # String write part
            if WRITE_STR_CALL_RE.search(jline):
                found_write = True
                # Look for string annotation on this line
                text = extract_string_annotation(jline)
                if not text:
                    # Check preceding DAT lines for annotation
                    for k in range(max(start_idx, j - 8), j):
                        text = extract_string_annotation(lines[k].strip())
                        if text:
                            break
                if not text:
                    # Try extracting string offset from call arguments
                    m_args = WRITE_STR_ARGS_RE.search(jline)
                    if m_args:
                        offset_str = m_args.group(1)
                        offset_val = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                        text = strings_db.get(offset_val)
                        if not text and exe_reader:
                            text = exe_reader.read_string(offset_val)
                if not text and dat_annotations:
                    # Use inline annotation from DAT_/puVar lines
                    text = dat_annotations[-1]
                if not text and dat_values:
                    # Try known positions for string offset in the stack frame:
                    # DAT_ style (6 elems): [TextRec, segment, STRING_OFFSET, width, segment, retaddr] → pos 2
                    # puVar style (7 elems): [seg, TextRec, segment, STRING_OFFSET, width, segment, retaddr] → pos 3
                    # puVar7[] style (5 elems): [segment, STRING_OFFSET, width, segment, retaddr] → pos 1
                    priority_positions = []
                    if len(dat_values) >= 7:
                        priority_positions.append(3)
                    if len(dat_values) >= 6:
                        priority_positions.append(2)
                    if len(dat_values) >= 5:
                        priority_positions.append(1)
                    for pos in priority_positions:
                        try:
                            val = dat_values[pos]
                            off = int(val, 16) if val.startswith('0x') else int(val)
                        except ValueError:
                            continue
                        # First try strings.json
                        text = strings_db.get(off)
                        if text:
                            break
                        # Then try reading directly from the EXE
                        if exe_reader:
                            text = exe_reader.read_string(off)
                            if text:
                                break
                # Reset for next write block
                dat_annotations.clear()
                dat_values.clear()
                if text:
                    # Escape single quotes in Pascal strings
                    text = text.replace("'", "''")
                    parts.append(f"'{text}'")
                else:
                    parts.append("'{???}'")
                j += 1
                continue

            # Integer write part
            if WRITE_INT_RE.search(jline):
                found_write = True
                # Try to extract value and width from arguments
                m = WRITE_INT_ARGS_RE.search(jline)
                if m:
                    width = int(m.group(1))
                    value = m.group(2).strip()
                    value = convert_expression(value)
                    if width > 0:
                        parts.append(f'{value}:{width}')
                    else:
                        parts.append(value)
                else:
                    m2 = WRITE_INT_ARGS_SIMPLE_RE.search(jline)
                    if m2:
                        width = int(m2.group(1))
                        value = m2.group(2).strip()
                        value = convert_expression(value)
                        if width > 0:
                            parts.append(f'{value}:{width}')
                        else:
                            parts.append(value)
                    else:
                        # Entry function: value was in DAT_ variable
                        # Look back for DAT_ = value pattern
                        val = _find_dat_value(lines, j)
                        if val:
                            parts.append(convert_expression(val))
                        else:
                            parts.append('{int}')
                j += 1
                continue

            # Longint write
            if WRITE_LONGINT_RE.search(jline):
                found_write = True
                parts.append('{longint}')
                j += 1
                continue

            # WriteLn terminator
            if WRITELN_END_RE.search(jline):
                if found_write:
                    j += 1
                    # Skip bp_iocheck and its arguments (DAT_ or puVar style).
                    # Tentatively advance past argument lines; consume only if
                    # bp_iocheck follows. Otherwise rollback to avoid eating
                    # the NEXT write sequence's setup lines.
                    saved_j = j
                    while j < len(lines):
                        nline = lines[j].strip()
                        if not nline:
                            j += 1
                        elif 'bp_iocheck' in nline:
                            j += 1
                            break
                        elif _is_stack_push(nline):
                            j += 1
                        else:
                            # No bp_iocheck found — rollback
                            j = saved_j
                            break
                    if parts:
                        sequences.append((start_idx, j, f"WriteLn({', '.join(parts)});"))
                    else:
                        sequences.append((start_idx, j, 'WriteLn;'))
                    break
                else:
                    # Standalone WriteLn (no preceding writes)
                    found_write = True
                    j += 1
                    saved_j = j
                    while j < len(lines):
                        nline = lines[j].strip()
                        if not nline:
                            j += 1
                        elif 'bp_iocheck' in nline:
                            j += 1
                            break
                        elif _is_stack_push(nline):
                            j += 1
                        else:
                            j = saved_j
                            break
                    sequences.append((start_idx, j, 'WriteLn;'))
                    break

            # Write (no newline) terminator
            if WRITE_END_RE.search(jline):
                if found_write:
                    j += 1
                    # Skip bp_iocheck and its arguments (tentative — rollback if no iocheck)
                    saved_j = j
                    while j < len(lines):
                        nline = lines[j].strip()
                        if not nline:
                            j += 1
                        elif 'bp_iocheck' in nline:
                            j += 1
                            break
                        elif _is_stack_push(nline):
                            j += 1
                        else:
                            j = saved_j
                            break
                    sequences.append((start_idx, j, f"Write({', '.join(parts)});"))
                    break
                j += 1
                continue

            # DAT_ lines (entry function argument setup) — collect for string lookup
            if jline.startswith('DAT_'):
                ann = extract_string_annotation(jline)
                if ann:
                    dat_annotations.append(ann)
                # Extract the assigned value
                dat_val_match = re.search(r'DAT_\w+\s*=\s*(.+?)\s*;', jline)
                if dat_val_match:
                    val = dat_val_match.group(1).strip()
                    dat_values.append(val)
                j += 1
                continue

            # puVar stack push lines (alternate stack manipulation styles)
            # Matches: *(word *)(puVarN + -N), puVarN[-N], puVarN[N], *puVarN
            if (re.match(r'\*\(word \*\)\(puVar\d+ \+ -', jline) or
                    re.match(r'puVar\d+\[-?\d+\]\s*=', jline) or
                    re.match(r'\*puVar\d+\s*=', jline)):
                ann = extract_string_annotation(jline)
                if ann:
                    dat_annotations.append(ann)
                pv_match = re.search(r'=\s*(.+?)\s*;', jline)
                if pv_match:
                    val = pv_match.group(1).strip()
                    dat_values.append(val)
                j += 1
                continue

            # Temp variable assignments (iVarN, uVarN) — part of write setup
            if re.match(r'^[iu]Var\d+\s*=', jline):
                # Collect as a potential value for write_int
                val_match = re.search(r'=\s*(.+?)\s*;', jline)
                if val_match:
                    dat_values.append(val_match.group(1).strip())
                j += 1
                continue

            # *(int *) puVar cast lines (integer write setup)
            if re.match(r'\*\((?:int|uint) \*\)\(puVar\d+ \+ -', jline):
                pv_match = re.search(r'=\s*(.+?)\s*;', jline)
                if pv_match:
                    dat_values.append(pv_match.group(1).strip())
                j += 1
                continue

            # bp_iocheck — skip if within a write sequence
            if 'bp_iocheck' in jline:
                if found_write:
                    j += 1
                    sequences.append((start_idx, j, f"WriteLn({', '.join(parts)});"))
                    break
                # bp_iocheck without preceding write — sequence boundary, stop
                break

            # Not part of a write sequence
            if found_write:
                # We found write parts but no terminator — emit what we have
                sequences.append((start_idx, j, f"Write({', '.join(parts)});"))
                break

            break

        if not found_write:
            i += 1
        else:
            i = j if sequences and sequences[-1][1] == j else i + 1

    return sequences


def _find_dat_value(lines, write_int_idx):
    """Look back from a bp_write_int() call to find the value in DAT_/puVar setup."""
    for k in range(write_int_idx - 1, max(0, write_int_idx - 8), -1):
        kline = lines[k].strip()
        # DAT_ = *(int *)0xNN (global variable read)
        m = DAT_VALUE_RE.search(kline)
        if m:
            return m.group(1)
        # puVar = iVarN or puVar = *(int *)0xNN
        pv = re.search(r'\*\(int \*\)\(puVar\d+ \+ -\d+\)\s*=\s*(\w+)\s*;', kline)
        if pv:
            val = pv.group(1)
            # If it's an iVar, look further back for its source
            if re.match(r'^iVar\d+$', val):
                for m2 in range(k - 1, max(0, k - 4), -1):
                    m2line = lines[m2].strip()
                    iv_match = re.match(rf'^{re.escape(val)}\s*=\s*(.+?)\s*;', m2line)
                    if iv_match:
                        return iv_match.group(1)
            return val
        # iVarN = *(int *)0xNN (direct global read into temp)
        iv = re.match(r'^iVar\d+\s*=\s*(\*\(int \*\)0x[0-9a-f]+)\s*;', kline)
        if iv:
            return iv.group(1)
    return None


# ────────────────────────────────────────────────────────────────
# Expression and statement conversion
# ────────────────────────────────────────────────────────────────

def convert_expression(expr):
    """Convert a C expression to Pascal expression."""
    expr = expr.strip()

    # Char literals: '\0' → 0, '\x01' → 1, 'A' → Ord('A'), etc.
    expr = re.sub(r"'\\0'", '0', expr)
    expr = re.sub(r"'\\x([0-9a-f]{2})'", lambda m: str(int(m.group(1), 16)), expr)

    # Memory access: *(int *)0xNN → g_00NN
    expr = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)(0x[0-9a-f]+)',
        lambda m: f'g_{m.group(1)[2:].zfill(4).upper()}',
        expr
    )
    # *(int *)(param_N + offset) → param_N.field_offset  (record access)
    expr = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)\((\w+) \+ (\d+)\)',
        lambda m: f'{m.group(1)}[{m.group(2)}]',
        expr
    )

    # Shift operators
    expr = re.sub(r'(\w+)\s*<<\s*1\b', r'\1 * 2', expr)
    expr = re.sub(r'(\w+)\s*>>\s*1\b', r'\1 div 2', expr)
    expr = re.sub(r'(\w+)\s*<<\s*(\d+)', lambda m: f'{m.group(1)} * {1 << int(m.group(2))}', expr)

    # Sign extension pattern: value >> 0xf → remove entirely (16-bit sign ext)
    expr = re.sub(r',\s*\w+ >> 0xf', '', expr)

    # Hex constants → decimal (for readability, skip address-like values)
    expr = re.sub(
        r'\b0x([0-9a-f]+)\b',
        lambda m: str(int(m.group(1), 16)),
        expr
    )

    # C operators → Pascal
    expr = expr.replace('!=', ' <> ')
    expr = expr.replace('==', ' = ')
    expr = expr.replace('&&', ' and ')
    expr = expr.replace('||', ' or ')
    # ! for logical not (careful not to match !=)
    expr = re.sub(r'!(\w)', r'not \1', expr)
    # Assignment
    expr = expr.replace(' = ', ' := ', 1) if ' = ' in expr and ':=' not in expr else expr

    # Clean up whitespace
    expr = re.sub(r'\s+', ' ', expr).strip()

    return expr


# Lines to strip entirely (noise)
NOISE_PATTERNS = [
    re.compile(r'^\s*bp_stack_check\s*\('),
    re.compile(r'^\s*bp_iocheck\s*\('),
    re.compile(r'^\s*return\s*;\s*$'),
    re.compile(r'^\s*\w+ unaff_\w+\s*;'),  # unaff_ variable declarations
    re.compile(r'^\s*\w+ extraout_\w+\s*;'),  # extraout_ variable declarations
    re.compile(r'^\s*\w+ uVar\d+\s*;'),  # uVar temp declarations
    re.compile(r'^\s*uVar\d+\s*=\s*'),  # uVar assignments (RTL temporaries)
    re.compile(r'^\s*DAT_\w+\s*='),  # DAT_ stack pushes in entry
    re.compile(r'^\s*/\*\s*WARNING'),  # Ghidra warnings
    re.compile(r'^\s*func_0x'),  # func_0x entry calls
    re.compile(r'^\s*bp_halt_handler\s*\('),  # halt (marks end of main)
    re.compile(r'^\s*bp_module_init\s*\('),
    re.compile(r'^\s*bp_clear_dseg\s*\('),
    re.compile(r'^\s*bp_runtime_init\s*\('),
    re.compile(r'^\s*bp_input_init\s*\('),
    re.compile(r'^\s*bp_output_init\s*\('),
    re.compile(r'^\s*bp_printstring\s*\('),
    re.compile(r'^\s*\(\*pcVar\d+\)\s*\('),  # indirect calls (swi dispatch)
    re.compile(r'^\s*pcVar\d+\s*='),  # pcVar assignments
    re.compile(r'^\s*code \*pcVar'),  # pcVar declarations
    re.compile(r'^\s*\*puVar\d+\s*='),  # pointer temp assignments
    re.compile(r'^\s*puVar\d+\s*='),  # pointer temp assignments
    re.compile(r'^\s*puVar\d+\['),  # pointer temp array access
    re.compile(r'^\s*\*\(word \*\)\(puVar\d+ \+ -?'),  # stack pushes via puVar
    re.compile(r'^\s*\w+ \*puVar\d+\s*;'),  # puVar declarations
    re.compile(r'^\s*\w+ in_\w+\s*;'),  # in_ register declarations
    re.compile(r'^\s*int unaff_'),  # unaff_ declarations
    re.compile(r'^\s*word unaff_'),
    re.compile(r'^\s*word uVar\d+\s*;'),
    re.compile(r'^\s*int iVar\d+\s*;'),  # Keep only if used in app logic
    re.compile(r'^\s*char cVar\d+\s*;'),
    re.compile(r'^\s*word extraout_'),
    re.compile(r'^\s*int \*piVar\d+\s*;'),
    re.compile(r'^\s*code \*'),
    re.compile(r'^\s*dword uVar\d+\s*;'),
    re.compile(r'^\s*byte \*puVar'),
    re.compile(r'^\s*word \*puVar'),
    re.compile(r'^\s*\w+Var\d+\s*=\s*\*\(.*puVar'),  # reading values via puVar
]


def is_noise_line(line):
    """Check if a line should be stripped as noise."""
    stripped = line.strip()
    if not stripped:
        return False  # Keep blank lines for readability
    for pat in NOISE_PATTERNS:
        if pat.search(stripped):
            return True
    return False


def is_system_init_line(line):
    """Check if a line is part of system initialization (after bp_halt_handler)."""
    stripped = line.strip()
    # Post-halt patterns
    if re.search(r'\*\(char \*\)\(.*unaff_SI', stripped):
        return True
    if re.search(r'\*\(word \*\)0x[0-9a-f]+\s*=\s*unaff_', stripped):
        return True
    if re.search(r'piVar\d+', stripped):
        return True
    if re.search(r'iVar\d+\s*=\s*iVar\d+\s*\+\s*\*\(int \*\)', stripped):
        return True
    if re.search(r'\*\(int \*\)0x[0-9a-f]+\s*=\s*iVar\d+', stripped):
        return True
    if re.search(r'iVar\d+\s*=\s*\(\(uint\)', stripped):
        return True
    return False


# ────────────────────────────────────────────────────────────────
# Function body conversion
# ────────────────────────────────────────────────────────────────

def convert_function_body(body, strings_db, func_info, exe_reader=None):
    """Convert a C function body to Pascal statements.

    func_info: dict with 'name', 'pascal_name', 'is_function', 'ret_type', 'params'
    """
    # Extract just the body inside { }
    brace_start = body.find('{')
    brace_end = body.rfind('}')
    if brace_start < 0:
        return '  { empty }'
    inner = body[brace_start + 1:brace_end] if brace_end > brace_start else body[brace_start + 1:]

    lines = inner.split('\n')

    # Phase 1: Detect and convert Write/WriteLn sequences
    write_seqs = detect_write_sequences(lines, strings_db, exe_reader)

    # Build a set of line indices consumed by write sequences
    consumed = set()
    write_replacements = {}  # start_idx → pascal statement
    for start, end, stmt in write_seqs:
        for k in range(start, end):
            consumed.add(k)
        write_replacements[start] = stmt

    # Phase 2: Collect non-consumed, non-noise lines with their type
    c_lines = []  # list of (tag, text) where tag is 'write' or 'code'
    for i, line in enumerate(lines):
        if i in consumed:
            if i in write_replacements:
                c_lines.append(('write', write_replacements[i]))
            continue

        stripped = line.strip()

        # Skip empty lines at the start
        if not stripped and not c_lines:
            continue

        # Detect halt handler = end of main block
        if 'bp_halt_handler' in stripped:
            break

        # Skip noise lines
        if is_noise_line(line):
            continue

        # Skip system init patterns
        if is_system_init_line(line):
            continue

        if stripped:
            c_lines.append(('code', stripped))

    # Phase 2b: Merge } + else patterns (C splits them across lines)
    merged = []
    i = 0
    while i < len(c_lines):
        tag, text = c_lines[i]
        if tag == 'code' and text == '}' and i + 1 < len(c_lines):
            next_tag, next_text = c_lines[i + 1]
            if next_tag == 'code' and next_text.startswith('else'):
                merged.append(('code', '} ' + next_text))
                i += 2
                continue
        merged.append((tag, text))
        i += 1

    # Phase 2c: Merge multi-line conditions (while/if spanning multiple lines)
    merged2 = []
    i = 0
    while i < len(merged):
        tag, text = merged[i]
        if tag == 'code' and text.count('(') > text.count(')'):
            # Unbalanced parens — merge with continuation lines
            while text.count('(') > text.count(')') and i + 1 < len(merged):
                i += 1
                next_tag, next_text = merged[i]
                if next_tag != 'code':
                    break
                text += ' ' + next_text
            merged2.append(('code', text))
        else:
            merged2.append((tag, text))
        i += 1

    # Phase 3: Convert C lines to Pascal
    raw_lines = []
    for tag, text in merged2:
        if tag == 'write':
            raw_lines.append(text)
        else:
            converted = convert_c_line(text, func_info)
            if converted is not None:
                raw_lines.append(converted.lstrip())

    # Phase 3: Apply proper indentation based on begin/end nesting
    result = []
    depth = 1  # Start at depth 1 (inside procedure/program begin)

    for raw in raw_lines:
        if not raw:
            result.append('')
            continue

        # Decrease depth for end/until lines BEFORE printing
        if re.match(r'^end\b|^until\b', raw):
            depth = max(1, depth - 1)

        result.append('  ' * depth + raw)

        # Increase depth for lines containing begin or repeat AFTER printing
        if re.search(r'\bbegin\b', raw) or raw == 'repeat':
            depth += 1

    # Clean up: remove trailing blank lines
    while result and not result[-1].strip():
        result.pop()

    return '\n'.join(result) if result else '  { empty }'


def convert_c_line(line, func_info):
    """Convert a single C statement line to Pascal."""
    if not line:
        return ''

    indent = '  '

    # Variable declarations (local vars)
    var_decl = re.match(r'^(\w+)\s+(\w+)\s*;$', line)
    if var_decl:
        ctype = var_decl.group(1)
        vname = var_decl.group(2)
        # Skip artifact variables
        if vname.startswith('unaff_') or vname.startswith('extraout_'):
            return None
        ptype = c_type_to_pascal(ctype)
        if ptype:
            return f'{indent}{{ var {vname}: {ptype}; }}'
        return None

    # Variable declarations with initialization
    var_init = re.match(r'^(\w+)\s+(\w+)\s*=\s*(.+?)\s*;$', line)
    if var_init:
        ctype = var_init.group(1)
        vname = var_init.group(2)
        value = var_init.group(3)
        if vname.startswith('unaff_') or vname.startswith('extraout_') or vname.startswith('uVar'):
            return None
        ptype = c_type_to_pascal(ctype)
        value = convert_expression(value)
        return f'{indent}{vname} := {value};'

    # Opening brace
    if line == '{':
        return f'{indent}begin'

    # Closing brace with else
    if line == '} else {' or line == '}else{':
        return f'{indent}end else begin'

    # Closing brace
    if line == '}' or line == '};':
        return f'{indent}end;'

    # Return statement with value (function result)
    ret_match = re.match(r'^return\s+(.+?)\s*;$', line)
    if ret_match:
        value = convert_expression(ret_match.group(1))
        if func_info.get('is_function'):
            return f'{indent}{func_info["pascal_name"]} := {value};'
        return None  # void return

    # Return void
    if line == 'return;':
        return None

    # if statement
    if_match = re.match(r'^if\s*\((.+?)\)\s*\{?\s*$', line)
    if if_match:
        cond = convert_condition(if_match.group(1))
        return f'{indent}if {cond} then begin'

    # Single-line if + break: if (cond) break;
    if_break = re.match(r'^if\s*\((.+?)\)\s*break\s*;', line)
    if if_break:
        cond = convert_condition(if_break.group(1))
        return f'{indent}if {cond} then Break;'

    # else if (with or without leading })
    elif_match = re.match(r'^(?:}\s*)?else\s+if\s*\((.+?)\)\s*\{?\s*$', line)
    if elif_match:
        cond = convert_condition(elif_match.group(1))
        return f'{indent}end else if {cond} then begin'

    # else
    if re.match(r'^(?:}\s*)?else\s*\{?\s*$', line):
        return f'{indent}end else begin'

    # while loop with comma operator: while (expr, cond) {
    # The comma operator means: evaluate expr, then test cond
    while_comma = re.match(r'^while\s*\((.+),\s*(.+?)\)\s*\{?\s*$', line)
    if while_comma:
        # expr is evaluated each iteration, cond is the loop test
        setup = convert_expression(while_comma.group(1).strip())
        cond = convert_condition(while_comma.group(2).strip())
        return f'{indent}while {cond} do begin {{ {setup} }}'

    # while loop
    while_match = re.match(r'^while\s*\((.+?)\)\s*\{?\s*$', line)
    if while_match:
        cond = convert_condition(while_match.group(1))
        return f'{indent}while {cond} do begin'

    # while(true)
    if 'while( true )' in line or 'while(true)' in line or 'while (true)' in line:
        return f'{indent}while True do begin'

    # do-while start
    if line == 'do {' or line == 'do{':
        return f'{indent}repeat'

    # do-while end
    dowhile_match = re.match(r'^}\s*while\s*\((.+?)\)\s*;?\s*$', line)
    if dowhile_match:
        cond = convert_condition(dowhile_match.group(1))
        # In Pascal, repeat/until uses the INVERSE condition
        neg_cond = negate_condition(cond)
        return f'{indent}until {neg_cond};'

    # for loop — complex, emit as while
    for_match = re.match(r'^for\s*\((.+?)\)\s*\{?\s*$', line)
    if for_match:
        return f'{indent}{{ for loop: {line} }}'

    # break
    if line == 'break;':
        return f'{indent}Break;'

    # continue
    if line == 'continue;':
        return f'{indent}Continue;'

    # Assignment with memory access
    assign_match = re.match(r'^(\*\((?:int|uint|word|byte|char) \*\)0x[0-9a-f]+)\s*=\s*(.+?)\s*;$', line)
    if assign_match:
        lhs = convert_expression(assign_match.group(1))
        rhs = convert_expression(assign_match.group(2))
        return f'{indent}{lhs} := {rhs};'

    # Assignment to pointer param: *param_1 = expr
    ptr_assign = re.match(r'^\*(\w+)\s*=\s*(.+?)\s*;$', line)
    if ptr_assign:
        lhs = ptr_assign.group(1)
        rhs = convert_expression(ptr_assign.group(2))
        return f'{indent}{lhs} := {rhs};'

    # Simple assignment: var = expr;
    simple_assign = re.match(r'^(\w+)\s*=\s*(.+?)\s*;$', line)
    if simple_assign:
        lhs = simple_assign.group(1)
        rhs = convert_expression(simple_assign.group(2))
        if lhs.startswith('uVar') or lhs.startswith('DAT_'):
            return None  # Skip temp/DAT assignments
        return f'{indent}{lhs} := {rhs};'

    # Compound assignment: *(type *)addr += expr or *(type *)addr op= expr
    compound_match = re.match(
        r'^(\*\((?:int|uint|word|byte|char) \*\)0x[0-9a-f]+)\s*'
        r'([\+\-\*])=\s*(.+?)\s*;$', line)
    if compound_match:
        lhs = convert_expression(compound_match.group(1))
        op = compound_match.group(2)
        rhs = convert_expression(compound_match.group(3))
        return f'{indent}{lhs} := {lhs} {op} {rhs};'

    # Function call (without assignment)
    call_match = re.match(r'^(\w+)\s*\(.*\)\s*;$', line)
    if call_match:
        fname = call_match.group(1)
        # Skip known noise functions
        if fname in ('bp_stack_check', 'bp_iocheck', 'bp_halt_handler',
                     'bp_write_char_flush', 'bp_flush_text_cond',
                     'bp_module_init', 'bp_clear_dseg', 'bp_runtime_init',
                     'bp_input_init', 'bp_output_init', 'bp_printstring'):
            return None
        # Convert known function names
        if fname.startswith('FUN_'):
            pascal_fname = 'Proc_' + fname[4:]
            # Extract arguments
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                args = args_match.group(1)
                args = convert_expression(args)
                return f'{indent}{pascal_fname}({args});'
            return f'{indent}{pascal_fname};'
        return f'{indent}{{ {line} }}'

    # Increment: var = var + 1
    inc_match = re.match(r'^(\w+)\s*=\s*\1\s*\+\s*1\s*;$', line)
    if inc_match:
        var = inc_match.group(1)
        return f'{indent}Inc({var});'

    # Decrement: var = var - 1
    dec_match = re.match(r'^(\w+)\s*=\s*\1\s*-\s*1\s*;$', line)
    if dec_match:
        var = dec_match.group(1)
        return f'{indent}Dec({var});'

    # Fall through: emit as comment
    if line.strip():
        return f'{indent}{{ {line} }}'

    return ''


def convert_condition(cond):
    """Convert a C condition expression to Pascal."""
    cond = cond.strip()

    # Char literals
    cond = re.sub(r"'\\0'", '0', cond)
    cond = re.sub(r"'\\x([0-9a-f]{2})'", lambda m: str(int(m.group(1), 16)), cond)

    # Memory access
    cond = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)(0x[0-9a-f]+)',
        lambda m: f'g_{m.group(1)[2:].zfill(4).upper()}',
        cond
    )

    # Hex constants → decimal
    cond = re.sub(
        r'\b0x([0-9a-f]+)\b',
        lambda m: str(int(m.group(1), 16)),
        cond
    )

    # Operators
    cond = cond.replace('!=', ' <> ')
    cond = cond.replace('==', ' = ')
    cond = cond.replace('&&', ' and ')
    cond = cond.replace('||', ' or ')
    cond = re.sub(r'!(\w)', r'not \1', cond)

    # Clean up
    cond = re.sub(r'\s+', ' ', cond).strip()

    return cond


def negate_condition(cond):
    """Negate a Pascal condition for repeat/until conversion."""
    # Simple cases
    if ' < ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' < ', ' >= ')
    if ' <= ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' <= ', ' > ')
    if ' > ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' > ', ' <= ')
    if ' >= ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' >= ', ' < ')
    if ' = ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' = ', ' <> ')
    if ' <> ' in cond and ' and ' not in cond and ' or ' not in cond:
        return cond.replace(' <> ', ' = ')
    return f'not ({cond})'


# ────────────────────────────────────────────────────────────────
# Global variable detection
# ────────────────────────────────────────────────────────────────

GLOBAL_MEM_RE = re.compile(r'\*\((int|uint|word|byte|char) \*\)(0x[0-9a-f]+)')


def detect_globals(functions):
    """Scan all function bodies for global memory accesses.

    Returns OrderedDict of offset → type, sorted by offset.
    """
    globals_map = {}
    for func in functions:
        for m in GLOBAL_MEM_RE.finditer(func['body']):
            ctype = m.group(1)
            offset = m.group(2)
            # Prefer wider type if conflict
            if offset not in globals_map or _type_width(ctype) > _type_width(globals_map[offset]):
                globals_map[offset] = ctype

    # Sort by offset
    sorted_globals = OrderedDict()
    for off in sorted(globals_map.keys(), key=lambda x: int(x, 16)):
        sorted_globals[off] = globals_map[off]

    return sorted_globals


def _type_width(ctype):
    return {'char': 1, 'byte': 1, 'word': 2, 'uint': 2, 'int': 2, 'dword': 4}.get(ctype, 2)


# ────────────────────────────────────────────────────────────────
# Uses clause detection
# ────────────────────────────────────────────────────────────────

def detect_uses(functions):
    """Detect which Pascal units are needed from library function names.

    Only scans application and entry functions — library functions
    are part of the RTL, not the user's uses clause.
    """
    uses = set()
    # Only look at app-level function bodies for calls to CRT/DOS library functions
    app_text = '\n'.join(
        f['body'] for f in functions
        if f.get('classification') in ('application', 'entry')
    )

    if re.search(r'\bcrt_|@AssignCrt|crt_gotoxy|crt_textattr|crt_clrscr|crt_readkey', app_text):
        uses.add('Crt')
    if re.search(r'\bdos_intr\b|@GetDate|@GetTime|@FindFirst|@DiskSize|@SetIntVec|@FSplit|@GetEnv|@Intr', app_text):
        uses.add('Dos')

    return sorted(uses)


# ────────────────────────────────────────────────────────────────
# Pascal file emitter
# ────────────────────────────────────────────────────────────────

def emit_pascal(program_name, uses, globals_map, app_functions, main_body):
    """Generate a complete .pas file."""
    lines = []

    # Program header
    lines.append(f'program {program_name};')
    lines.append('')

    # Uses clause
    if uses:
        lines.append(f'uses {", ".join(uses)};')
        lines.append('')

    # Global variables
    if globals_map:
        lines.append('var')
        for offset, ctype in globals_map.items():
            vname = f'g_{offset[2:].zfill(4).upper()}'
            ptype = c_type_to_pascal(ctype)
            lines.append(f'  {vname}: {ptype};')
        lines.append('')

    # Forward declarations (if functions reference each other)
    for func in app_functions:
        if func.get('is_function'):
            lines.append(f'{func["declaration"]} forward;')
        else:
            lines.append(f'{func["declaration"]} forward;')
    if app_functions:
        lines.append('')

    # Function/procedure bodies
    for func in app_functions:
        lines.append(func['declaration'])

        # Local variables
        if func.get('local_vars'):
            lines.append('var')
            for vname, vtype in func['local_vars']:
                lines.append(f'  {vname}: {vtype};')

        lines.append('begin')
        lines.append(func['body'])
        lines.append('end;')
        lines.append('')

    # Main block
    lines.append('begin')
    if main_body:
        lines.append(main_body)
    else:
        lines.append('  { Main program body }')
    lines.append('end.')

    return '\n'.join(lines)


# ────────────────────────────────────────────────────────────────
# Main pipeline
# ────────────────────────────────────────────────────────────────

def process(decompiled_path, strings_path=None, output_path=None, exe_path=None):
    """Process a decompiled.c file and emit a .pas file."""
    with open(decompiled_path, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    # Determine program name from directory
    dir_name = os.path.basename(os.path.dirname(os.path.abspath(decompiled_path)))
    program_name = dir_name if dir_name and dir_name != '.' else 'Program1'

    # Auto-detect strings.json
    if not strings_path:
        candidate = os.path.join(os.path.dirname(decompiled_path), 'strings.json')
        if os.path.isfile(candidate):
            strings_path = candidate

    strings_db = load_strings(strings_path)

    # Auto-detect EXE for direct string reading
    exe_reader = None
    if not exe_path:
        exe_path = find_exe_for_decompiled(decompiled_path)
    if exe_path:
        exe_reader = ExeStringReader(exe_path)

    # Parse functions
    functions = parse_functions(text)

    # Find primary segment
    primary_seg = find_primary_segment(functions)

    # Classify functions
    for func in functions:
        func['classification'] = classify_function(func)
        # Refine: functions NOT in the primary segment and not entry are system
        if (func['classification'] == 'application' and
                func['segment'] != primary_seg and
                func['name'] != 'entry'):
            func['classification'] = 'system'

    # Separate function types
    app_funcs = [f for f in functions if f['classification'] == 'application']
    entry_func = next((f for f in functions if f['classification'] == 'entry'), None)

    # Detect uses clause
    uses = detect_uses(functions)

    # Detect global variables (from app functions and entry)
    scan_funcs = app_funcs + ([entry_func] if entry_func else [])
    globals_map = detect_globals(scan_funcs)

    # Filter out low-address system globals (< 0x50 are typically system area)
    globals_map = OrderedDict(
        (k, v) for k, v in globals_map.items()
        if int(k, 16) >= 0x50
    )

    # Convert application functions
    pascal_funcs = []
    for func in app_funcs:
        sig_info = parse_c_signature(func['body'])
        if not sig_info:
            continue

        ret_type, c_name, params = sig_info
        keyword, declaration, pascal_name, is_function = make_pascal_signature(
            ret_type, func['name'], params)

        func_info = {
            'name': func['name'],
            'pascal_name': pascal_name,
            'is_function': is_function,
            'ret_type': ret_type,
            'params': params,
        }

        body = convert_function_body(func['body'], strings_db, func_info, exe_reader)

        # Extract local variable declarations from body
        local_vars = []
        clean_body_lines = []
        for bline in body.split('\n'):
            lv_match = re.match(r'\s*\{ var (\w+): (\w+); \}', bline)
            if lv_match:
                local_vars.append((lv_match.group(1), lv_match.group(2)))
            else:
                clean_body_lines.append(bline)

        pascal_funcs.append({
            'declaration': declaration,
            'body': '\n'.join(clean_body_lines),
            'is_function': is_function,
            'pascal_name': pascal_name,
            'local_vars': local_vars,
        })

    # Convert entry function (main block)
    main_body = ''
    if entry_func:
        func_info = {
            'name': 'entry',
            'pascal_name': program_name,
            'is_function': False,
            'ret_type': 'void',
            'params': [],
        }
        main_body = convert_function_body(entry_func['body'], strings_db, func_info, exe_reader)

    # Emit
    pascal_text = emit_pascal(program_name, uses, globals_map, pascal_funcs, main_body)

    # Determine output path
    if not output_path:
        output_path = os.path.join(
            os.path.dirname(decompiled_path),
            program_name + '.pas'
        )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(pascal_text)

    print(f'  {output_path}')
    return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pascal_emit.py <decompiled.c> [-o output.pas]")
        sys.exit(1)

    output_path = None
    paths = []
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        else:
            paths.append(sys.argv[i])
            i += 1

    for path in paths:
        process(path, output_path=output_path)


if __name__ == '__main__':
    main()
