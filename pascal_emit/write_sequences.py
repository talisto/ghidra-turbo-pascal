"""Write/WriteLn sequence detection and conversion."""
import re

from .expressions import convert_expression


# Patterns for Write/WriteLn-related calls
WRITE_STR_CALL_RE = re.compile(
    r'(?:bp_write_str|FUN_\w+_0670)\s*\('
)
WRITE_STR_ARGS_RE = re.compile(
    r'(?:bp_write_str|FUN_\w+_0670)\s*\(\s*\d+\s*,\s*(0x[0-9a-f]+|\d+)\s*,\s*0x[0-9a-f]+\s*\)'
)
WRITE_INT_RE = re.compile(r'bp_write_int\s*\(')
WRITE_LONGINT_RE = re.compile(r'bp_write_longint\s*\(')
WRITELN_END_RE = re.compile(r'bp_write_char_flush\s*\(')
WRITE_END_RE = re.compile(r'bp_flush_text_cond\s*\(')
STRING_ANNOTATION_RE = re.compile(r'/\*\s*"((?:[^"\\]|\\.)*)"\s*\*/')

WRITE_INT_ARGS_RE = re.compile(
    r'bp_write_int\s*\(\s*(\d+)\s*,\s*(.+?)\s*,\s*\1\s*>>\s*0xf\s*\)'
)
WRITE_INT_ARGS_SIMPLE_RE = re.compile(
    r'bp_write_int\s*\(\s*(\d+)\s*,\s*(.+?)\s*,'
)

DAT_VALUE_RE = re.compile(r'DAT_\w+ = (\*\(int \*\)0x[0-9a-f]+)')


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
                text = extract_string_annotation(jline)
                if not text:
                    for k in range(max(start_idx, j - 8), j):
                        text = extract_string_annotation(lines[k].strip())
                        if text:
                            break
                if not text:
                    m_args = WRITE_STR_ARGS_RE.search(jline)
                    if m_args:
                        offset_str = m_args.group(1)
                        offset_val = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                        text = strings_db.get(offset_val)
                        if not text and exe_reader:
                            text = exe_reader.read_string(offset_val)
                if not text and dat_annotations:
                    text = dat_annotations[-1]
                if not text and dat_values:
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
                        text = strings_db.get(off)
                        if text:
                            break
                        if exe_reader:
                            text = exe_reader.read_string(off)
                            if text:
                                break
                dat_annotations.clear()
                dat_values.clear()
                if text:
                    text = text.replace("'", "''")
                    parts.append(f"'{text}'")
                else:
                    parts.append("'{???}'")
                j += 1
                continue

            # Integer write part
            if WRITE_INT_RE.search(jline):
                found_write = True
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
                    if parts:
                        sequences.append((start_idx, j, f"WriteLn({', '.join(parts)});"))
                    else:
                        sequences.append((start_idx, j, 'WriteLn;'))
                    break
                else:
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

            # DAT_ lines (entry function argument setup)
            if jline.startswith('DAT_'):
                ann = extract_string_annotation(jline)
                if ann:
                    dat_annotations.append(ann)
                dat_val_match = re.search(r'DAT_\w+\s*=\s*(.+?)\s*;', jline)
                if dat_val_match:
                    val = dat_val_match.group(1).strip()
                    dat_values.append(val)
                j += 1
                continue

            # puVar stack push lines
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

            # Temp variable assignments (iVarN, uVarN)
            if re.match(r'^[iu]Var\d+\s*=', jline):
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
                break

            # Not part of a write sequence
            if found_write:
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
        m = DAT_VALUE_RE.search(kline)
        if m:
            return m.group(1)
        pv = re.search(r'\*\(int \*\)\(puVar\d+ \+ -\d+\)\s*=\s*(\w+)\s*;', kline)
        if pv:
            val = pv.group(1)
            if re.match(r'^iVar\d+$', val):
                for m2 in range(k - 1, max(0, k - 4), -1):
                    m2line = lines[m2].strip()
                    iv_match = re.match(rf'^{re.escape(val)}\s*=\s*(.+?)\s*;', m2line)
                    if iv_match:
                        return iv_match.group(1)
            return val
        iv = re.match(r'^iVar\d+\s*=\s*(\*\(int \*\)0x[0-9a-f]+)\s*;', kline)
        if iv:
            return iv.group(1)
    return None
