"""Convert C function bodies to Pascal statements."""
import re

from .expressions import convert_expression, convert_condition, negate_condition
from .types import c_type_to_pascal
from .write_sequences import detect_write_sequences

# Library label → Pascal builtin mapping (only functions that work as
# standalone calls or whose args are explicitly present in the decompiled output)
_LABEL_TO_PASCAL = {
    'bp_random': 'Random',
    'bp_randomize': 'Randomize',
    'bp_halt': 'Halt',
    'bp_delay': 'Delay',
    'bp_readkey': 'ReadKey',
    'bp_keypressed': 'KeyPressed',
    'bp_gotoxy': 'GotoXY',
    'bp_clrscr': 'ClrScr',
    'bp_clreol': 'ClrEol',
    'bp_textcolor': 'TextColor',
    'bp_textbackground': 'TextBackground',
    'bp_ioresult': 'IOResult',
    'crt_wherex_impl': 'WhereX',
    'crt_wherey_impl': 'WhereY',
    'crt_gotoxy_impl': 'GotoXY',
}


# Lines to strip entirely (noise)
NOISE_PATTERNS = [
    re.compile(r'^\s*(?:bp_stack_check|FUN_\w+_02cd)\s*\('),
    re.compile(r'^\s*(?:bp_iocheck|FUN_\w+_0291)\s*\('),
    re.compile(r'^\s*return\s*;\s*$'),
    re.compile(r'^\s*\w+ unaff_\w+\s*;'),
    re.compile(r'^\s*\w+ extraout_\w+\s*;'),
    re.compile(r'^\s*\w+ uVar\d+\s*;'),
    re.compile(r'^\s*uVar\d+\s*=\s*.*;\s*$'),
    re.compile(r'^\s*DAT_\w+\s*='),
    re.compile(r'^\s*/\*\s*WARNING'),
    re.compile(r'^\s*func_0x'),
    re.compile(r'^\s*(?:bp_halt_handler|_Halt_q4Word)\s*\('),
    re.compile(r'^\s*(?:bp_module_init|FUN_\w+_00b1)\s*\('),
    re.compile(r'^\s*(?:bp_clear_dseg|__ClearDSeg)\s*\('),
    re.compile(r'^\s*(?:bp_runtime_init|FUN_\w+_02e6)\s*\('),
    re.compile(r'^\s*(?:bp_input_init|FUN_\w+_0364)\s*\('),
    re.compile(r'^\s*(?:bp_output_init|FUN_\w+_0369)\s*\('),
    re.compile(r'^\s*(?:bp_printstring|__PrintString)\s*\('),
    re.compile(r'^\s*___SystemInit_qv\s*\('),
    re.compile(r'^\s*\(\*pcVar\d+\)\s*\('),
    re.compile(r'^\s*pcVar\d+\s*='),
    re.compile(r'^\s*code \*pcVar'),
    re.compile(r'^\s*\*puVar\d+\s*='),
    re.compile(r'^\s*puVar\d+\s*='),
    re.compile(r'^\s*puVar\d+\['),
    re.compile(r'^\s*\*\(word \*\)\(puVar\d+ \+ -?'),
    re.compile(r'^\s*\w+ \*puVar\d+\s*;'),
    re.compile(r'^\s*\w+ in_\w+\s*;'),
    re.compile(r'^\s*int unaff_'),
    re.compile(r'^\s*word unaff_'),
    re.compile(r'^\s*word uVar\d+\s*;'),
    re.compile(r'^\s*int iVar\d+\s*;'),
    re.compile(r'^\s*char cVar\d+\s*;'),
    re.compile(r'^\s*word extraout_'),
    re.compile(r'^\s*int \*piVar\d+\s*;'),
    re.compile(r'^\s*code \*'),
    re.compile(r'^\s*dword uVar\d+\s*;'),
    re.compile(r'^\s*byte \*puVar'),
    re.compile(r'^\s*word \*puVar'),
    re.compile(r'^\s*\w+Var\d+\s*=\s*\*\(.*puVar'),
    # Leaked Ghidra identifiers in active code
    re.compile(r'^\s*(?:p[bui]Var\d+|abStack_\w+)\s*[=\[]'),
    re.compile(r'^\s*\*\s*(?:p[bui]Var\d+|abStack_\w+)'),
    re.compile(r'^\s*(?:byte|word|int)\s+\*?(?:p[bui]Var|pbVar|abStack_)'),
    # extraout_ assignments
    re.compile(r'^\s*extraout_\w+\s*='),
    # CARRY artifacts from 32-bit arithmetic
    re.compile(r'^\s*\w+\s*=\s*.*CARRY\d'),
    re.compile(r'^\s*CARRY\d'),
    # func_0x references (raw Ghidra func pointers)
    re.compile(r'^\s*func_0x[0-9a-f]+\s*\('),
    # DAT_ with direct dereference in assignment context
    re.compile(r'^\s*DAT_\w+\s*=\s*DAT_'),
]


def is_noise_line(line, referenced_uvars=None):
    """Check if a line should be stripped as noise."""
    stripped = line.strip()
    if not stripped:
        return False
    # Preserve uVar assignments when the variable is referenced elsewhere
    if referenced_uvars:
        m = re.match(r'^\s*uVar(\d+)\s*=', stripped)
        if m and m.group(1) in referenced_uvars:
            return False
    for pat in NOISE_PATTERNS:
        if pat.search(stripped):
            return True
    return False


def is_system_init_line(line):
    """Check if a line is part of system initialization (after bp_halt_handler)."""
    stripped = line.strip()
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


# ── Case statement reconstruction ──

# Matches:  if VAR = CONST then begin
_CASE_IF_RE = re.compile(r'^(\s*)if\s+(\w+)\s*=\s*(\d+)\s+then\s+begin\s*$')
# Matches:  end else if VAR = CONST then begin
_CASE_ELIF_RE = re.compile(r'^(\s*)end\s+else\s+if\s+(\w+)\s*=\s*(\d+)\s+then\s+begin\s*$')
# Matches:  end else if (VAR < LO) or (HI < VAR) then begin
_CASE_RANGE_COMPLEMENT_RE = re.compile(
    r'^(\s*)end\s+else\s+if\s+\((\w+)\s*<\s*(\d+)\)\s+or\s+\((\d+)\s*<\s*\2\)\s+then\s+begin\s*$'
)
# Matches:  end else begin
_CASE_ELSE_RE = re.compile(r'^(\s*)end\s+else\s+begin\s*$')
# Matches:  end;
_CASE_END_RE = re.compile(r'^(\s*)end;\s*$')


def _reconstruct_case_statements(lines):
    """Post-process Pascal lines to convert if/else if chains to case statements.

    Detects patterns like:
        if VAR = 1 then begin ... end else if VAR = 2 then begin ... end;
    And converts to:
        case VAR of 1: begin ... end; 2: begin ... end; end;

    Also handles Ghidra's range complement pattern:
        end else if (VAR < 3) or (5 < VAR) then begin
    which means "NOT in range 3..5", so the else branch IS the range case.
    """
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _CASE_IF_RE.match(line)
        if not m:
            result.append(line)
            i += 1
            continue

        indent = m.group(1)
        case_var = m.group(2)
        first_val = m.group(3)

        # Collect entire if/else chain
        chain = _collect_case_chain(lines, i, indent, case_var)

        if chain is None or len(chain['branches']) < 2:
            # Not a meaningful case chain (need at least 2 branches)
            result.append(line)
            i += 1
            continue

        # Emit case statement
        result.append(f'{indent}case {case_var} of')
        for branch in chain['branches']:
            label = branch['label']
            body = branch['body']
            if len(body) == 1:
                # Single statement — emit on same line
                stmt = body[0].strip().rstrip(';')
                result.append(f'{indent}  {label}: {stmt};')
            else:
                result.append(f'{indent}  {label}: begin')
                for bline in body:
                    result.append(f'{indent}  {bline.rstrip()}')
                result.append(f'{indent}  end;')

        if chain['else_body']:
            result.append(f'{indent}else')
            if len(chain['else_body']) == 1:
                stmt = chain['else_body'][0].strip().rstrip(';')
                result.append(f'{indent}  {stmt};')
            else:
                result.append(f'{indent}  begin')
                for bline in chain['else_body']:
                    result.append(f'{indent}  {bline.rstrip()}')
                result.append(f'{indent}  end;')

        result.append(f'{indent}end;')
        i = chain['end_index']
        continue

    return result


def _collect_case_chain(lines, start, indent, case_var):
    """Collect an if/else if chain comparing case_var to integer constants.

    Returns dict with:
        branches: list of {label: str, body: list[str]}
        else_body: list[str] or None
        end_index: int (next line index after the chain)
    Or None if the chain doesn't match.
    """
    branches = []
    else_body = None
    i = start

    # First branch: if VAR = CONST then begin
    m = _CASE_IF_RE.match(lines[i])
    if not m or m.group(2) != case_var:
        return None

    first_val = m.group(3)
    i += 1
    body, i = _collect_branch_body(lines, i, indent)
    branches.append({'label': first_val, 'body': body})

    # Subsequent branches: end else if ...
    while i < len(lines):
        line = lines[i]

        # end else if VAR = CONST then begin
        m = _CASE_ELIF_RE.match(line)
        if m and m.group(2) == case_var:
            i += 1
            body, i = _collect_branch_body(lines, i, indent)
            branches.append({'label': m.group(3), 'body': body})
            continue

        # end else if (VAR < LO) or (HI < VAR) then begin — range complement
        m = _CASE_RANGE_COMPLEMENT_RE.match(line)
        if m and m.group(2) == case_var:
            lo = int(m.group(3))
            hi = int(m.group(4))
            # This branch is for NOT in range LO..HI
            # The else of this branch IS the range case
            i += 1
            not_range_body, i = _collect_complement_branch(lines, i, indent)

            if not_range_body is not None:
                # not_range_body has two parts: the "not range" body and the "range" body
                complement_body = not_range_body['outer_body']
                range_body = not_range_body['inner_body']

                if range_body is not None:
                    # The inner (else) body is the range case
                    branches.append({'label': f'{lo}..{hi}', 'body': range_body})
                    # The outer body is the else/other handler
                    if complement_body:
                        # Check for nested range pattern in complement body
                        nested = _try_nested_range(complement_body, indent, case_var)
                        if nested:
                            branches.extend(nested['branches'])
                            if nested['else_body']:
                                else_body = nested['else_body']
                        else:
                            else_body = complement_body
                else:
                    else_body = complement_body
            continue

        # end else begin — else clause
        m = _CASE_ELSE_RE.match(line)
        if m:
            i += 1
            body, i = _collect_branch_body(lines, i, indent)
            else_body = body
            continue

        # end; — end of chain
        m = _CASE_END_RE.match(line)
        if m and _indent_level(line) == _indent_level(lines[start]):
            i += 1
            break
        else:
            break

    return {
        'branches': branches,
        'else_body': else_body,
        'end_index': i,
    }


def _collect_branch_body(lines, i, base_indent):
    """Collect lines until we hit a matching end/else at the same indentation level.

    Returns (body_lines, next_index).
    """
    body = []
    depth = 1  # we're inside a begin block
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check end FIRST — if it closes the current block, stop before
        # counting any begin on the same line (e.g., "end else if ... begin")
        if re.match(r'^end\b', stripped):
            depth -= 1
            if depth == 0:
                return body, i

        if re.search(r'\bbegin\b', stripped):
            depth += 1

        body.append(line)
        i += 1

    return body, i


def _collect_complement_branch(lines, i, base_indent):
    """Collect a range complement branch (the NOT-in-range branch).

    This branch has the pattern:
        [outer body]
        end else begin     ← the range case body
        [inner body]
        end;

    Returns (result_dict, next_index) where result_dict has outer_body and inner_body.
    """
    outer_body = []
    inner_body = None
    depth = 1

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if re.match(r'^end\b', stripped):
            depth -= 1
            if depth == 0:
                # Check if it's "end else begin" (inner range case)
                if _CASE_ELSE_RE.match(line):
                    depth = 1
                    i += 1
                    inner_body, i = _collect_branch_body(lines, i, base_indent)
                    return {'outer_body': outer_body, 'inner_body': inner_body}, i
                # Or just "end;" — no inner branch
                return {'outer_body': outer_body, 'inner_body': None}, i

        if re.search(r'\bbegin\b', stripped):
            depth += 1

        outer_body.append(line)
        i += 1

    return {'outer_body': outer_body, 'inner_body': None}, i


def _try_nested_range(body_lines, indent, case_var):
    """Check if body_lines contain a nested range complement pattern.

    Pattern: if (VAR < LO) or (HI < VAR) then begin ... end else begin ... end;
    """
    if not body_lines:
        return None
    first = body_lines[0].strip()
    m = re.match(
        r'if\s+\((' + re.escape(case_var) + r')\s*<\s*(\d+)\)\s+or\s+\((\d+)\s*<\s*\1\)\s+then\s+begin\s*$',
        first
    )
    if not m:
        return None

    lo = int(m.group(2))
    hi = int(m.group(3))

    # Parse the nested structure
    branches = []
    i = 1
    outer_body = []
    inner_body = None
    depth = 1

    while i < len(body_lines):
        line = body_lines[i]
        stripped = line.strip()

        if re.match(r'^end\b', stripped):
            depth -= 1
            if depth == 0:
                if _CASE_ELSE_RE.match(line):
                    depth = 1
                    i += 1
                    while i < len(body_lines):
                        line2 = body_lines[i]
                        stripped2 = line2.strip()
                        if re.match(r'^end\b', stripped2):
                            depth -= 1
                            if depth == 0:
                                break
                        if re.search(r'\bbegin\b', stripped2):
                            depth += 1
                        inner_body = inner_body or []
                        inner_body.append(line2)
                        i += 1
                    break
                break

        if re.search(r'\bbegin\b', stripped):
            depth += 1

        outer_body.append(line)
        i += 1

    if inner_body is not None:
        branches.append({'label': f'{lo}..{hi}', 'body': inner_body})
        return {'branches': branches, 'else_body': outer_body if outer_body else None}

    return None


def _indent_level(line):
    """Return the indentation level (number of leading spaces)."""
    return len(line) - len(line.lstrip())


# ── For loop patterns ──
# Pattern: for (VAR = START; ..., VAR != END; VAR = VAR + 1)
_FOR_UP_RE = re.compile(
    r'^(\w+)\s*=\s*(.+?);\s*'           # init: var = start
    r'(?:(.+?),\s*)?'                     # optional comma body
    r'(\w+)\s*!=\s*(.+?);\s*'            # cond: var != end
    r'(\w+)\s*=\s*\6\s*\+\s*1$'          # step: var = var + 1
)
# Pattern: for (VAR = START; ..., VAR != END; VAR = VAR - 1)
_FOR_DOWN_RE = re.compile(
    r'^(\w+)\s*=\s*(.+?);\s*'           # init: var = start
    r'(?:(.+?),\s*)?'                     # optional comma body
    r'(\w+)\s*!=\s*(.+?);\s*'            # cond: var != end
    r'(\w+)\s*=\s*\6\s*-\s*1$'          # step: var = var - 1
)
# Pattern: for (; VAR != 0; VAR = VAR - 1)  (countdown to 0)
_FOR_COUNTDOWN_RE = re.compile(
    r'^;\s*'                              # no init
    r'(?:(.+?),\s*)?'                     # optional comma body
    r'(\w+)\s*!=\s*0;\s*'               # cond: var != 0
    r'(\w+)\s*=\s*\3\s*-\s*1$'          # step: var = var - 1
)


def _convert_for_loop(for_content, indent):
    """Convert a C for loop to Pascal.

    Tries to match simple counting for loops and convert to Pascal for/downto.
    Falls back to while loop for complex patterns.
    """
    # Try counting up: for (var = start; ..., var != end; var = var + 1)
    m = _FOR_UP_RE.match(for_content)
    if m:
        var_init, start, comma_body, var_cond, end, var_step = m.groups()
        if var_init == var_cond == var_step:
            start_expr = convert_expression(start)
            end_expr = convert_expression(end)
            if comma_body:
                # Multi-assignment comma body — emit as while loop
                # (commented for header, body lines still processed)
                return f'{indent}while True do begin'
            else:
                # No comma body: loop stops BEFORE end value
                try:
                    end_val = int(end) - 1
                    end_expr = str(end_val)
                except ValueError:
                    end_expr = convert_expression(end) + ' - 1'
                return f'{indent}for {var_init} := {start_expr} to {end_expr} do begin'

    # Try counting down: for (var = start; ..., var != end; var = var - 1)
    m = _FOR_DOWN_RE.match(for_content)
    if m:
        var_init, start, comma_body, var_cond, end, var_step = m.groups()
        if var_init == var_cond == var_step:
            start_expr = convert_expression(start)
            end_expr = convert_expression(end)
            if comma_body:
                # Multi-assignment comma body — emit as while loop
                # (commented for header, body lines still processed)
                return f'{indent}while True do begin'
            else:
                try:
                    end_val = int(end) + 1
                    end_expr = str(end_val)
                except ValueError:
                    end_expr = convert_expression(end) + ' + 1'
                return f'{indent}for {var_init} := {start_expr} downto {end_expr} do begin'

    # Try countdown to 0: for (; var != 0; var = var - 1)
    m = _FOR_COUNTDOWN_RE.match(for_content)
    if m:
        comma_body, var_cond, var_step = m.groups()
        if var_cond == var_step:
            pre = ''
            if comma_body:
                pre_stmt = convert_expression(comma_body.strip())
                pre = f'\n{indent}  {pre_stmt};'
            return f'{indent}while {var_cond} <> 0 do begin{pre}'

    # Fallback: emit as while loop comment
    return f'{indent}{{ for loop: for ({for_content}) }}'


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
    write_replacements = {}
    for start, end, stmt in write_seqs:
        for k in range(start, end):
            consumed.add(k)
        write_replacements[start] = stmt

    # Pre-scan: find uVar names referenced outside their own assignments
    # to avoid stripping assignments that are actually used
    _uvar_assign_re = re.compile(r'^\s*uVar(\d+)\s*=')
    _uvar_ref_re = re.compile(r'\buVar(\d+)\b')
    referenced_uvars = set()
    for line in lines:
        s = line.strip()
        # Skip declaration lines and assignment lines
        if _uvar_assign_re.match(s):
            continue
        if re.match(r'^\s*(?:word|undefined2|dword)\s+uVar\d+', s):
            continue
        for m in _uvar_ref_re.finditer(s):
            referenced_uvars.add(m.group(1))

    # Phase 2: Collect non-consumed, non-noise lines with their type
    c_lines = []
    for i, line in enumerate(lines):
        if i in consumed:
            if i in write_replacements:
                c_lines.append(('write', write_replacements[i]))
            continue

        stripped = line.strip()

        if not stripped and not c_lines:
            continue

        if 'bp_halt_handler' in stripped or '_Halt_q4Word' in stripped:
            # Emit Halt and collect only the closing braces needed to
            # balance the current nesting depth back to zero.
            c_lines.append(('code', 'bp_halt();'))
            depth = 0
            for cl in c_lines:
                if cl[0] == 'code':
                    depth += cl[1].count('{') - cl[1].count('}')
            for remaining in lines[i + 1:]:
                rs = remaining.strip()
                if rs == '}' or rs == '};':
                    c_lines.append(('code', rs))
                    depth -= 1
                    if depth <= 0:
                        break
                elif '{' in rs:
                    break  # New block opened after halt — stop
            break

        if is_noise_line(line, referenced_uvars):
            continue

        if is_system_init_line(line):
            continue

        if stripped:
            c_lines.append(('code', stripped))

    # Phase 2b: Merge } + else patterns
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

    # Phase 2c: Merge multi-line conditions
    merged2 = []
    i = 0
    while i < len(merged):
        tag, text = merged[i]
        if tag == 'code' and text.count('(') > text.count(')'):
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

    # Phase 4: Apply proper indentation based on begin/end nesting
    result = []
    depth = 1

    for raw in raw_lines:
        if not raw:
            result.append('')
            continue

        if re.match(r'^end\b|^until\b', raw):
            depth = max(1, depth - 1)

        result.append('  ' * depth + raw)

        if re.search(r'\bbegin\b', raw) or raw == 'repeat':
            depth += 1

    while result and not result[-1].strip():
        result.pop()

    # Phase 4.5: Sanitize leaked Ghidra identifiers
    result = _sanitize_ghidra_artifacts(result)

    # Phase 5: Reconstruct case statements from if/else if chains
    result = _reconstruct_case_statements(result)

    return '\n'.join(result) if result else '  { empty }'


# Patterns for identifiers that must not appear in active Pascal code
_LEAKED_IDENT_RE = re.compile(
    r'\b(?:p[bui]Var\d+|abStack_\w+|CARRY\d|func_0x[0-9a-f]+|'
    r'extraout_\w+|stack0x[0-9a-f]+|DAT_[0-9a-f_]+|FUN_[0-9a-f_]+|'
    r'dos_\w+)\b',
    re.IGNORECASE
)


def _sanitize_ghidra_artifacts(lines):
    """Comment out lines containing leaked Ghidra identifiers.

    Lines that reference undeclared Ghidra variables (puVar, pbVar,
    abStack, CARRY, func_0x, extraout_, stack0x) are wrapped in comments
    unless they're already inside a comment.

    When commenting out a line that opens a begin/end block, the matching
    end is also commented out to prevent orphaned structural keywords.
    """
    result = []
    for line in lines:
        stripped = line.strip()
        # Skip lines already commented out
        if stripped.startswith('{') and stripped.endswith('}'):
            result.append(line)
            continue
        # Skip structural keywords
        if stripped in ('begin', 'end;', 'end.', 'repeat', '') or stripped.startswith('end '):
            result.append(line)
            continue
        # For Write/WriteLn lines, convert FUN_ calls to Func_ before
        # checking for leaked identifiers — these are function calls
        # that should match their Pascal declarations
        check_text = stripped
        if re.match(r'Write(?:Ln)?\s*\(', stripped) and 'FUN_' in stripped:
            check_text = re.sub(r'\bFUN_([0-9a-fA-F_]+)', r'Func_\1', stripped)
        # Check for leaked identifiers
        if _LEAKED_IDENT_RE.search(check_text):
            indent = line[:len(line) - len(line.lstrip())]
            result.append(f'{indent}{{ {stripped} }}')
        else:
            if check_text != stripped:
                # FUN_ was converted to Func_ — use the converted version
                indent = line[:len(line) - len(line.lstrip())]
                result.append(f'{indent}{check_text}')
            else:
                result.append(line)

    # Second pass: comment out orphaned end; keywords whose matching begin
    # was commented out.  Track depth from lines that are NOT comments.
    result = _fix_orphaned_ends(result)
    result = _fix_orphaned_breaks(result)
    return result


def _fix_orphaned_breaks(lines):
    """Comment out Break statements that are not inside a while/repeat loop.

    Tracks loop depth by counting while/repeat openers and their matching
    end; closers.  A ``Break`` at depth 0 is orphaned and gets commented out.
    """
    # First pass: determine loop depth at each line
    loop_depth = 0
    # Track begin/end depth within loops to match the right end;
    block_stack = []  # stack of (kind, depth) where kind is 'loop' or 'block'
    result = []
    for line in lines:
        stripped = line.strip()
        is_comment = stripped.startswith('{') and stripped.endswith('}')
        if is_comment or not stripped:
            result.append(line)
            continue

        is_loop_start = bool(re.search(r'\bwhile\b.*\bdo\b.*\bbegin\b', stripped)) or stripped == 'repeat'
        has_begin = bool(re.search(r'\bbegin\b', stripped))
        is_standalone_end = stripped == 'end;'

        if is_loop_start:
            loop_depth += 1
            block_stack.append('loop')
        elif has_begin and not is_loop_start:
            block_stack.append('block')
        elif is_standalone_end and block_stack:
            kind = block_stack.pop()
            if kind == 'loop':
                loop_depth -= 1

        if re.search(r'\bBreak\b', stripped, re.IGNORECASE) and loop_depth <= 0:
            indent = line[:len(line) - len(line.lstrip())]
            result.append(f'{indent}{{ {stripped} }}')
        else:
            result.append(line)
    return result


def _fix_orphaned_ends(lines):
    """Comment out end; lines that have no matching begin.

    Scans active (non-comment) lines tracking begin/end depth.  When an
    ``end;`` would drive depth negative (no matching ``begin``), it is
    wrapped in a comment.  ``case ... of`` counts as an implicit block
    opener since it requires a closing ``end;`` without a ``begin``.

    Lines like ``end else if ... then begin`` count as both a block close
    and a block open.
    """
    depth = 0
    result = []
    for line in lines:
        stripped = line.strip()
        is_comment = stripped.startswith('{') and stripped.endswith('}')
        if is_comment or not stripped:
            result.append(line)
            continue

        # Count end keywords (standalone end; or end at start of compound line)
        has_begin = bool(re.search(r'\bbegin\b', stripped)) or stripped == 'repeat'
        has_case = bool(re.search(r'\bcase\b.*\bof\b', stripped))
        is_standalone_end = stripped == 'end;'
        # "end else ..." or "end;" at start of a line with more content
        has_end = is_standalone_end or stripped.startswith('end ')

        if is_standalone_end and not has_begin:
            # Pure end; line
            if depth <= 0:
                indent = line[:len(line) - len(line.lstrip())]
                result.append(f'{indent}{{ {stripped} }}')
                continue
            else:
                depth -= 1
        else:
            # Process end before begin on compound lines like "end else begin"
            if has_end:
                depth -= 1
                if depth < 0:
                    depth = 0
            if has_begin or has_case:
                depth += 1

        result.append(line)
    return result


# Regex to strip C-style comments (/* ... */) from a line
_C_COMMENT_RE = re.compile(r'/\*.*?\*/')


def convert_c_line(line, func_info):
    """Convert a single C statement line to Pascal."""
    if not line:
        return ''

    indent = '  '

    # Strip C-style comments before pattern matching.
    # Ghidra description comments (/* ... */) and string annotations
    # prevent regex patterns with $ anchors from matching.
    original_line = line
    line = _C_COMMENT_RE.sub('', line).strip()

    # Return statement with value (function result) — must be before var_decl
    ret_match = re.match(r'^return\s+(.+?)\s*;$', line)
    if ret_match:
        value = convert_expression(ret_match.group(1))
        if func_info.get('is_function'):
            return f'{indent}{func_info["pascal_name"]} := {value};'
        return None

    # Return void
    if line == 'return;':
        return None

    # Variable declarations (local vars)
    var_decl = re.match(r'^(\w+)\s+(\w+)\s*;$', line)
    if var_decl:
        ctype = var_decl.group(1)
        vname = var_decl.group(2)
        if vname.startswith('unaff_') or vname.startswith('extraout_'):
            return None
        ptype = c_type_to_pascal(ctype)
        if ptype:
            return f'{indent}{{ var {vname}: {ptype}; }}'
        return None

    # C array variable declarations: type name [size];
    arr_decl = re.match(r'^(\w+)\s+(\w+)\s*\[(\d+)\]\s*;$', line)
    if arr_decl:
        ctype = arr_decl.group(1)
        vname = arr_decl.group(2)
        size = int(arr_decl.group(3))
        ptype = c_type_to_pascal(ctype) or 'Byte'
        return f'{indent}{{ var {vname}: array[0..{size - 1}] of {ptype}; }}'

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

    # if statement
    if_match = re.match(r'^if\s*\((.+?)\)\s*\{?\s*$', line)
    if if_match:
        cond = convert_condition(if_match.group(1))
        return f'{indent}if {cond} then begin'

    # Single-line if + break
    if_break = re.match(r'^if\s*\((.+?)\)\s*break\s*;', line)
    if if_break:
        cond = convert_condition(if_break.group(1))
        return f'{indent}if {cond} then Break;'

    # else if
    elif_match = re.match(r'^(?:}\s*)?else\s+if\s*\((.+?)\)\s*\{?\s*$', line)
    if elif_match:
        cond = convert_condition(elif_match.group(1))
        return f'{indent}end else if {cond} then begin'

    # else
    if re.match(r'^(?:}\s*)?else\s*\{?\s*$', line):
        return f'{indent}end else begin'

    # while loop with comma operator
    while_comma = re.match(r'^while\s*\((.+),\s*(.+?)\)\s*\{?\s*$', line)
    if while_comma:
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
        neg_cond = negate_condition(cond)
        return f'{indent}until {neg_cond};'

    # for loop — try to convert to Pascal for/while
    # Use greedy .+ to handle nested parens in for(...) content like (uint)
    for_match = re.match(r'^for\s*\((.+)\)\s*\{?\s*$', line)
    if for_match:
        return _convert_for_loop(for_match.group(1), indent)

    # break
    if line == 'break;':
        return f'{indent}Break;'

    # continue
    if line == 'continue;':
        return f'{indent}Continue;'

    # Assignment with memory access (global address or field offset)
    # Matches: *(type *)0xNN = value;  AND  *(type *)(var + offset) = value;
    _MEM_LHS = (r'(\*\((?:int|uint|word|byte|char) \*\)'
                r'(?:0x[0-9a-f]+|\(\w+ \+ -?(?:0x[0-9a-f]+|\d+)\)))')
    assign_match = re.match(_MEM_LHS + r'\s*=\s*(.+?)\s*;$', line)
    if assign_match:
        lhs = convert_expression(assign_match.group(1))
        rhs = convert_expression(assign_match.group(2))
        return f'{indent}{lhs} := {rhs};'

    # Assignment to pointer param
    ptr_assign = re.match(r'^\*(\w+)\s*=\s*(.+?)\s*;$', line)
    if ptr_assign:
        lhs = ptr_assign.group(1)
        rhs = convert_expression(ptr_assign.group(2))
        return f'{indent}{lhs} := {rhs};'

    # Simple assignment
    simple_assign = re.match(r'^(\w+)\s*=\s*(.+?)\s*;$', line)
    if simple_assign:
        lhs = simple_assign.group(1)
        rhs = convert_expression(simple_assign.group(2))
        if lhs.startswith('uVar') or lhs.startswith('DAT_'):
            return None
        return f'{indent}{lhs} := {rhs};'

    # Compound assignment (global address or field offset)
    compound_match = re.match(
        _MEM_LHS + r'\s*([\+\-\*])=\s*(.+?)\s*;$', line)
    if compound_match:
        lhs = convert_expression(compound_match.group(1))
        op = compound_match.group(2)
        rhs = convert_expression(compound_match.group(3))
        return f'{indent}{lhs} := {lhs} {op} {rhs};'

    # Function call (without assignment)
    call_match = re.match(r'^(\w+)\s*\(.*\)\s*;$', line)
    if call_match:
        fname = call_match.group(1)
        # Known system/noise calls to skip
        skip_names = {
            'bp_stack_check', 'bp_iocheck', 'bp_halt_handler',
            'bp_write_char_flush', 'bp_flush_text_cond',
            'bp_module_init', 'bp_clear_dseg', 'bp_runtime_init',
            'bp_input_init', 'bp_output_init', 'bp_printstring',
            '___SystemInit_qv',
            'bp_str_temp_free', 'bp_unit_init',
            'bp___stackcheck', 'bp___systeminit',
            'bp_textrec_init', 'bp_text_open_check',
        }
        if fname in skip_names:
            return None
        if fname == 'bp_halt':
            return f'{indent}Halt;'
        # Setter-style calls: crt_textattr_set(value) → TextAttr := value
        _SETTER_MAP = {'crt_textattr_set': 'TextAttr'}
        if fname in _SETTER_MAP:
            var_name = _SETTER_MAP[fname]
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                val = convert_expression(args_match.group(1))
                return f'{indent}{var_name} := {val};'
            return None
        # String assignment from constant: look up source string in DB
        if fname in ('bp_str_assign_const', 'bp_str_copy_const'):
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                parts = [a.strip() for a in args_match.group(1).split(',')]
                if len(parts) >= 5:
                    dest_off = parts[1]
                    dest_seg = parts[2]
                    src_off = parts[3]
                    sdb = func_info.get('strings_db', {})
                    if dest_seg == 'unaff_DS' and dest_off.startswith('0x'):
                        # Look up source string in strings DB
                        string_val = None
                        try:
                            src_int = int(src_off, 16) if src_off.startswith('0x') else int(src_off)
                            string_val = sdb.get(src_int)
                        except ValueError:
                            pass
                        if string_val:
                            var_name = f'g_{dest_off[2:].zfill(4).upper()}'
                            escaped = string_val.replace("'", "''")
                            return f"{indent}{{ {var_name} := '{escaped}'; }}"
            return f'{indent}{{ {line} }}'
        # Library label → Pascal builtin
        if fname in _LABEL_TO_PASCAL:
            pascal_name = _LABEL_TO_PASCAL[fname]
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                args = convert_expression(args_match.group(1))
                return f'{indent}{pascal_name}({args});'
            return f'{indent}{pascal_name};'
        # Skip FLIRT-identified system init/IO functions
        if re.match(r'^_(?:Halt|WriteLn|Write|ReadLn|Read|RunError)_q', fname):
            return f'{indent}{{ {line} }}'
        # Write implementation internals — keep as comment to preserve context
        # (args passed via DAT_ globals, unresolvable by body_converter)
        if fname in ('bp_write_str_body', 'bp_writeln_impl',
                     'bp_write_bool', 'bp_write_real',
                     'bp_write_setup', 'bp_write_char_buf'):
            return f'{indent}{{ {fname}(); }}'
        if fname.startswith('FUN_'):
            # Write char function (FUN_xxxx_067b)
            if re.match(r'FUN_\w+_067b$', fname):
                args_match = re.search(r'\(\s*\d+\s*,\s*(\d+|0x[0-9a-f]+)', line)
                if args_match:
                    char_str = args_match.group(1)
                    char_val = int(char_str, 16) if char_str.startswith('0x') else int(char_str)
                    if 0x20 <= char_val <= 0x7e:
                        return f"{indent}Write('{chr(char_val)}');"
                    return f'{indent}Write(Chr({char_val}));'
                return f"{indent}Write(' ');"
            # Write Real function (FUN_xxxx_078a)
            if re.match(r'FUN_\w+_078a$', fname):
                return f'{indent}Write(0.0);'
            pascal_fname = 'Proc_' + fname[4:]
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                args = args_match.group(1)
                # Strip segment constants from far call arguments.
                # FUN_SSSS_xxxx calls pass seg:off pairs; the segment 0xSSSS
                # is meaningless in Pascal and causes param count mismatches.
                seg_match = re.match(r'FUN_([0-9a-f]+)_', fname)
                if seg_match:
                    seg_hex = '0x' + seg_match.group(1)
                    args = re.sub(r',\s*' + re.escape(seg_hex) + r'\b', '', args)
                    args = re.sub(r'\b' + re.escape(seg_hex) + r'\s*,\s*', '', args)
                args = convert_expression(args)
                return f'{indent}{pascal_fname}({args});'
            return f'{indent}{pascal_fname};'
        return f'{indent}{{ {line} }}'

    # Increment
    inc_match = re.match(r'^(\w+)\s*=\s*\1\s*\+\s*1\s*;$', line)
    if inc_match:
        var = inc_match.group(1)
        return f'{indent}Inc({var});'

    # Decrement
    dec_match = re.match(r'^(\w+)\s*=\s*\1\s*-\s*1\s*;$', line)
    if dec_match:
        var = dec_match.group(1)
        return f'{indent}Dec({var});'

    # Fall through: emit as comment
    if line.strip():
        return f'{indent}{{ {line} }}'

    return ''
