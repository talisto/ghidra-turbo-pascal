"""Convert C function bodies to Pascal statements."""
import re

from .expressions import convert_expression, convert_condition, negate_condition
from .types import c_type_to_pascal
from .write_sequences import detect_write_sequences


# Lines to strip entirely (noise)
NOISE_PATTERNS = [
    re.compile(r'^\s*(?:bp_stack_check|FUN_\w+_02cd)\s*\('),
    re.compile(r'^\s*(?:bp_iocheck|FUN_\w+_0291)\s*\('),
    re.compile(r'^\s*return\s*;\s*$'),
    re.compile(r'^\s*\w+ unaff_\w+\s*;'),
    re.compile(r'^\s*\w+ extraout_\w+\s*;'),
    re.compile(r'^\s*\w+ uVar\d+\s*;'),
    re.compile(r'^\s*uVar\d+\s*=\s*'),
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
]


def is_noise_line(line):
    """Check if a line should be stripped as noise."""
    stripped = line.strip()
    if not stripped:
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
            break

        if is_noise_line(line):
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
        return None

    # Return void
    if line == 'return;':
        return None

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

    # Compound assignment
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
        # Known system/noise calls to skip
        skip_names = {
            'bp_stack_check', 'bp_iocheck', 'bp_halt_handler',
            'bp_write_char_flush', 'bp_flush_text_cond',
            'bp_module_init', 'bp_clear_dseg', 'bp_runtime_init',
            'bp_input_init', 'bp_output_init', 'bp_printstring',
            '___SystemInit_qv',
        }
        if fname in skip_names:
            return None
        # Skip FLIRT-identified system init/IO functions
        if re.match(r'^_(?:Halt|WriteLn|Write|ReadLn|Read|RunError)_q', fname):
            return f'{indent}{{ {line} }}'
        if fname.startswith('FUN_'):
            pascal_fname = 'Proc_' + fname[4:]
            args_match = re.search(r'\((.+)\)', line)
            if args_match:
                args = args_match.group(1)
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
