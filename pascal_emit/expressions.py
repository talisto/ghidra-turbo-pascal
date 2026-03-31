"""Expression and condition conversion from C to Pascal."""
import re

from .types import c_type_to_pascal

# C types that appear in pointer casts: *(TYPE *)addr, (TYPE *)var
_C_PTR_TYPES = r'(?:int|uint|word|byte|char|dword|short|ushort|long|ulong)'


def convert_expression(expr):
    """Convert a C expression to Pascal expression."""
    expr = expr.strip()

    # Char literals: '\0' → 0, '\x01' → 1, 'A' → Ord('A'), etc.
    expr = re.sub(r"'\\0'", '0', expr)
    expr = re.sub(r"'\\x([0-9a-f]{2})'", lambda m: str(int(m.group(1), 16)), expr)

    # Memory access: *(int *)0xNN → g_00NN
    expr = re.sub(
        r'\*\(' + _C_PTR_TYPES + r' \*\)(0x[0-9a-f]+)',
        lambda m: f'g_{m.group(1)[2:].zfill(4).upper()}',
        expr
    )
    # Array via pointer arithmetic: *(type *)(var * ELEM_SIZE + BASE_ADDR)
    # → g_BASE[var]  (typed array access on a global array)
    def _ptr_arith_array(m):
        var = m.group(1)
        base_hex = m.group(2)
        base = int(base_hex, 0)
        return f'g_{base:04X}[{var}]'
    expr = re.sub(
        r'\*\(' + _C_PTR_TYPES + r' \*\)\((\w+) \* 2 \+ (0x[0-9a-f]+|\d+)\)',
        _ptr_arith_array, expr
    )
    # *(int *)(param_N + offset) → param_N[offset]  (indexed access)
    # Offset may be hex (0xNN) or decimal
    expr = re.sub(
        r'\*\(' + _C_PTR_TYPES + r' \*\)\((\w+) \+ (0x[0-9a-f]+|\d+)\)',
        lambda m: f'{m.group(1)}[{int(m.group(2), 0)}]',
        expr
    )
    # *(int *)(param_N + -offset) → param_N[-offset]  (negative indexed access)
    expr = re.sub(
        r'\*\(' + _C_PTR_TYPES + r' \*\)\((\w+) \+ (-(?:0x[0-9a-f]+|\d+))\)',
        lambda m: f'{m.group(1)}[{int(m.group(2), 0)}]',
        expr
    )
    # (type *)variable → variable  (pointer cast — drop for var params)
    expr = re.sub(r'\(' + _C_PTR_TYPES + r' \*\)(\w+)', r'\1', expr)
    # (type)*(type *)variable → Type(variable)  (cast + deref + pointer cast)
    # Must be before the general deref pattern since ) before * blocks it
    _CAST_DEREF_MAP = {
        'int': 'Integer', 'uint': 'Word', 'ushort': 'Word',
        'byte': 'Byte', 'char': 'Char', 'word': 'Word',
        'dword': 'LongInt', 'ulong': 'LongInt', 'short': 'Integer',
        'long': 'LongInt',
    }
    def _cast_deref(m):
        ctype = m.group(1)
        var = m.group(2)
        pascal_type = _CAST_DEREF_MAP.get(ctype, 'Integer')
        return f'{pascal_type}({var})'
    expr = re.sub(r'\((\w+)\)\*(\w+)', _cast_deref, expr)
    # *variable → variable  (pointer deref on var params — var already dereferences)
    # Only match when * is not preceded by identifier/digit/close-paren (not multiplication)
    expr = re.sub(r'(?<![a-zA-Z0-9_)\]])\*(\w+)', r'\1', expr)

    # C-style casts → Pascal type casts: (type)expr → Type(expr)
    # Handle casts followed by a parenthesized expression: (ulong)(expr)
    expr = re.sub(r'\(ulong\)\(', 'LongInt(', expr)
    expr = re.sub(r'\(uint\)\(', 'Word(', expr)
    expr = re.sub(r'\(ushort\)\(', 'Word(', expr)
    expr = re.sub(r'\(int\)\(', 'Integer(', expr)
    expr = re.sub(r'\(byte\)\(', 'Byte(', expr)
    expr = re.sub(r'\(char\)\(', 'Char(', expr)
    expr = re.sub(r'\(word\)\(', 'Word(', expr)
    expr = re.sub(r'\(dword\)\(', 'LongInt(', expr)
    # Handle casts followed by a single identifier: (ulong)varName → LongInt(varName)
    expr = re.sub(r'\(ulong\)(\w+)', r'LongInt(\1)', expr)
    expr = re.sub(r'\(uint\)(\w+)', r'Word(\1)', expr)
    expr = re.sub(r'\(ushort\)(\w+)', r'Word(\1)', expr)
    expr = re.sub(r'\(int\)(\w+)', r'Integer(\1)', expr)
    expr = re.sub(r'\(byte\)(\w+)', r'Byte(\1)', expr)
    expr = re.sub(r'\(char\)(\w+)', r'Char(\1)', expr)
    expr = re.sub(r'\(word\)(\w+)', r'Word(\1)', expr)
    expr = re.sub(r'\(dword\)(\w+)', r'LongInt(\1)', expr)
    # Remove redundant chains like Word(Word(x)) → Word(x)
    expr = re.sub(r'(Word|Integer|Byte|Char|LongInt)\(\1\(', r'\1(', expr)

    # CONCAT patterns → extract meaningful value
    expr = re.sub(r'CONCAT11\s*\(\s*extraout_AH\s*,\s*([^)]+)\)', r'\1', expr)
    expr = re.sub(r'CONCAT22\s*\(\s*[^,]+\s*,\s*([^)]+)\)', r'\1', expr)

    # Address arguments: 0xNN followed by unaff_DS means data segment address
    # Convert to global variable reference before stripping unaff_*
    expr = re.sub(
        r'(0x[0-9a-f]+)\s*,\s*unaff_DS\b',
        lambda m: f'g_{m.group(1)[2:].zfill(4).upper()}',
        expr
    )

    # Strip unaff_* arguments from call argument lists
    expr = re.sub(r',\s*unaff_\w+', '', expr)
    expr = re.sub(r'unaff_\w+\s*,\s*', '', expr)

    # Strip Ghidra sub-field accessors: var._1_1_ → Byte(var)
    expr = re.sub(r'(\w+)\._\d+_\d+_', r'Byte(\1)', expr)

    # Strip &stack references: &stack0xNNNN → 0 { stack ref }
    expr = re.sub(r'and\s+stack0x[0-9a-f]+', '0 { stack ref }', expr)
    expr = re.sub(r'&stack0x[0-9a-f]+', '0 { stack ref }', expr)

    # Library label function calls → Pascal builtins (in expressions)
    _EXPR_LABEL_MAP = {
        'bp_random': 'Random', 'bp_randomize': 'Randomize',
        'bp_chr': 'Chr', 'bp_ord': 'Ord', 'bp_length': 'Length',
        'bp_copy': 'Copy', 'bp_pos': 'Pos', 'bp_concat': 'Concat',
        'bp_upcase': 'UpCase', 'bp_hi': 'Hi', 'bp_lo': 'Lo',
        'bp_swap': 'Swap', 'bp_sizeof': 'SizeOf',
        'bp_paramcount': 'ParamCount', 'bp_paramstr': 'ParamStr',
        'bp_keypressed': 'KeyPressed', 'bp_readkey': 'ReadKey',
        'bp_filepos': 'FilePos', 'bp_filesize': 'FileSize',
        'bp_eof': 'Eof', 'bp_eoln': 'Eoln',
        'bp_ioresult': 'IOResult',
        'crt_wherex_impl': 'WhereX', 'crt_wherey_impl': 'WhereY',
        'crt_gotoxy_impl': 'GotoXY',
    }
    for old, new in _EXPR_LABEL_MAP.items():
        expr = re.sub(r'\b' + re.escape(old) + r'\b', new, expr)

    # Parameterless functions: strip any spurious Ghidra arguments
    _NOARG_FUNCS = ('WhereX', 'WhereY', 'ReadKey', 'KeyPressed',
                    'ParamCount', 'Randomize')
    for fn in _NOARG_FUNCS:
        expr = re.sub(r'\b' + fn + r'\s*\([^)]*\)', fn, expr)

    # Shift operators → shl/shr
    expr = re.sub(r'(\w+)\s*<<\s*(\d+)', r'\1 shl \2', expr)
    expr = re.sub(r'(\w+)\s*>>\s*(\d+)', r'\1 shr \2', expr)

    # Sign extension pattern: value >> 0xf → remove entirely (16-bit sign ext)
    expr = re.sub(r',\s*\w+ shr 15', '', expr)

    # Hex constants → decimal (for readability, skip address-like values)
    expr = re.sub(
        r'\b0x([0-9a-f]+)\b',
        lambda m: str(int(m.group(1), 16)),
        expr
    )

    # C operators → Pascal (order matters: multi-char before single-char)
    expr = expr.replace('!=', ' <> ')
    expr = expr.replace('==', ' = ')
    expr = expr.replace('&&', ' and ')
    expr = expr.replace('||', ' or ')
    # Modulo and integer division
    expr = re.sub(r'\s*%\s*', ' mod ', expr)
    expr = re.sub(r'\s*/\s*', ' div ', expr)
    # Bitwise operators (use word boundaries to avoid matching inside identifiers)
    expr = re.sub(r'(?<!\w)~(\w)', r'not \1', expr)
    expr = re.sub(r'\s*&\s*', ' and ', expr)
    expr = re.sub(r'\s*\|\s*', ' or ', expr)
    expr = re.sub(r'\s*\^\s*', ' xor ', expr)
    # ! for logical not (careful not to match !=)
    expr = re.sub(r'!(\w)', r'not \1', expr)
    # Assignment
    expr = expr.replace(' = ', ' := ', 1) if ' = ' in expr and ':=' not in expr else expr

    # Clean up whitespace
    expr = re.sub(r'\s+', ' ', expr).strip()

    # Fix doubled operators from stripping (e.g., "and and" → "and")
    expr = re.sub(r'\band\s+and\b', 'and', expr)
    expr = re.sub(r'\bor\s+or\b', 'or', expr)

    return expr


def _split_at_depth0(text, op):
    """Split text on operator at parenthesis depth 0."""
    parts = []
    depth = 0
    current = []
    i = 0
    while i < len(text):
        if text[i] == '(':
            depth += 1
            current.append('(')
        elif text[i] == ')':
            depth -= 1
            current.append(')')
        elif depth == 0 and text[i:i+len(op)] == op:
            parts.append(''.join(current).strip())
            current = []
            i += len(op)
            continue
        else:
            current.append(text[i])
        i += 1
    parts.append(''.join(current).strip())
    return parts


def _strip_outer_parens(text):
    """Strip outermost matched parentheses if they wrap the entire expression."""
    text = text.strip()
    if not (text.startswith('(') and text.endswith(')')):
        return text
    depth = 0
    for i, c in enumerate(text):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        if depth == 0 and i < len(text) - 1:
            return text  # Opening paren matches before end
    return text[1:-1].strip()


def _wrap_parens(cond):
    """Wrap in parens if not already fully parenthesized."""
    stripped = cond.strip()
    if stripped.startswith('(') and stripped.endswith(')'):
        depth = 0
        for i, c in enumerate(stripped):
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            if depth == 0 and i < len(stripped) - 1:
                break
        else:
            return stripped  # Already fully parenthesized
    return f'({stripped})'


def convert_condition(cond):
    """Convert a C condition expression to Pascal.

    Handles operator precedence: C's && and || bind loosely (below
    comparisons), but Pascal's ``and``/``or`` bind tightly (above
    comparisons).  Sub-expressions joined by ``and``/``or`` that contain
    comparison operators are wrapped in parentheses.
    """
    cond = cond.strip()

    # Strip outermost matched parens repeatedly (handles ((expr)))
    while True:
        stripped = _strip_outer_parens(cond)
        if stripped == cond:
            break
        cond = stripped

    # Split on || (lower precedence) at depth 0
    or_parts = _split_at_depth0(cond, '||')
    if len(or_parts) > 1:
        converted = [_wrap_parens(convert_condition(p)) for p in or_parts]
        return ' or '.join(converted)

    # Split on && at depth 0
    and_parts = _split_at_depth0(cond, '&&')
    if len(and_parts) > 1:
        converted = [_wrap_parens(convert_condition(p)) for p in and_parts]
        return ' and '.join(converted)

    # Atomic condition — apply conversions
    return _convert_atomic_condition(cond)


def _convert_atomic_condition(cond):
    """Convert a single C condition (no &&/||) to Pascal.

    Splits on comparison operators at depth 0 and delegates each
    operand to convert_expression, avoiding duplicated conversion logic.
    """
    cond = cond.strip()

    # Try comparison operators at depth 0 (longest first)
    for c_op, pas_op in [('!=', ' <> '), ('==', ' = '),
                          ('<=', ' <= '), ('>=', ' >= '),
                          ('<', ' < '), ('>', ' > ')]:
        parts = _split_at_depth0(cond, c_op)
        if len(parts) == 2:
            lhs = convert_expression(parts[0])
            rhs = convert_expression(parts[1])
            return f'{lhs}{pas_op}{rhs}'

    # No comparison operator — bare boolean expression
    return convert_expression(cond)


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
