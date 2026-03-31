"""Expression and condition conversion from C to Pascal."""
import re

from .types import c_type_to_pascal


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
    # *(int *)(param_N + offset) → param_N[offset]  (indexed access)
    expr = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)\((\w+) \+ (\d+)\)',
        lambda m: f'{m.group(1)}[{m.group(2)}]',
        expr
    )
    # *(int *)(param_N + -offset) → param_N[-offset]  (negative indexed access)
    expr = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)\((\w+) \+ (-\d+)\)',
        lambda m: f'{m.group(1)}[{m.group(2)}]',
        expr
    )
    # (type *)variable → variable  (pointer cast — drop for var params)
    expr = re.sub(r'\((?:int|uint|word|byte|char) \*\)(\w+)', r'\1', expr)
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
    }
    for old, new in _EXPR_LABEL_MAP.items():
        expr = re.sub(r'\b' + re.escape(old) + r'\b', new, expr)

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

    # Strip outermost matched parens for cleaner processing
    cond = _strip_outer_parens(cond)

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
    """Convert a single C condition (no &&/||) to Pascal."""
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
    # Pointer casts and dereferences (same as convert_expression)
    cond = re.sub(
        r'\*\((?:int|uint|word|byte|char) \*\)\((\w+) \+ (-?\d+)\)',
        lambda m: f'{m.group(1)}[{m.group(2)}]',
        cond
    )
    cond = re.sub(r'\((?:int|uint|word|byte|char) \*\)(\w+)', r'\1', cond)
    cond = re.sub(r'(?<![a-zA-Z0-9_)\]])\*(\w+)', r'\1', cond)

    # C-style casts → Pascal type casts
    cond = re.sub(r'\(ulong\)\(', 'LongInt(', cond)
    cond = re.sub(r'\(uint\)\(', 'Word(', cond)
    cond = re.sub(r'\(ushort\)\(', 'Word(', cond)
    cond = re.sub(r'\(int\)\(', 'Integer(', cond)
    cond = re.sub(r'\(byte\)\(', 'Byte(', cond)
    cond = re.sub(r'\(char\)\(', 'Char(', cond)
    cond = re.sub(r'\(word\)\(', 'Word(', cond)
    cond = re.sub(r'\(dword\)\(', 'LongInt(', cond)
    cond = re.sub(r'\(ulong\)(\w+)', r'LongInt(\1)', cond)
    cond = re.sub(r'\(uint\)(\w+)', r'Word(\1)', cond)
    cond = re.sub(r'\(ushort\)(\w+)', r'Word(\1)', cond)
    cond = re.sub(r'\(int\)(\w+)', r'Integer(\1)', cond)
    cond = re.sub(r'\(byte\)(\w+)', r'Byte(\1)', cond)
    cond = re.sub(r'\(char\)(\w+)', r'Char(\1)', cond)
    cond = re.sub(r'\(word\)(\w+)', r'Word(\1)', cond)
    cond = re.sub(r'\(dword\)(\w+)', r'LongInt(\1)', cond)

    # Hex constants → decimal
    cond = re.sub(
        r'\b0x([0-9a-f]+)\b',
        lambda m: str(int(m.group(1), 16)),
        cond
    )

    # Operators (order matters: multi-char before single-char)
    cond = cond.replace('!=', ' <> ')
    cond = cond.replace('==', ' = ')
    cond = re.sub(r'\s*%\s*', ' mod ', cond)
    cond = re.sub(r'\s*/\s*', ' div ', cond)
    cond = re.sub(r'(?<!\w)~(\w)', r'not \1', cond)
    cond = re.sub(r'\s*&\s*', ' and ', cond)
    cond = re.sub(r'\s*\|\s*', ' or ', cond)
    cond = re.sub(r'\s*\^\s*', ' xor ', cond)
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
