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
