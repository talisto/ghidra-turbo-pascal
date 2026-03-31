"""C-to-Pascal type mapping and signature generation."""


C_TO_PASCAL_TYPE = {
    'void': '',
    'int': 'Integer',
    'int16': 'Integer',
    'int32': 'LongInt',
    'uint': 'Word',
    'uint16': 'Word',
    'uint32': 'LongInt',
    'word': 'Word',
    'byte': 'Byte',
    'char': 'Byte',
    'long': 'LongInt',
    'ulong': 'LongInt',
    'dword': 'LongInt',
    'bool': 'Boolean',
    'short': 'Integer',
    'ushort': 'Word',
}


def c_type_to_pascal(ctype):
    """Convert a C type name to Pascal type name."""
    # Strip const, unsigned, etc.
    ctype = ctype.replace('unsigned ', '').replace('const ', '').strip()
    # Handle array types: byte32 → array[0..31] of Byte, etc.
    import re
    m = re.match(r'^(\w+?)(\d+)$', ctype)
    if m and m.group(1) in C_TO_PASCAL_TYPE and m.group(1) not in ('int16', 'int32', 'uint16', 'uint32'):
        base = C_TO_PASCAL_TYPE[m.group(1)]
        size = int(m.group(2))
        if base:
            return f'array[0..{size - 1}] of {base}'
    return C_TO_PASCAL_TYPE.get(ctype, ctype)


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
        # Inline array types can't be used in Pascal parameter lists
        if ptype_pascal.startswith('array'):
            ptype_pascal = 'Pointer'
        if is_ptr:
            pascal_params.append(f'var {pname}: {ptype_pascal}')
        else:
            pascal_params.append(f'{pname}: {ptype_pascal}')

    param_str = '; '.join(pascal_params)

    is_function = ret_type not in ('void', '')
    if is_function:
        ret_pascal = c_type_to_pascal(ret_type)
        pascal_name_func = pascal_name.replace('Proc_', 'Func_')
        if param_str:
            return ('function', f'function {pascal_name_func}({param_str}): {ret_pascal};',
                    pascal_name_func, True)
        return ('function', f'function {pascal_name_func}: {ret_pascal};',
                pascal_name_func, True)
    else:
        if param_str:
            return ('procedure', f'procedure {pascal_name}({param_str});',
                    pascal_name, False)
        return ('procedure', f'procedure {pascal_name};',
                pascal_name, False)
