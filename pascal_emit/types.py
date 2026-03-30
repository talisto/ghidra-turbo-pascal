"""C-to-Pascal type mapping and signature generation."""


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
