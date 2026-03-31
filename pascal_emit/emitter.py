"""Emit a complete Pascal source file."""
from .types import c_type_to_pascal


def emit_pascal(program_name, uses, globals_map, app_functions, main_body,
                main_temps=None):
    """Generate a complete .pas file."""
    lines = []

    # Program header
    lines.append(f'program {program_name};')
    lines.append('')

    # Uses clause
    if uses:
        lines.append(f'uses {", ".join(uses)};')
        lines.append('')

    # Global variables (memory-mapped + main block temps)
    has_globals = bool(globals_map) or bool(main_temps)
    if has_globals:
        lines.append('var')
        for offset, ctype in globals_map.items():
            vname = f'g_{offset[2:].zfill(4).upper()}'
            ptype = c_type_to_pascal(ctype)
            lines.append(f'  {vname}: {ptype};')
        if main_temps:
            for vname, vtype in main_temps:
                lines.append(f'  {vname}: {vtype};')
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
