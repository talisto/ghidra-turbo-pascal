"""Main pipeline: orchestrate parsing, conversion, and emission."""
import os
import re
from collections import OrderedDict

from .strings import load_strings, ExeStringReader, find_exe_for_decompiled
from .parser import parse_functions, classify_function, find_primary_segment, parse_c_signature
from .types import make_pascal_signature
from .body_converter import convert_function_body
from .globals_scanner import detect_globals, detect_uses
from .emitter import emit_pascal


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
