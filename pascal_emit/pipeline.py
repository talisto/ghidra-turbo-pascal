"""Main pipeline: orchestrate parsing, conversion, and emission.

Reads functions.json (structured IR from Decompile.java Phase 7) as the
primary data source.  Falls back to parsing decompiled.c only when
functions.json is unavailable.
"""
import os
import re
from collections import OrderedDict

from .strings import load_strings, ExeStringReader, find_exe_for_decompiled
from .types import c_type_to_pascal, make_pascal_signature
from .body_converter import convert_function_body
from .emitter import emit_pascal
from .ir_reader import load_functions_json, find_functions_json


# ─── cCode post-processing (replaces Decompile.java Phase 5 transforms) ───

# Ghidra sanitizes identifiers for C: @→_, $→_
_GHIDRA_IDENT_SANITIZE = str.maketrans({'@': '_', '$': '_'})

# Library function prefixes (matching Decompile.java/parser.py)
_LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')

_FLIRT_RE = [
    re.compile(r'^@\w+\$'),
    re.compile(r'^__[A-Z]'),
]

# Regex used by the old globals_scanner
_GLOBAL_MEM_RE = re.compile(r'\*\((int|uint|word|byte|char) \*\)(0x[0-9a-f]+)')


def _sanitize_ghidra_name(name):
    """Convert Ghidra's internal name to the C identifier form."""
    return name.translate(_GHIDRA_IDENT_SANITIZE)


def _build_rename_table(ir_functions):
    """Build a rename table from functions.json labels.

    Returns dict mapping sanitized-C-name → label for all functions
    that have a label assigned.
    """
    renames = {}
    for fn in ir_functions:
        label = fn.get('label', '')
        if not label:
            continue
        name = fn['name']
        # Map the sanitized C identifier form to the label
        c_name = _sanitize_ghidra_name(name)
        if c_name != label:
            renames[c_name] = label
        # Also map the original form (in case it appears)
        if name != label and name != c_name:
            renames[name] = label
    return renames


def _apply_renames(text, renames):
    """Apply function name renames to a block of C code.

    Applies longest names first to avoid partial matches
    (e.g., _Write_qm4Text matching inside _Write_qm4Textm6String4Word).
    Uses word-boundary-aware replacement.
    """
    for old in sorted(renames.keys(), key=len, reverse=True):
        new = renames[old]
        # Use word boundary to avoid partial matches
        text = re.sub(r'(?<!\w)' + re.escape(old) + r'(?!\w)', new, text)
    return text


def _postprocess_ccode(ccode, renames, strings_db):
    """Apply Phase-5-style post-processing to raw cCode from functions.json.

    This replicates the transforms that Decompile.java Phase 5 applies:
    1. Function renames (label-based)
    2. Ghidra type cleanup (undefined → standard types)
    3. Calling convention removal
    4. CONCAT11 cleanup
    5. String annotations
    """
    if not ccode:
        return ccode

    # 1. Apply renames
    text = _apply_renames(ccode, renames)

    # 2. Type cleanup
    text = re.sub(r'\bundefined1\b', 'byte', text)
    text = re.sub(r'\bundefined2\b', 'word', text)
    text = re.sub(r'\bundefined4\b', 'dword', text)
    text = re.sub(r'\bundefined8\b', 'qword', text)

    # 3. Calling convention removal
    text = text.replace('__cdecl16near ', '')
    text = text.replace('__cdecl16far ', '')
    text = text.replace('__stdcall16far ', '')

    # 4. CONCAT11 cleanup: CONCAT11(extraout_AH, value) → value
    text = re.sub(r'CONCAT11\s*\(\s*extraout_AH\s*,\s*([^)]+)\)', r'\1', text)

    # 5. String annotations — add /* "..." */ comments for known offsets
    if strings_db:
        def _annotate_value(m):
            """Add string annotation to hex constants that match string DB."""
            hex_str = m.group(0)
            try:
                val = int(hex_str, 16)
            except ValueError:
                return hex_str
            s = strings_db.get(val)
            if s:
                return f'{hex_str}  /* "{s}" */'
            return hex_str
        # Annotate hex constants in assignment values
        text = re.sub(r'(?<==\s)0x[0-9a-f]+(?=\s*;)', _annotate_value, text)

    return text


def _is_library_function(fn):
    """Check if a function is a library function."""
    if fn.get('isLibrary', False):
        return True
    label = fn.get('label', '')
    name = fn.get('name', '')
    if any(label.startswith(p) for p in _LIBRARY_PREFIXES):
        return True
    if any(name.startswith(p) for p in _LIBRARY_PREFIXES):
        return True
    for pat in _FLIRT_RE:
        if pat.match(name):
            return True
    return False


def _classify_ir_function(fn, primary_seg):
    """Classify a function from IR data."""
    if fn['name'] == 'entry':
        return 'entry'
    if _is_library_function(fn):
        return 'library'
    # Non-primary segment → system
    seg = fn.get('address', '0000:0000').split(':')[0]
    if seg != primary_seg:
        return 'system'
    return 'application'


def _find_primary_segment(ir_functions):
    """Find the primary application segment from IR function data."""
    for fn in ir_functions:
        if fn['name'] == 'entry':
            return fn.get('address', '1000:0000').split(':')[0]
    if ir_functions:
        return ir_functions[0].get('address', '1000:0000').split(':')[0]
    return '1000'


def _detect_globals(bodies):
    """Scan function bodies for global memory accesses.

    Returns OrderedDict of hex-offset → type, sorted by offset.
    """
    globals_map = {}
    for body in bodies:
        for m in _GLOBAL_MEM_RE.finditer(body):
            ctype = m.group(1)
            offset = m.group(2)
            if offset not in globals_map or _type_width(ctype) > _type_width(globals_map[offset]):
                globals_map[offset] = ctype

    sorted_globals = OrderedDict()
    for off in sorted(globals_map.keys(), key=lambda x: int(x, 16)):
        sorted_globals[off] = globals_map[off]
    return sorted_globals


def _type_width(ctype):
    return {'char': 1, 'byte': 1, 'word': 2, 'uint': 2, 'int': 2, 'dword': 4}.get(ctype, 2)


def _detect_uses(ir_functions):
    """Detect which Pascal units are needed from function labels and calls."""
    uses = set()
    # Collect all labels from library functions called by app/entry functions
    all_labels = set()
    for fn in ir_functions:
        label = fn.get('label', '')
        if label:
            all_labels.add(label)
        name = fn.get('name', '')
        all_labels.add(name)

    label_text = ' '.join(all_labels)

    if re.search(r'\bcrt_|AssignCrt|crt_gotoxy|crt_textattr|crt_clrscr|crt_readkey', label_text):
        uses.add('Crt')
    if re.search(r'\bdos_intr\b|GetDate|GetTime|FindFirst|DiskSize|SetIntVec|FSplit|GetEnv|Intr', label_text):
        uses.add('Dos')

    return sorted(uses)


def _extract_params(fn):
    """Extract parameter tuples (type, name, is_pointer) from IR function data."""
    params = []
    for p in fn.get('parameters', []):
        ptype = p.get('type', 'int')
        pname = p.get('name', 'param')
        is_ptr = '*' in ptype
        # Clean up type: remove pointer asterisk, map Ghidra types
        clean_type = ptype.replace(' *', '').replace('*', '').strip()
        clean_type = re.sub(r'^undefined\d?$', 'int', clean_type)
        params.append((clean_type, pname, is_ptr))
    return params


def process(decompiled_path, strings_path=None, output_path=None, exe_path=None):
    """Process decompiled output and emit a .pas file.

    Primary data source is functions.json (structured IR from Decompile.java).
    Falls back to parsing decompiled.c when functions.json is unavailable.
    """
    # Determine program name from directory
    dir_name = os.path.basename(os.path.dirname(os.path.abspath(decompiled_path)))
    program_name = dir_name if dir_name and dir_name != '.' else 'Program1'

    # Try to load structured IR (functions.json)
    ir_path = find_functions_json(decompiled_path)
    ir_data = load_functions_json(ir_path) if ir_path else None

    if ir_data:
        return _process_ir(ir_data, decompiled_path, strings_path, output_path,
                           exe_path, program_name)
    else:
        return _process_legacy(decompiled_path, strings_path, output_path,
                               exe_path, program_name)


def _process_ir(ir_data, decompiled_path, strings_path, output_path,
                exe_path, program_name):
    """IR-based pipeline: uses functions.json as primary data source."""

    ir_functions = ir_data.get('functions', [])

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

    # Build rename table from all function labels
    renames = _build_rename_table(ir_functions)

    # Find primary segment and classify
    primary_seg = _find_primary_segment(ir_functions)

    classified = []
    for fn in ir_functions:
        cls = _classify_ir_function(fn, primary_seg)
        classified.append((fn, cls))

    app_funcs = [(fn, cls) for fn, cls in classified if cls == 'application']
    entry_fn = next((fn for fn, cls in classified if cls == 'entry'), None)

    # Detect uses clause from labels
    uses = _detect_uses(ir_functions)

    # Post-process cCode for app functions and entry
    processed_bodies = []
    for fn, cls in classified:
        if cls in ('application', 'entry'):
            ccode = fn.get('cCode', '')
            processed = _postprocess_ccode(ccode, renames, strings_db)
            processed_bodies.append(processed)

    # Detect global variables
    globals_map = _detect_globals(processed_bodies)
    globals_map = OrderedDict(
        (k, v) for k, v in globals_map.items()
        if int(k, 16) >= 0x50
    )

    # Convert application functions
    pascal_funcs = []
    for fn, cls in app_funcs:
        ccode = fn.get('cCode', '')
        body_text = _postprocess_ccode(ccode, renames, strings_db)

        ret_type = fn.get('returnType', 'void')
        # Clean up Ghidra types
        ret_type = re.sub(r'^undefined\d?$', 'int', ret_type)

        params = _extract_params(fn)

        keyword, declaration, pascal_name, is_function = make_pascal_signature(
            ret_type, fn['name'], params)

        func_info = {
            'name': fn['name'],
            'pascal_name': pascal_name,
            'is_function': is_function,
            'ret_type': ret_type,
            'params': params,
            'ir': fn,
        }

        body = convert_function_body(body_text, strings_db, func_info, exe_reader)

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
    if entry_fn:
        ccode = entry_fn.get('cCode', '')
        body_text = _postprocess_ccode(ccode, renames, strings_db)

        func_info = {
            'name': 'entry',
            'pascal_name': program_name,
            'is_function': False,
            'ret_type': 'void',
            'params': [],
            'ir': entry_fn,
        }
        main_body = convert_function_body(body_text, strings_db, func_info, exe_reader)

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


def _process_legacy(decompiled_path, strings_path, output_path,
                    exe_path, program_name):
    """Legacy pipeline: parse decompiled.c text with regex.

    Used only when functions.json is unavailable.
    """
    from .parser import parse_functions, classify_function, find_primary_segment, parse_c_signature
    from .globals_scanner import detect_globals as detect_globals_legacy
    from .globals_scanner import detect_uses as detect_uses_legacy

    with open(decompiled_path, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

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
        if (func['classification'] == 'application' and
                func['segment'] != primary_seg and
                func['name'] != 'entry'):
            func['classification'] = 'system'

    app_funcs = [f for f in functions if f['classification'] == 'application']
    entry_func = next((f for f in functions if f['classification'] == 'entry'), None)

    uses = detect_uses_legacy(functions)

    scan_funcs = app_funcs + ([entry_func] if entry_func else [])
    globals_map = detect_globals_legacy(scan_funcs)
    globals_map = OrderedDict(
        (k, v) for k, v in globals_map.items()
        if int(k, 16) >= 0x50
    )

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
            'ir': None,
        }

        body = convert_function_body(func['body'], strings_db, func_info, exe_reader)

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

    main_body = ''
    if entry_func:
        func_info = {
            'name': 'entry',
            'pascal_name': program_name,
            'is_function': False,
            'ret_type': 'void',
            'params': [],
            'ir': None,
        }
        main_body = convert_function_body(entry_func['body'], strings_db, func_info, exe_reader)

    pascal_text = emit_pascal(program_name, uses, globals_map, pascal_funcs, main_body)

    if not output_path:
        output_path = os.path.join(
            os.path.dirname(decompiled_path),
            program_name + '.pas'
        )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(pascal_text)

    print(f'  {output_path}')
    return output_path
