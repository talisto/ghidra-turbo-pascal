"""Main pipeline: orchestrate parsing, conversion, and emission.

Reads functions.json (structured IR from Decompile.java Phase 7) as the
data source.
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

# Library function prefixes (matching Decompile.java)
_LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')

_FLIRT_RE = [
    re.compile(r'^@\w+\$'),
    re.compile(r'^__[A-Z]'),
]

_GLOBAL_MEM_RE = re.compile(r'\*\((int|uint|word|byte|char|dword|short|ushort|long|ulong) \*\)(0x[0-9a-f]+)')


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


def _replace_undefined_large(m):
    """Replace undefinedN with array type for N > 8."""
    size = int(m.group(1))
    if size <= 8:
        return m.group(0)  # already handled above
    return f'array[0..{size - 1}] of Byte'


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
    # Large undefined types (e.g., undefined132 = 132-byte struct)
    text = re.sub(r'\bundefined(\d+)\b', _replace_undefined_large, text)

    # 3. Calling convention removal
    text = text.replace('__cdecl16near ', '')
    text = text.replace('__cdecl16far ', '')
    text = text.replace('__stdcall16far ', '')

    # 4. CONCAT11 cleanup: CONCAT11(extraout_AH, value) → value
    # Also handle numbered variants: extraout_AH_00, extraout_AH_01, etc.
    text = re.sub(r'CONCAT11\s*\(\s*extraout_AH(?:_\d+)?\s*,\s*([^)]+)\)', r'\1', text)

    # 4b. Clean up extraout_AH artifacts in shift expressions:
    # (uint)extraout_AH_XX << 8 → 0 (high byte from CONCAT11 is always 0)
    text = re.sub(r'\(uint\)\s*extraout_AH(?:_\d+)?\s*<<\s*\d+', '0', text)

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


# Pattern for Ghidra temp variable references: iVar1, uVar5, cVar3, bVar2, etc.
_TEMP_VAR_RE = re.compile(r'\b([iucb]Var\d+)\b')

# Map Ghidra temp variable prefix to Pascal type
_TEMP_VAR_TYPES = {
    'i': 'Integer',
    'u': 'Word',
    'c': 'Byte',
    'b': 'Byte',
}

# Pattern matching unconverted C pointer dereferences in Pascal output
_UNSAFE_C_RE = re.compile(r'\*\s*\(\s*\w+\s*\*')
# C pointer type casts like (int *) or (word *)
_UNSAFE_CAST_RE = re.compile(r'\(\w+\s*\*\s*[)(]')
# Non-array variable indexing: varname[digits] where var is not array type
_NONARRAY_INDEX_RE = re.compile(r'\bparam_\w+\[|\(\w+\)\[\d+\]')


def _comment_out_unsafe_lines(body, array_vars=None, param_names=None):
    """Comment out lines that contain unconverted C constructs.

    Detects:
    - Remaining C pointer dereferences: *(type *)expr
    - C pointer type casts: (type *)
    - Scalar assignments to array-typed variables
    - Indexing on non-array params: param_N[M]
    """
    if array_vars is None:
        array_vars = set()
    if param_names is None:
        param_names = set()
    lines = body.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        # Skip already-commented lines
        if stripped.startswith('{ ') and stripped.endswith(' }'):
            result.append(line)
            continue
        # Strip out { ... } comment sections before checking for unsafe C
        uncommented = re.sub(r'\{[^}]*\}', '', stripped)
        # Check for unconverted C pointer dereferences in uncommented text
        if _UNSAFE_C_RE.search(uncommented) or _UNSAFE_CAST_RE.search(uncommented):
            result.append(line.replace(stripped, '{ ' + stripped + ' }'))
            continue
        # Check for non-array parameter indexing: param_N[M]
        if _NONARRAY_INDEX_RE.search(uncommented):
            result.append(line.replace(stripped, '{ ' + stripped + ' }'))
            continue
        # Check for scalar assignment to array-typed variable
        if array_vars:
            assign_m = re.match(r'(\w+)\s*:=\s*.+;$', stripped)
            if assign_m and assign_m.group(1) in array_vars:
                # Only comment out if the RHS is not an array constructor
                rhs = stripped[stripped.index(':=') + 2:].strip().rstrip(';')
                # If RHS doesn't contain array indexing, it's a scalar assignment
                if '[' not in rhs:
                    result.append(line.replace(stripped, '{ ' + stripped + ' }'))
                    continue
        result.append(line)
    return '\n'.join(result)


_FUNC_CALL_IN_WRITE_RE = re.compile(r'\b(Func_[0-9a-fA-F_]+)\s*\(\s*\)')


def _comment_out_bad_func_calls(body, proc_param_info):
    """Fix Write/WriteLn lines with Func_ calls that have wrong arg count.

    When _sanitize_ghidra_artifacts converts FUN_ to Func_ inside Write
    statements, the calls have no arguments. If the target function is
    declared with parameters, insert placeholder 0 args (or _tmp_ vars
    for var params) to make the call compile.
    """
    if not proc_param_info:
        return body
    lines = body.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('{') and stripped.endswith('}'):
            result.append(line)
            continue
        m = _FUNC_CALL_IN_WRITE_RE.search(stripped)
        if m:
            func_name = m.group(1)
            if func_name in proc_param_info:
                count, has_var, var_flags, param_types = proc_param_info[func_name]
                if count > 0:
                    placeholders = []
                    for i in range(count):
                        if var_flags and i < len(var_flags) and var_flags[i]:
                            placeholders.append(f'_tmp_{func_name}_{i}')
                        else:
                            placeholders.append('0')
                    args = ', '.join(placeholders)
                    fixed = stripped.replace(
                        f'{func_name}()', f'{func_name}({args})')
                    indent = line[:len(line) - len(line.lstrip())]
                    result.append(f'{indent}{fixed}')
                    continue
        result.append(line)
    return '\n'.join(result)


def _collect_undeclared_temps(body_text):
    """Scan a converted body for temp variable references and return declarations.

    Returns list of (name, type) tuples for variables like iVar1, uVar5, etc.
    If a temp var is used with indexed access (e.g., iVar1[21]), it's typed as
    an array instead of a scalar.
    """
    found = set()
    for m in _TEMP_VAR_RE.finditer(body_text):
        found.add(m.group(1))

    # Detect indexed access: varName[N] → need array type
    _INDEXED_RE = re.compile(r'\b(\w+)\[(\d+)\]')
    max_index = {}
    for m in _INDEXED_RE.finditer(body_text):
        vname = m.group(1)
        idx = int(m.group(2))
        if vname in found:
            max_index[vname] = max(max_index.get(vname, 0), idx)

    result = []
    for name in sorted(found):
        if name in max_index:
            # Variable used with indexing → declare as array
            hi = max_index[name]
            result.append((name, f'array[0..{hi}] of Integer'))
        else:
            prefix = name[0]
            ptype = _TEMP_VAR_TYPES.get(prefix, 'Integer')
            result.append((name, ptype))
    return result


def _fix_empty_proc_calls(body, proc_param_info):
    """Fix procedure calls with missing arguments.

    When Ghidra can't resolve BP7 stack-based argument passing, it emits
    FUN_xxxx() with no args, but the procedure actually has parameters.
    Add placeholder 0 args for non-var params, and temp variables for
    var params (since literals can't be passed by reference).
    """
    if not proc_param_info:
        return body
    lines = body.split('\n')
    result = []
    for line in lines:
        stripped = line.strip().rstrip(';')
        if stripped in proc_param_info:
            count, has_var, var_flags, param_types = proc_param_info[stripped]
            if count > 0:
                indent = line[:len(line) - len(line.lstrip())]
                placeholders = []
                for i in range(count):
                    if var_flags and i < len(var_flags) and var_flags[i]:
                        placeholders.append(f'_tmp_{stripped}_{i}')
                    else:
                        placeholders.append('0')
                args = ', '.join(placeholders)
                line = f'{indent}{stripped}({args});'
        result.append(line)
    return '\n'.join(result)

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
    if re.search(r'\bddp_', label_text):
        uses.add('ddplus')

    return sorted(uses)


def _extract_params(fn):
    """Extract parameter tuples (type, name, is_pointer) from IR function data."""
    params = []
    for p in fn.get('parameters', []):
        ptype = p.get('type', 'int')
        pname = p.get('name', 'param')
        is_ptr = '*' in ptype
        # Clean up type: remove pointer asterisk and pointer size suffix
        # Ghidra emits "byte *32" meaning "pointer-to-byte (32-bit pointer)"
        # Strip " *NN" as a unit to avoid "byte32" being misread as an array
        clean_type = re.sub(r'\s*\*\d*', '', ptype).strip()
        # Only map small undefined types (undefined, undefined1-8) to int
        # Large ones (undefined132, undefined232) are handled by c_type_to_pascal
        if re.match(r'^undefined\d?$', clean_type):
            clean_type = 'int'
        params.append((clean_type, pname, is_ptr))
    return params


def process(decompiled_path, strings_path=None, output_path=None, exe_path=None):
    """Process decompiled output and emit a .pas file.

    Requires functions.json (structured IR from Decompile.java) in the same
    directory as decompiled_path.
    """
    # Determine program name from directory
    dir_name = os.path.basename(os.path.dirname(os.path.abspath(decompiled_path)))
    program_name = dir_name if dir_name and dir_name != '.' else 'Program1'

    # Load structured IR (functions.json)
    ir_path = find_functions_json(decompiled_path)
    if not ir_path:
        raise FileNotFoundError(
            f"functions.json not found for {decompiled_path}. "
            f"Run Decompile.java to generate it."
        )
    ir_data = load_functions_json(ir_path)
    if not ir_data:
        raise ValueError(
            f"Failed to load functions.json from {ir_path}."
        )

    return _process_ir(ir_data, decompiled_path, strings_path, output_path,
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
            'strings_db': strings_db,
            'exe_reader': exe_reader,
        }

        body = convert_function_body(body_text, strings_db, func_info, exe_reader)

        # Extract local variable declarations from body
        local_vars = []
        clean_body_lines = []
        for bline in body.split('\n'):
            lv_match = re.match(r'\s*\{ var (\w+): (.+?); \}', bline)
            if lv_match:
                local_vars.append((lv_match.group(1), lv_match.group(2)))
            else:
                clean_body_lines.append(bline)

        clean_body = '\n'.join(clean_body_lines)

        # Collect undeclared temp variables from the body
        declared_names = {v[0] for v in local_vars}
        declared_names.update(p[1] for p in params)  # parameter names
        for temp_name, temp_type in _collect_undeclared_temps(clean_body):
            if temp_name not in declared_names:
                local_vars.append((temp_name, temp_type))

        pascal_funcs.append({
            'declaration': declaration,
            'body': clean_body,
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
            'strings_db': strings_db,
            'exe_reader': exe_reader,
        }
        main_body = convert_function_body(body_text, strings_db, func_info, exe_reader)

    # Extract local variable declarations from main body
    main_temps = []
    if main_body:
        clean_main_lines = []
        for bline in main_body.split('\n'):
            lv_match = re.match(r'\s*\{ var (\w+): (.+?); \}', bline)
            if lv_match:
                main_temps.append((lv_match.group(1), lv_match.group(2)))
            else:
                clean_main_lines.append(bline)
        main_body = '\n'.join(clean_main_lines)

    # Collect undeclared temp vars from main body and add to globals
    if main_body:
        global_names = {f'g_{off[2:].zfill(4).upper()}' for off in globals_map}
        declared_main = {t[0] for t in main_temps}
        for temp_name, temp_type in _collect_undeclared_temps(main_body):
            if temp_name not in global_names and temp_name not in declared_main:
                main_temps.append((temp_name, temp_type))
                declared_main.add(temp_name)

    # Filter globals: only keep those actually referenced in converted Pascal
    all_pascal_text = main_body
    for func in pascal_funcs:
        all_pascal_text += '\n' + func['body']
    referenced_globals = OrderedDict(
        (k, v) for k, v in globals_map.items()
        if f'g_{k[2:].zfill(4).upper()}' in all_pascal_text
    )

    # Also detect g_XXXX references from unaff_DS conversion (expressions.py)
    # These won't appear in _detect_globals() since they come from function
    # arguments (0xNN, unaff_DS), not pointer dereferences (*(int *)0xNN)
    existing_values = {int(k, 16) for k in referenced_globals}
    _G_REF_RE = re.compile(r'\bg_([0-9A-F]{4})\b')
    for m in _G_REF_RE.finditer(all_pascal_text):
        int_val = int(m.group(1), 16)
        if int_val not in existing_values:
            hex_offset = '0x' + m.group(1).lower()
            referenced_globals[hex_offset] = 'int'
            existing_values.add(int_val)
    # Re-sort by offset
    referenced_globals = OrderedDict(
        sorted(referenced_globals.items(), key=lambda x: int(x[0], 16))
    )

    # Detect globals that receive string assignments and retype them
    _STR_ASSIGN_RE = re.compile(
        r"\{ (g_[0-9A-F]{4}) := '([^']*)'; \}")
    string_globals = {}  # g_XXXX → max string length
    for m in _STR_ASSIGN_RE.finditer(all_pascal_text):
        gname = m.group(1)
        slen = len(m.group(2))
        if gname not in string_globals or slen > string_globals[gname]:
            string_globals[gname] = slen
    if string_globals:
        for offset in list(referenced_globals):
            gname = f'g_{offset[2:].zfill(4).upper()}'
            if gname in string_globals:
                slen = max(string_globals[gname], 1)
                referenced_globals[offset] = f'String[{slen}]'
        # Uncomment string assignments in function bodies and main body
        def _uncomment_str_assigns(text, str_globals):
            lines = text.split('\n')
            out = []
            for line in lines:
                m = _STR_ASSIGN_RE.search(line)
                if m and m.group(1) in str_globals:
                    # Remove { } comment wrapper
                    indent = len(line) - len(line.lstrip())
                    out.append(' ' * indent + m.group(1) +
                               " := '" + m.group(2) + "';")
                else:
                    out.append(line)
            return '\n'.join(out)
        main_body = _uncomment_str_assigns(main_body, string_globals)
        for func in pascal_funcs:
            func['body'] = _uncomment_str_assigns(
                func['body'], string_globals)

    # Detect globals used with array indexing and retype them
    _ARRAY_GLOBAL_RE = re.compile(r'\bg_([\dA-F]{4})\[([^\]]+)\]')
    array_globals = {}  # g_XXXX → max observed index
    for m in _ARRAY_GLOBAL_RE.finditer(all_pascal_text):
        gname = f'g_{m.group(1)}'
        try:
            idx = int(m.group(2))
            if gname not in array_globals or idx > array_globals[gname]:
                array_globals[gname] = idx
        except ValueError:
            # Dynamic index — use a default upper bound
            if gname not in array_globals:
                array_globals[gname] = 9
    if array_globals:
        for offset in list(referenced_globals):
            gname = f'g_{offset[2:].zfill(4).upper()}'
            if gname in array_globals:
                hi = max(array_globals[gname], 1)
                base_type = referenced_globals[offset]
                ptype = c_type_to_pascal(base_type) or 'Integer'
                referenced_globals[offset] = f'array[0..{hi}] of {ptype}'

    # Generate stubs for cross-segment Proc_ references not declared
    declared_procs = {f['pascal_name'] for f in pascal_funcs}
    proc_refs = set(re.findall(r'\bProc_[0-9a-fA-F]+_[0-9a-fA-F]+\b', all_pascal_text))
    undeclared_procs = sorted(proc_refs - declared_procs)

    # Build lookup from FUN_/Proc_ name to IR function for parameter info
    ir_by_name = {}
    for fn in ir_functions:
        name = fn.get('name', '')
        if name.startswith('FUN_'):
            ir_by_name['Proc_' + name[4:]] = fn

    stub_funcs = []
    for pname in undeclared_procs:
        # Check if ANY call site passes arguments (look for 'Proc_name(')
        has_args_call = re.search(re.escape(pname) + r'\s*\(', all_pascal_text)
        ir_fn = ir_by_name.get(pname)
        if has_args_call and ir_fn:
            # Strip 'var' from stub params — call sites often pass literal
            # offsets (from seg:off expansion), not variable references
            params = [(t, n, False) for t, n, _ in _extract_params(ir_fn)]
            # Count max args at call sites to detect param count mismatch
            call_args = re.findall(
                re.escape(pname) + r'\s*\(([^)]+)\)', all_pascal_text)
            if call_args:
                max_args = max(
                    len(re.split(r',(?![^(]*\))', a)) for a in call_args)
                # If call sites have more args than IR definition, pad with
                # extra Integer params (leftover segment/offset values)
                existing_names = {n for _, n, _ in params}
                pad_idx = len(params) + 1
                while len(params) < max_args:
                    while f'param_{pad_idx}' in existing_names:
                        pad_idx += 1
                    params.append(('int', f'param_{pad_idx}', False))
                    pad_idx += 1
            _, decl, _, _ = make_pascal_signature('void', ir_fn['name'], params)
        elif has_args_call:
            # No IR function — generate params from call site arg count
            call_args = re.findall(
                re.escape(pname) + r'\s*\(([^)]+)\)', all_pascal_text)
            max_args = max(
                len(re.split(r',(?![^(]*\))', a)) for a in call_args)
            params = [('int', f'param_{i + 1}', False)
                      for i in range(max_args)]
            _, decl, _, _ = make_pascal_signature('void', pname, params)
        else:
            decl = f'procedure {pname};'
        stub_funcs.append({
            'declaration': decl,
            'body': '  { cross-segment stub }',
            'is_function': False,
            'pascal_name': pname,
            'local_vars': [],
        })
    pascal_funcs = stub_funcs + pascal_funcs

    # Generate stubs for cross-segment Func_ references (functions used
    # in Write/WriteLn arguments that aren't declared in the program)
    func_refs = set(re.findall(r'\bFunc_[0-9a-fA-F]+_[0-9a-fA-F]+\b',
                               all_pascal_text))
    declared_funcs = {f['pascal_name'] for f in pascal_funcs}
    undeclared_funcs = sorted(func_refs - declared_funcs)
    func_stubs = []
    for fname in undeclared_funcs:
        decl = f'function {fname}: Integer;'
        func_stubs.append({
            'declaration': decl,
            'body': '  { cross-segment stub }',
            'is_function': True,
            'pascal_name': fname,
            'local_vars': [],
        })
    pascal_funcs = func_stubs + pascal_funcs

    # Build map of procedure names to required param counts for fixing
    # empty calls (Ghidra emits FUN_xxxx() with no args when it can't
    # resolve BP7 stack-based argument passing)
    proc_param_info = {}
    for func in pascal_funcs:
        pname = func['pascal_name']
        decl = func['declaration']
        # Count params from declaration: procedure Name(p1: T; p2: T);
        param_match = re.search(r'\(([^)]+)\)', decl)
        if param_match:
            param_text = param_match.group(1)
            param_groups = param_text.split(';')
            count = len(param_groups)
            has_var = 'var ' in param_text
            # Track which params are var and their types
            var_flags = []
            param_types = []
            for g in param_groups:
                g = g.strip()
                is_var = g.startswith('var ')
                var_flags.append(is_var)
                # Extract type: "var param_1: Byte" → "Byte", "param_2: Integer" → "Integer"
                type_match = re.search(r':\s*(\w+)', g)
                param_types.append(type_match.group(1) if type_match else 'Integer')
            proc_param_info[pname] = (count, has_var, var_flags, param_types)

    # Fix procedure calls with missing arguments (placeholder 0 values)
    if proc_param_info:
        main_body = _fix_empty_proc_calls(main_body, proc_param_info)
        for func in pascal_funcs:
            func['body'] = _fix_empty_proc_calls(
                func['body'], proc_param_info)

    # Collect _tmp_ variables generated by _fix_empty_proc_calls
    # Build lookup: _tmp_ProcName_idx → type from proc_param_info
    _tmp_type_map = {}
    for pname, (count, has_var, var_flags, param_types) in proc_param_info.items():
        for i in range(count):
            if var_flags and i < len(var_flags) and var_flags[i]:
                tmp_name = f'_tmp_{pname}_{i}'
                _tmp_type_map[tmp_name] = param_types[i] if i < len(param_types) else 'Integer'
    _TMP_VAR_RE = re.compile(r'\b(_tmp_\w+)\b')
    for func in pascal_funcs:
        existing = {v[0] for v in func.get('local_vars', [])}
        for m in _TMP_VAR_RE.finditer(func['body']):
            vname = m.group(1)
            if vname not in existing:
                vtype = _tmp_type_map.get(vname, 'Integer')
                func.setdefault('local_vars', []).append((vname, vtype))
                existing.add(vname)
    existing_main = {t[0] for t in main_temps}
    for m in _TMP_VAR_RE.finditer(main_body):
        vname = m.group(1)
        if vname not in existing_main:
            vtype = _tmp_type_map.get(vname, 'Integer')
            main_temps.append((vname, vtype))
            existing_main.add(vname)

    # Comment out lines with unconverted C pointer syntax or scalar→array assigns
    for func in pascal_funcs:
        array_vars = {name for name, typ in func['local_vars']
                      if typ.startswith('array[')}
        func['body'] = _comment_out_unsafe_lines(func['body'], array_vars)
    main_body = _comment_out_unsafe_lines(main_body)

    # Comment out Write/WriteLn lines that call Func_ with wrong arg count
    main_body = _comment_out_bad_func_calls(main_body, proc_param_info)
    for func in pascal_funcs:
        func['body'] = _comment_out_bad_func_calls(
            func['body'], proc_param_info)

    # Collect _tmp_ variables generated by _comment_out_bad_func_calls
    for func in pascal_funcs:
        existing = {v[0] for v in func.get('local_vars', [])}
        for m in _TMP_VAR_RE.finditer(func['body']):
            vname = m.group(1)
            if vname not in existing:
                vtype = _tmp_type_map.get(vname, 'Integer')
                func.setdefault('local_vars', []).append((vname, vtype))
                existing.add(vname)
    for m in _TMP_VAR_RE.finditer(main_body):
        vname = m.group(1)
        if vname not in existing_main:
            vtype = _tmp_type_map.get(vname, 'Integer')
            main_temps.append((vname, vtype))
            existing_main.add(vname)

    # Emit
    pascal_text = emit_pascal(program_name, uses, referenced_globals, pascal_funcs,
                              main_body, main_temps)

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
