"""Parse decompiled.c into function blocks and classify them."""
import re


FUNC_HEADER_RE = re.compile(
    r'\n// ={10,}\n// Function: (\S+) @ ([0-9a-f]+:[0-9a-f]+)\n// ={10,}\n'
)

LIBRARY_MARKER_RE = re.compile(r'^\s*// \[LIBRARY\]')

# Prefixes that indicate library functions (bodies already eliminated)
LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')

FLIRT_PATTERNS = [
    re.compile(r'^@\w+\$'),
    re.compile(r'^__[A-Z]'),
]


def parse_functions(text):
    """Parse decompiled.c into a list of function blocks.

    Returns list of dicts with keys:
      name, address, body, is_library, segment
    """
    parts = FUNC_HEADER_RE.split(text)
    # parts: [preamble, name1, addr1, body1, name2, addr2, body2, ...]
    functions = []
    i = 1
    while i < len(parts):
        name = parts[i]
        addr = parts[i + 1]
        body = parts[i + 2] if i + 2 < len(parts) else ''
        seg = addr.split(':')[0]
        is_library = bool(LIBRARY_MARKER_RE.search(body.split('\n')[0] if body else ''))
        functions.append({
            'name': name,
            'address': addr,
            'body': body.strip(),
            'is_library': is_library,
            'segment': seg,
        })
        i += 3
    return functions


def classify_function(func):
    """Classify a function as 'library', 'entry', 'application', or 'system'.

    Returns the classification string.
    """
    name = func['name']

    if func['is_library']:
        return 'library'

    if name == 'entry':
        return 'entry'

    # Check if it's a library function that wasn't tagged
    if any(name.startswith(p) for p in LIBRARY_PREFIXES):
        return 'library'
    for pat in FLIRT_PATTERNS:
        if pat.match(name):
            return 'library'

    return 'application'


def find_primary_segment(functions):
    """Find the primary application segment (usually 1000).

    The entry function is always in the primary segment.
    """
    for func in functions:
        if func['name'] == 'entry':
            return func['segment']
    # Default to first segment
    if functions:
        return functions[0]['segment']
    return '1000'


# ────────────────────────────────────────────────────────────────
# C signature parser
# ────────────────────────────────────────────────────────────────

C_SIG_RE = re.compile(
    r'^(\w[\w\s*]*?)\s+' +       # return type
    r'(\w+)\s*'                   # function name
    r'\(([^)]*)\)',               # parameters
    re.MULTILINE
)

C_PARAM_RE = re.compile(
    r'(\w[\w\s*]*?)\s*(\*?)\s*(\w+)$'
)


def parse_c_signature(body):
    """Parse a C function signature from the body text.

    Returns (return_type, func_name, params) where params is a list of
    (type, name, is_pointer) tuples. Returns None if parsing fails.
    """
    # Strip leading comments and blank lines
    lines = body.split('\n')
    sig_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('/*') or stripped.startswith('//'):
            continue
        sig_lines.append(stripped)
        if '{' in stripped or ')' in stripped:
            break

    if not sig_lines:
        return None

    sig_text = ' '.join(sig_lines).split('{')[0].strip()

    m = C_SIG_RE.match(sig_text)
    if not m:
        return None

    ret_type = m.group(1).strip()
    func_name = m.group(2).strip()
    param_text = m.group(3).strip()

    params = []
    if param_text and param_text != 'void':
        for p in param_text.split(','):
            p = p.strip()
            pm = C_PARAM_RE.match(p)
            if pm:
                ptype = pm.group(1).strip()
                is_ptr = bool(pm.group(2))
                pname = pm.group(3).strip()
                params.append((ptype, pname, is_ptr))
            else:
                # Fallback: just use the whole thing
                params.append(('int', p.split()[-1] if p.split() else 'param', False))

    return ret_type, func_name, params
