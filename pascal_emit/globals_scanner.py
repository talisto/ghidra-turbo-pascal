"""Global variable detection and uses clause inference."""
import re
from collections import OrderedDict


GLOBAL_MEM_RE = re.compile(r'\*\((int|uint|word|byte|char) \*\)(0x[0-9a-f]+)')


def detect_globals(functions):
    """Scan all function bodies for global memory accesses.

    Returns OrderedDict of offset → type, sorted by offset.
    """
    globals_map = {}
    for func in functions:
        for m in GLOBAL_MEM_RE.finditer(func['body']):
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


def detect_uses(functions):
    """Detect which Pascal units are needed from library function names.

    Only scans application and entry functions — library functions
    are part of the RTL, not the user's uses clause.
    """
    uses = set()
    app_text = '\n'.join(
        f['body'] for f in functions
        if f.get('classification') in ('application', 'entry')
    )

    if re.search(r'\bcrt_|@AssignCrt|crt_gotoxy|crt_textattr|crt_clrscr|crt_readkey', app_text):
        uses.add('Crt')
    if re.search(r'\bdos_intr\b|@GetDate|@GetTime|@FindFirst|@DiskSize|@SetIntVec|@FSplit|@GetEnv|@Intr', app_text):
        uses.add('Dos')

    return sorted(uses)
