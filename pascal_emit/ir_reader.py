"""Read and navigate the structured IR from functions.json.

functions.json is emitted by Decompile.java Phase 7 and contains per-function:
- Metadata: name, address, returnType, parameters, locals, isLibrary, label
- Call data: PcodeOp.CALL targets + arguments with resolved string references
- AST: serialized ClangTokenGroup tree (statement/token hierarchy)
- cCode: flat C text (debugging fallback)
"""
import json
import os


def load_functions_json(path):
    """Load and parse a functions.json file.

    Returns a dict with:
        version: int
        program: str
        functions: list of FunctionIR dicts
    Or None if the file doesn't exist or can't be parsed.
    """
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict) or 'functions' not in data:
            return None
        return data
    except (json.JSONDecodeError, IOError):
        return None


def find_functions_json(decompiled_path):
    """Find functions.json alongside a decompiled.c file."""
    dir_path = os.path.dirname(os.path.abspath(decompiled_path))
    candidate = os.path.join(dir_path, 'functions.json')
    return candidate if os.path.isfile(candidate) else None


# ─── AST navigation helpers ───


def ast_children(node):
    """Get children of an AST group node, filtering nulls."""
    if node is None or node.get('nodeType') == 'token':
        return []
    return [c for c in node.get('children', []) if c is not None]


def ast_tokens(node):
    """Recursively collect all leaf tokens from an AST node."""
    if node is None:
        return []
    if node.get('nodeType') == 'token':
        return [node]
    tokens = []
    for child in node.get('children', []):
        if child is not None:
            tokens.extend(ast_tokens(child))
    return tokens


def ast_text(node):
    """Reconstruct the text content of an AST node by joining all tokens."""
    return ' '.join(t.get('value', '') for t in ast_tokens(node))


def ast_find_groups(node, group_type):
    """Find all group nodes of a specific type (e.g., 'statement', 'function')."""
    results = []
    if node is None:
        return results
    if node.get('nodeType') == group_type:
        results.append(node)
    for child in node.get('children', []):
        if child is not None:
            results.extend(ast_find_groups(child, group_type))
    return results


def ast_find_tokens(node, kind):
    """Find all tokens of a specific kind (e.g., 'variable', 'funcName', 'op')."""
    return [t for t in ast_tokens(node) if t.get('kind') == kind]


def classify_statement(stmt_node):
    """Classify a statement node by its leading keyword token.

    Returns one of: 'if', 'while', 'for', 'do', 'switch', 'return',
    'break', 'continue', 'goto', 'declaration', 'block', 'expression'.
    """
    if stmt_node is None or stmt_node.get('nodeType') != 'statement':
        return 'unknown'

    children = ast_children(stmt_node)
    if not children:
        return 'empty'

    # Look at the first significant token
    first = children[0]
    if first.get('nodeType') == 'token':
        val = first.get('value', '').strip()
        kind = first.get('kind', '')

        if val in ('if', 'while', 'for', 'do', 'switch', 'return',
                    'break', 'continue', 'goto'):
            return val
        if kind == 'type':
            return 'declaration'
        if val == '{':
            return 'block'

    # Check for varDecl children
    for child in children:
        if child.get('nodeType') == 'varDecl':
            return 'declaration'

    return 'expression'


# ─── Function-level access ───


def get_app_functions(ir_data):
    """Get non-library functions from the IR data."""
    if ir_data is None:
        return []
    return [f for f in ir_data.get('functions', []) if not f.get('isLibrary', False)]


def get_function_params(func):
    """Get parameters as list of (name, type) tuples."""
    return [(p['name'], p['type']) for p in func.get('parameters', [])]


def get_function_locals(func):
    """Get local variables as list of (name, type) tuples."""
    return [(v['name'], v['type']) for v in func.get('locals', [])]


def get_function_calls(func):
    """Get all call operations from a function."""
    return func.get('calls', [])


def get_resolved_strings(func):
    """Get all resolved string references from calls.

    Returns a dict mapping (targetAddress, argIndex) -> string.
    """
    result = {}
    for call in func.get('calls', []):
        for sarg in call.get('resolvedStrings', []):
            key = (call.get('target', ''), sarg.get('argIndex', -1))
            result[key] = sarg.get('string', '')
    return result


def get_call_string_args(call):
    """Get resolved strings for a specific call.

    Returns a dict mapping argIndex -> string.
    """
    result = {}
    for sarg in call.get('resolvedStrings', []):
        result[sarg.get('argIndex', -1)] = sarg.get('string', '')
    return result
