"""pascal_emit — Convert decompiled C output to Pascal source.

Prototype C-to-Pascal transpiler for Borland Pascal 7 decompiled output.
Data source: functions.json (structured IR from Decompile.java Phase 7).

Usage:
  python3 -m pascal_emit tests/output/HELLO/decompiled.c
  python3 -m pascal_emit tests/output/PROCFUNC/decompiled.c -o output.pas
"""

# Re-export public API
from .strings import load_strings, ExeStringReader, find_exe_for_decompiled
from .types import c_type_to_pascal, make_pascal_signature, C_TO_PASCAL_TYPE
from .expressions import convert_expression, convert_condition, negate_condition
from .write_sequences import (
    detect_write_sequences, extract_string_annotation,
    STRING_ANNOTATION_RE,
)
from .body_converter import (
    convert_function_body, convert_c_line,
    is_noise_line, is_system_init_line, NOISE_PATTERNS,
)
from .emitter import emit_pascal
from .pipeline import process
from .ir_reader import (
    load_functions_json, find_functions_json,
    ast_children, ast_tokens, ast_text, ast_find_groups, ast_find_tokens,
    classify_statement, get_app_functions, get_function_params,
    get_function_locals, get_function_calls, get_resolved_strings,
    get_call_string_args,
)

__all__ = [
    # strings
    'load_strings', 'ExeStringReader', 'find_exe_for_decompiled',
    # types
    'c_type_to_pascal', 'make_pascal_signature', 'C_TO_PASCAL_TYPE',
    # expressions
    'convert_expression', 'convert_condition', 'negate_condition',
    # write_sequences
    'detect_write_sequences', 'extract_string_annotation',
    'STRING_ANNOTATION_RE',
    # body_converter
    'convert_function_body', 'convert_c_line',
    'is_noise_line', 'is_system_init_line', 'NOISE_PATTERNS',
    # emitter
    'emit_pascal',
    # pipeline
    'process',
    # ir_reader
    'load_functions_json', 'find_functions_json',
    'ast_children', 'ast_tokens', 'ast_text', 'ast_find_groups',
    'ast_find_tokens', 'classify_statement', 'get_app_functions',
    'get_function_params', 'get_function_locals', 'get_function_calls',
    'get_resolved_strings', 'get_call_string_args',
]
