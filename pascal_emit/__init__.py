"""pascal_emit — Convert decompiled C output to Pascal source.

Prototype C-to-Pascal transpiler for Borland Pascal 7 decompiled output.
Reads decompiled.c and strings.json, emits a .pas file.

Usage:
  python3 -m pascal_emit tests/output/HELLO/decompiled.c
  python3 -m pascal_emit tests/output/PROCFUNC/decompiled.c -o output.pas
"""

# Re-export public API for backward compatibility with `import pascal_emit`
from .strings import load_strings, ExeStringReader, find_exe_for_decompiled
from .parser import (
    parse_functions, classify_function, find_primary_segment,
    parse_c_signature,
)
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
from .globals_scanner import detect_globals, detect_uses, GLOBAL_MEM_RE
from .emitter import emit_pascal
from .pipeline import process

__all__ = [
    # strings
    'load_strings', 'ExeStringReader', 'find_exe_for_decompiled',
    # parser
    'parse_functions', 'classify_function', 'find_primary_segment',
    'parse_c_signature',
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
    # globals_scanner
    'detect_globals', 'detect_uses', 'GLOBAL_MEM_RE',
    # emitter
    'emit_pascal',
    # pipeline
    'process',
]
