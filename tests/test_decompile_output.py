"""test_decompile_output.py — Validate decompiled output structure.

Tests run against pre-generated output in tests/output/ — they don't
invoke Ghidra. Run the full pipeline first via run_tests.sh or decompile.sh.
"""
import os
import re
import pytest
from conftest import OUTPUT_DIR


# Minimum expected function counts per program (from Ghidra analysis)
MIN_FUNCTIONS = {
    'HELLO':    28,
    'CONTROL':  35,
    'CRTTEST':  60,
    'DDTEST':  290,
    'DOSTEST':  55,
    'EXITPROC': 34,
    'FILEIO':   80,
    'GAMESIM':  48,
    'MATHOPS':  49,
    'PROCFUNC': 44,
    'PTRMEM':   55,
    'RANDTEST': 41,
    'RECORDS':  47,
    'STRINGS':  43,
    'TYPECAST': 35,
}


class TestDecompiledOutput:
    """Validate the raw decompiled.c output from Ghidra."""

    def test_output_files_exist(self, program):
        """Pipeline output file must exist."""
        prog_dir = os.path.join(OUTPUT_DIR, program)
        assert os.path.isfile(os.path.join(prog_dir, 'decompiled.c'))

    def test_minimum_functions(self, program, decompiled_text):
        """Each program should decompile to at least MIN_FUNCTIONS functions."""
        func_count = len(re.findall(r'^// Function:', decompiled_text, re.MULTILINE))
        min_count = MIN_FUNCTIONS.get(program, 5)
        assert func_count >= min_count, (
            f"{program} has {func_count} functions, expected >= {min_count}")

    def test_has_function_headers(self, decompiled_text, program):
        """Every function should have the expected header format."""
        headers = re.findall(
            r'^// Function: (\S+) @ ([0-9a-f]+:[0-9a-f]+)$',
            decompiled_text, re.MULTILINE)
        assert len(headers) > 0, f"{program} has no function headers"
        # Each header should have a valid seg:off address
        for name, addr in headers:
            seg, off = addr.split(':')
            assert len(seg) == 4, f"Bad segment in {name}: {seg}"
            assert len(off) == 4, f"Bad offset in {name}: {off}"

    def test_no_decompiler_errors(self, decompiled_text, program):
        """Output should not contain Ghidra error markers."""
        # These indicate decompilation failures
        assert 'BADSPACEBASE' not in decompiled_text, f"{program} has BADSPACEBASE"
        assert 'Low-level Error' not in decompiled_text, f"{program} has Low-level Error"

    def test_has_flirt_functions(self, decompiled_text, program):
        """Every TP7 binary should have at least some FLIRT-identified functions.
        Decompile.java may rename FLIRT names to short labels (e.g.
        _WriteLn_qm4Text → bp_writeln), so we check for either pattern."""
        # FLIRT names that survived renaming (original mangled form)
        flirt_funcs = re.findall(
            r'_[A-Za-z]\w*_q[A-Za-z0-9]+|__[A-Z][A-Za-z]+',
            decompiled_text)
        # Renamed FLIRT functions (bp_write*, crt_*, dos_*, etc.)
        renamed_funcs = re.findall(
            r'\b(?:bp_write\w+|bp_read\w+|bp_random\w*|bp_halt\w*|bp_assign\w*|'
            r'bp_concat|bp_copy|bp_pos|bp_delete|bp_insert|bp_str_\w+|bp_val_\w+|'
            r'bp_length|bp_ioresult|bp_upcase|bp_runerror|bp_new|bp_dispose|'
            r'bp_getmem|bp_freemem|bp_memavail|bp_maxavail|bp_eof\w*|bp_erase|'
            r'bp_rename|bp_reset|bp_rewrite|bp_close|bp_seek|bp_filesize|bp_filepos|'
            r'crt_\w+|dos_\w+|ddp_\w+|comio_\w+|ovr_\w+)\b',
            decompiled_text)
        total = len(flirt_funcs) + len(renamed_funcs)
        assert total > 0, (
            f"{program} has no FLIRT-identified functions (original or renamed)")


class TestTypeCleanup:
    """Verify that Decompile.java cleans up Ghidra type artifacts."""

    def test_no_undefined_types(self, decompiled_text, program):
        """Output should not contain Ghidra's undefined type placeholders.

        Decompile.java Phase 5 replaces undefined1/2/4/8 with byte/word/dword/qword."""
        for undef in ['undefined1', 'undefined2', 'undefined4', 'undefined8']:
            assert re.search(r'\b' + undef + r'\b', decompiled_text) is None, (
                f"{program} still contains '{undef}' — type cleanup not applied")

    def test_no_cdecl16_calling_convention(self, decompiled_text, program):
        """Output should not contain __cdecl16near or __cdecl16far annotations.

        These are 16-bit calling convention noise that makes output harder to read."""
        assert '__cdecl16near' not in decompiled_text, (
            f"{program} still contains '__cdecl16near' — convention cleanup not applied")
        assert '__cdecl16far' not in decompiled_text, (
            f"{program} still contains '__cdecl16far' — convention cleanup not applied")

    def test_uses_standard_type_names(self, decompiled_text, program):
        """Output should use standard type names (byte, word) instead of undefined."""
        # After cleanup, at least some byte/word types should appear
        has_byte = 'byte' in decompiled_text
        has_word = 'word' in decompiled_text
        assert has_byte or has_word, (
            f"{program} has neither 'byte' nor 'word' types — cleanup may not be working")
