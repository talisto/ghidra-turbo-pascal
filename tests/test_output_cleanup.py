"""test_output_cleanup.py — Tests for output cleanup and library elimination.

Tests for Phase 3.2 (Library Code Elimination) and Phase 3.4 (Artifact Cleanup)
from the ROADMAP.
"""
import os
import re
import pytest
from conftest import OUTPUT_DIR


class TestLibraryElimination:
    """Phase 3.2: Library function bodies should be eliminated from output."""

    # Library function prefixes: bp_ (System RTL), plus FLIRT-identified functions
    LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')
    # FLIRT name patterns: @Name$... or __Name
    FLIRT_PATTERNS = (re.compile(r'^@\w+\$'), re.compile(r'^__[A-Z]'))

    @classmethod
    def _is_library_function(cls, name):
        """Check if a function name is a known library function."""
        if any(name.startswith(p) for p in cls.LIBRARY_PREFIXES):
            return True
        for pat in cls.FLIRT_PATTERNS:
            if pat.match(name):
                return True
        return False

    def test_library_functions_marked(self, decompiled_text, program):
        """Library functions should have [LIBRARY] marker in their header."""
        headers = re.findall(
            r'^// Function: (\S+) @ [0-9a-f]+:[0-9a-f]+\s*$',
            decompiled_text, re.MULTILINE)
        lib_funcs = [h for h in headers if self._is_library_function(h)]
        if not lib_funcs:
            pytest.skip(f"{program} has no library functions to check")

        for func_name in lib_funcs:
            # The function header block should contain [LIBRARY]
            pattern = re.compile(
                r'^// Function: ' + re.escape(func_name) + r' @ [0-9a-f]+:[0-9a-f]+\n'
                r'// ={10,}\n'
                r'// \[LIBRARY\]',
                re.MULTILINE)
            assert pattern.search(decompiled_text), (
                f"{program}: library function {func_name} missing [LIBRARY] marker")

    def test_library_functions_no_body(self, decompiled_text, program):
        """Library functions should NOT have full C function bodies.

        After the header+marker, the next non-blank, non-comment line
        should be another function header, not a C function body."""
        # Split into function blocks
        blocks = re.split(r'(?=\n// ={10,}\n// Function:)', decompiled_text)
        for block in blocks:
            header_match = re.search(
                r'// Function: (\S+) @ [0-9a-f]+:[0-9a-f]+', block)
            if not header_match:
                continue
            func_name = header_match.group(1)
            if not self._is_library_function(func_name):
                continue

            # Library function block should NOT contain a C function body
            # (no opening brace after a function signature)
            body_lines = block.split('\n')
            # Skip header comment lines
            has_c_body = False
            for line in body_lines:
                stripped = line.strip()
                if stripped.startswith('//') or stripped == '':
                    continue
                # If we find a C declaration/definition line, it's a body
                if stripped.startswith(('void ', 'int ', 'uint ', 'byte ',
                                       'word ', 'char ', 'dword ', 'short ',
                                       'long ', 'ushort ')):
                    has_c_body = True
                    break
                if stripped == '{':
                    has_c_body = True
                    break

            assert not has_c_body, (
                f"{program}: library function {func_name} still has C body — "
                f"should be eliminated")

    def test_application_functions_have_body(self, decompiled_text, program):
        """Application functions (FUN_*, entry, ddp_*, etc.) should still have bodies."""
        blocks = re.split(r'(?=\n// ={10,}\n// Function:)', decompiled_text)
        app_with_body = 0
        for block in blocks:
            header_match = re.search(
                r'// Function: (\S+) @ [0-9a-f]+:[0-9a-f]+', block)
            if not header_match:
                continue
            func_name = header_match.group(1)
            if self._is_library_function(func_name):
                continue
            # Application function — should have a body (at least a '{')
            if '{' in block:
                app_with_body += 1

        assert app_with_body >= 1, (
            f"{program}: no application functions have bodies")

    def test_library_summary_section(self, decompiled_text, program):
        """Output should contain a library function summary section."""
        assert '// === Library Functions ===' in decompiled_text, (
            f"{program}: missing library function summary section")

    def test_library_summary_lists_functions(self, decompiled_text, program):
        """Library summary section should list function names with addresses."""
        summary_match = re.search(
            r'// === Library Functions ===\n(.*?)(?:\n// ===|\Z)',
            decompiled_text, re.DOTALL)
        if not summary_match:
            pytest.skip(f"{program} has no library summary section")

        summary = summary_match.group(1)
        # Should contain at least some bp_ function references
        bp_refs = re.findall(r'//\s+(bp_\w+)', summary)
        assert len(bp_refs) >= 5, (
            f"{program}: library summary has only {len(bp_refs)} bp_ entries, "
            f"expected >= 5")


class TestArtifactCleanup:
    """Phase 3.4: Ghidra register artifacts should be cleaned up."""

    def test_no_concat11_extraout(self, decompiled_text, program):
        """CONCAT11(extraout_AH, value) should be simplified to just value.

        In BP7, the AH part of the CONCAT11 result is irrelevant —
        only the lower byte (AL) matters for character/byte operations."""
        # Match CONCAT11(extraout_AH, ...) or CONCAT11(extraout_AH_00, ...)
        matches = re.findall(r'CONCAT11\(extraout_AH\w*,\s*[^)]+\)',
                             decompiled_text)
        assert len(matches) == 0, (
            f"{program}: {len(matches)} CONCAT11(extraout_AH,...) artifacts remaining: "
            f"{matches[:3]}")

    def test_no_unused_unaff_ds_declarations(self, decompiled_text, program):
        """Unused unaff_DS variable declarations should be removed.

        unaff_DS is the data segment register, which is implicitly set
        by the BP7 calling convention. Declarations are only kept when
        the variable is actually referenced in the function body."""
        # Split into function blocks and check each
        blocks = re.split(r'(?=\n// ={10,}\n// Function:)', decompiled_text)
        unused_decls = []
        for block in blocks:
            for match in re.finditer(r'^\s+\w+\s+(unaff_DS)\s*;',
                                     block, re.MULTILINE):
                var_name = match.group(1)
                other_text = block[:match.start()] + block[match.end():]
                if not re.search(r'\b' + re.escape(var_name) + r'\b', other_text):
                    unused_decls.append(var_name)

        assert len(unused_decls) == 0, (
            f"{program}: {len(unused_decls)} unused unaff_DS declarations remaining")

    def test_no_unused_extraout_declarations(self, decompiled_text, program):
        """Unused extraout_AH variable declarations should be removed.

        After CONCAT11(extraout_AH, X) → X cleanup, some extraout_AH
        variables become unused. Their declarations should be removed.
        Declarations ARE kept when the variable has standalone uses
        (e.g., `*(byte *)0x63 = extraout_AH;`)."""
        # Split into function blocks and check each
        blocks = re.split(r'(?=\n// ={10,}\n// Function:)', decompiled_text)
        unused_decls = []
        for block in blocks:
            # Find extraout_AH declarations
            for match in re.finditer(r'^\s+\w+\s+(extraout_AH\w*)\s*;',
                                     block, re.MULTILINE):
                var_name = match.group(1)
                # Check if var is used elsewhere (not just declared)
                other_text = block[:match.start()] + block[match.end():]
                if not re.search(r'\b' + re.escape(var_name) + r'\b', other_text):
                    unused_decls.append(var_name)

        assert len(unused_decls) == 0, (
            f"{program}: {len(unused_decls)} unused extraout_AH declarations: "
            f"{unused_decls[:5]}")
