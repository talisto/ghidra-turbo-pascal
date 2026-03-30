"""test_annotate_strings.py — Tests for string annotation output

Validates that string annotations in decompiled output are accurate
and don't produce false positives.
"""
import os
import re
import pytest
from conftest import OUTPUT_DIR, DATA_DIR


class TestStringAnnotations:
    """Validate string annotation correctness."""

    def test_annotations_are_printable(self, annotated_text, program):
        """All annotated strings should contain printable characters."""
        # Extract string annotations: /* "..." */
        annotations = re.findall(r'/\*\s*"([^"]+)"\s*\*/', annotated_text)
        for ann in annotations:
            # Allow backtick color codes, standard printable ASCII, and whitespace
            for ch in ann:
                assert (ch.isprintable() or ch in '\t\n\r'), (
                    f"{program}: non-printable char in annotation: {repr(ann)}")

    def test_no_annotation_on_ptr_offset_itself(self, annotated_text, program):
        """The pointer offset in address computation should not be annotated.

        Regression test: `*(ptr + -0x10a) = 0x52` should NOT match 0x10a
        as a string offset. The VALUE being stored (0x52) may legitimately
        be a string offset, but the arithmetic offset (-0x10a) should not.

        We check for annotations where the ONLY hex constants on the line
        are part of pointer arithmetic (no function call or stored value).
        """
        for line in annotated_text.split('\n'):
            if '/*' not in line or '"' not in line:
                continue
            # Very specific: catch annotations that are triggered by the
            # address offset rather than the stored value.
            # Pattern: line has only one hex constant and it's in ptr arithmetic
            stripped = line.strip()
            # Skip lines with function calls — those are legitimate
            if '(' in stripped and ')' in stripped:
                # Has a function call or cast — likely legitimate
                continue
            # Pure assignment where only constant is in the address offset
            if re.match(r'\*.*[+\-]\s*-?0x[0-9a-fA-F]+.*=\s*[^0].*?/\*', stripped):
                pytest.fail(
                    f"{program}: annotation may be on ptr offset, not value: "
                    f"{stripped}")

    def test_annotation_count_reasonable(self, annotated_text, program):
        """Programs should have a reasonable number of annotations."""
        annotations = re.findall(r'/\*\s*"[^"]+"\s*\*/', annotated_text)
        total_lines = annotated_text.count('\n')
        # Annotations should be < 10% of total lines (sanity check)
        if total_lines > 0:
            ratio = len(annotations) / total_lines
            assert ratio < 0.10, (
                f"{program}: {len(annotations)} annotations in {total_lines} lines "
                f"({ratio:.1%}) seems too many — possible false positive flood")


class TestStringAnnotationRegression:
    """Specific regression tests for known bugs."""

    def test_strings_program_no_false_after_insert(self):
        """STRINGS program should not have false 'After Insert:' annotations.

        Regression: The old code matched 0x10a in pointer arithmetic
        `puVar8 + -0x10a` as string offset → false 'After Insert:' floods.
        """
        path = os.path.join(OUTPUT_DIR, 'STRINGS', 'decompiled.c')
        if not os.path.isfile(path):
            pytest.skip("STRINGS output not available")
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        # Count occurrences of "After Insert:" annotation
        after_insert = text.count('"After Insert:')
        # Should be exactly 1 (the legitimate one) not dozens
        assert after_insert <= 2, (
            f"STRINGS has {after_insert} 'After Insert:' annotations "
            f"(expected <= 2, was ~40+ before fix)")

    def test_gamesim_has_string_annotations(self):
        """GAMESIM should have meaningful string annotations."""
        path = os.path.join(OUTPUT_DIR, 'GAMESIM', 'decompiled.c')
        if not os.path.isfile(path):
            pytest.skip("GAMESIM output not available")
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        annotations = re.findall(r'/\*\s*"([^"]+)"\s*\*/', text)
        assert len(annotations) >= 20, (
            f"GAMESIM has only {len(annotations)} annotations, expected >= 20")

    def test_hello_has_writeln(self):
        """HELLO program should have WriteLn in decompiled output."""
        path = os.path.join(OUTPUT_DIR, 'HELLO', 'decompiled.c')
        if not os.path.isfile(path):
            pytest.skip("HELLO output not available")
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        # HELLO uses WriteLn('Hello, world.') — FLIRT should identify it,
        # or Decompile.java may have renamed it
        assert ('_Write_qm4Textm6String4Word' in text
                or '_WriteLn_qm4Text' in text
                or 'bp_write_str' in text
                or 'bp_writeln' in text), (
            "HELLO should have Write/WriteLn FLIRT functions (or renamed)")
