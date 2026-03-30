"""test_label_functions.py — Tests for function labeling output

Validates that Decompile.java applied correct labels, function renames,
and FLIRT identifications to decompiled output.
"""
import re
import os
import pytest
from conftest import OUTPUT_DIR


class TestEnhancedLabelOutput:
    """Verify that Decompile.java applied labels correctly."""

    def test_system_labels_present(self, decompiled_text, program):
        """Enhanced output should contain core System RTL labels."""
        core_labels = ['bp_module_init', 'bp_runtime_init', 'bp_stack_check',
                        'bp_char_out', 'bp_exit_handler', 'bp_halt_handler',
                        'bp_iocheck', 'bp_char_out_setup']
        found = sum(1 for label in core_labels if label in decompiled_text)
        assert found >= 2, (
            f"{program}: only {found}/{len(core_labels)} core labels found in output")

    def test_module_init_labeled(self, decompiled_text, program):
        """bp_module_init should appear in enhanced output."""
        assert 'bp_module_init' in decompiled_text, (
            f"{program} missing bp_module_init in output")

    def test_char_out_labeled(self, decompiled_text, program):
        """bp_char_out (offset 0232) should appear in enhanced output."""
        assert 'bp_char_out' in decompiled_text, (
            f"{program} missing bp_char_out in output")

    def test_has_label_annotations(self, decompiled_text, program):
        """Enhanced output should have inline label comments."""
        # Count lines with /* description */ annotations (not string annotations)
        label_comments = re.findall(r'/\*\s*(?!WARNING|")([\w\(\)].*?)\s*\*/',
                                     decompiled_text)
        assert len(label_comments) >= 5, (
            f"{program}: only {len(label_comments)} label comments, expected >= 5")

    def test_function_renames_applied(self, decompiled_text, program):
        """Enhanced output should have renamed functions (not all FUN_)."""
        # Count renamed vs unrenamed functions
        fun_refs = len(re.findall(r'\bFUN_[0-9a-f]+_[0-9a-f]+\b', decompiled_text))
        bp_refs = len(re.findall(r'\bbp_\w+\b', decompiled_text))
        assert bp_refs >= 10, (
            f"{program}: only {bp_refs} bp_ renamed references, expected >= 10")

    def test_ddplus_labels_in_ddtest(self):
        """DDPlus door driver functions should be labeled in DDTEST."""
        path = os.path.join(OUTPUT_DIR, 'DDTEST', 'decompiled.c')
        if not os.path.isfile(path):
            pytest.skip("DDTEST output not available")
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        expected_ddp = {
            'ddp_swriteln', 'ddp_swrite', 'ddp_sclrscr', 'ddp_sgoto_xy',
            'ddp_set_foreground', 'ddp_set_background', 'ddp_set_color',
            'ddp_swritec', 'ddp_sclreol', 'ddp_sendtext',
        }
        found = {label for label in expected_ddp if label in text}
        missing = expected_ddp - found
        assert not missing, (
            f"DDTEST missing DDPlus labels: {missing}")


class TestLabelCoverage:
    """Regression tests for label coverage on test programs."""

    # Programs that should have specific FLIRT-identified functions.
    # Decompile.java may rename these to short labels, so check for
    # either the original FLIRT name OR the decoded short name.
    EXPECTED_FLIRT = {
        'CRTTEST': [('_AssignCrt_qm4Text', 'crt_assigncrt'),
                    ('_Write_qm4Text4Char4Word', 'bp_write_char')],
        'DOSTEST': [('_DiskSize_q4Byte', 'dos_disksize'),
                    ('_FindNext_qm9SearchRec', 'dos_findnext')],
        'FILEIO':  [('_Delete_qm6String7Integert2', 'bp_delete'),
                    ('_Eof_qm4File', 'bp_eof')],
        'PTRMEM':  [('_Write_qm4Text7Boolean4Word', 'bp_write_bool'),
                    ('_Write_qm4Text7Longint4Word', 'bp_write_longint')],
        'RANDTEST': [('_Random_q4Word', 'bp_random')],
        'STRINGS': [('_Delete_qm6String7Integert2', 'bp_delete'),
                    ('_UpCase_q4Char', 'bp_upcase')],
    }

    @pytest.mark.parametrize('program,expected_fns', list(EXPECTED_FLIRT.items()))
    def test_expected_flirt_functions_present(self, program, expected_fns):
        """Programs using specific features should have corresponding FLIRT IDs."""
        path = os.path.join(OUTPUT_DIR, program, 'decompiled.c')
        if not os.path.isfile(path):
            pytest.skip(f"{program} output not available")
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        for flirt_name, short_name in expected_fns:
            assert flirt_name in text or short_name in text, (
                f"{program} missing expected FLIRT function: "
                f"{flirt_name} (or renamed {short_name})")

    def test_no_high_freq_unidentified(self, decompiled_text, program):
        """No FUN_* function with >10 references should remain unidentified."""
        all_funcs = re.findall(r'(FUN_[0-9a-f]+_[0-9a-f]+)', decompiled_text)
        counts = {}
        for f in all_funcs:
            counts[f] = counts.get(f, 0) + 1
        high_freq_unlabeled = [
            (name, count) for name, count in counts.items()
            if count > 10
        ]
        assert len(high_freq_unlabeled) == 0, (
            f"{program} has unlabeled high-frequency functions: "
            + ', '.join(f'{n}({c})' for n, c in high_freq_unlabeled))
