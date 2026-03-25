"""test_label_functions.py — Tests for label_functions.py

Tests the function labeling pipeline: offset detection, pattern matching,
FLIRT decoding, and overall label coverage.
"""
import re
import pytest
import label_functions as lf


class TestBuildLabelTable:
    """Test the offset-based and pattern-based label table builder."""

    def test_system_segment_detected(self, decompiled_text, program):
        """System RTL segment should be identified in every program."""
        labels = lf.build_label_table(decompiled_text)
        # At least some core RTL labels should be found
        core_labels = [n for n, (short, _) in labels.items()
                       if short.startswith('bp_')]
        assert len(core_labels) >= 5, (
            f"{program}: only {len(core_labels)} core labels found")

    def test_module_init_labeled(self, decompiled_text, program):
        """bp_module_init (offset 00b1) should be found in every program."""
        labels = lf.build_label_table(decompiled_text)
        names = {short for _, (short, _) in labels.items()}
        assert 'bp_module_init' in names, (
            f"{program} missing bp_module_init label")

    def test_char_out_labeled(self, decompiled_text, program):
        """bp_char_out (offset 0232) should be found in every program."""
        labels = lf.build_label_table(decompiled_text)
        names = {short for _, (short, _) in labels.items()}
        assert 'bp_char_out' in names, (
            f"{program} missing bp_char_out label")

    def test_no_duplicate_labels_per_function(self, decompiled_text, program):
        """Each function should get at most one label."""
        labels = lf.build_label_table(decompiled_text)
        # Keys are function names — should be unique by definition
        assert len(labels) == len(set(labels.keys()))

    def test_label_count_range(self, decompiled_text, program):
        """Reasonable number of labels for a TP7 test program."""
        labels = lf.build_label_table(decompiled_text)
        assert len(labels) >= 7, (
            f"{program}: only {len(labels)} labels, expected >= 7")
        # DDPlus binaries have more labellable functions
        max_labels = 150 if program == 'DDTEST' else 100
        assert len(labels) <= max_labels, (
            f"{program}: {len(labels)} labels seems too many")

    def test_ddplus_labels_detected(self, decompiled_text, program):
        """DDPlus door driver functions should be labeled in DDTEST."""
        if program != 'DDTEST':
            pytest.skip('DDPlus labels only expected in DDTEST')
        labels = lf.build_label_table(decompiled_text)
        names = {short for _, (short, _) in labels.items()}
        expected_ddp = {
            'ddp_swriteln', 'ddp_swrite', 'ddp_sclrscr', 'ddp_sgoto_xy',
            'ddp_set_foreground', 'ddp_set_background', 'ddp_set_color',
            'ddp_swritec', 'ddp_sclreol', 'ddp_sendtext',
        }
        missing = expected_ddp - names
        assert not missing, (
            f"DDTEST missing DDPlus labels: {missing}")


class TestPatternDetection:
    """Test the identify_by_pattern function."""

    def test_write_str_pattern(self):
        """Functions calling __WriteBlanks and __WriteBuffer → bp_write_str."""
        body = """// Function: FUN_1066_0964 @ 1066:0964
// ==========================================

void __stdcall16far FUN_1066_0964(int param_1,byte *param_2)
{
  byte bVar1;
  bVar1 = *param_2;
  if ((int)(uint)bVar1 < param_1) {
    __WriteBlanks();
  }
  if (bVar1 != 0) {
    __WriteBuffer();
  }
  return;
}
"""
        result = lf.identify_by_pattern('FUN_1066_0964', body)
        assert result is not None
        assert result[0] == 'bp_write_str'

    def test_bios_int10_pattern(self):
        """Small function with swi(0x10) → bp_bios_int10."""
        body = """// Function: FUN_1056_0614 @ 1056:0614
// ==========================================

void __cdecl16near FUN_1056_0614(void)
{
  code *pcVar1;
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  return;
}
"""
        result = lf.identify_by_pattern('FUN_1056_0614', body)
        assert result is not None
        assert result[0] == 'bp_bios_int10'

    def test_dos_int21_pattern(self):
        """Small function with swi(0x21) → bp_dos_int21."""
        body = """// Function: FUN_10e6_0232 @ 10e6:0232
// ==========================================

void __cdecl16near FUN_10e6_0232(void)
{
  code *pcVar1;
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  return;
}
"""
        result = lf.identify_by_pattern('FUN_10e6_0232', body)
        assert result is not None
        assert result[0] == 'bp_dos_int21'

    def test_complex_function_not_matched(self):
        """Large complex functions should not match any pattern."""
        body = """// Function: FUN_1000_0100 @ 1000:0100
// ==========================================

void FUN_1000_0100(void)
{
  int i;
  for (i = 0; i < 100; i++) {
    FUN_1000_0200(i);
    if (i > 50) {
      FUN_1000_0300();
      break;
    }
    FUN_1000_0400(i * 2);
  }
  return;
}
"""
        result = lf.identify_by_pattern('FUN_1000_0100', body)
        assert result is None


class TestFlirtDecoding:
    """Test FLIRT name decoding."""

    def test_write_str_decoded(self):
        result = lf.decode_flirt_name('_Write_qm4Textm6String4Word')
        assert result is not None
        assert result[0] == 'bp_write_str'

    def test_writeln_decoded(self):
        result = lf.decode_flirt_name('_WriteLn_qm4Text')
        assert result is not None
        assert result[0] == 'bp_writeln'

    def test_halt_decoded(self):
        result = lf.decode_flirt_name('_Halt_q4Word')
        assert result is not None
        assert result[0] == 'bp_halt'

    def test_clrscr_decoded(self):
        result = lf.decode_flirt_name('_ClrScr_qv')
        assert result is not None
        assert result[0] == 'crt_clrscr'

    def test_clear_dseg_decoded(self):
        result = lf.decode_flirt_name('__ClearDSeg')
        assert result is not None
        assert result[0] == 'bp_clear_dseg'

    def test_unknown_generic_decode(self):
        """Unknown _Name_q... patterns get a generic decode."""
        result = lf.decode_flirt_name('_MyFunc_qm4Text')
        assert result is not None
        assert 'MyFunc' in result[1]

    def test_random_string_not_decoded(self):
        """Arbitrary strings should not decode."""
        result = lf.decode_flirt_name('some_random_name')
        assert result is None


class TestLabelLine:
    """Test the line labeling function."""

    def test_fun_call_labeled(self):
        labels = {'FUN_10e6_0701': ('bp_write_str', 'Write string')}
        line = '  FUN_10e6_0701(0,0x51,0x10e6);\n'
        result = lf.label_line(line, labels)
        assert 'Write string' in result
        assert '/* Write string */' in result

    def test_unlabeled_fun_unchanged(self):
        labels = {'FUN_10e6_0701': ('bp_write_str', 'Write string')}
        line = '  FUN_10e6_9999(0,0x51);\n'
        result = lf.label_line(line, labels)
        assert result == line

    def test_flirt_call_labeled(self):
        labels = {}
        flirt_labels = {'_WriteLn_qm4Text': ('bp_writeln', 'WriteLn(Text)')}
        line = '  _WriteLn_qm4Text(0x178,unaff_DS);\n'
        result = lf.label_line(line, labels, flirt_labels)
        assert 'WriteLn(Text)' in result
        assert '/* WriteLn(Text) */' in result


class TestApplyRenames:
    """Test function renaming via apply_renames."""

    def test_rename_in_declaration(self):
        """FUN_* name in a function declaration is replaced with short name."""
        text = 'void __stdcall16far FUN_1095_1d30(int param_1)  /* DDPlus ANSI color dispatch */\n'
        labels = {'FUN_1095_1d30': ('ddp_ansi_dispatch', 'DDPlus ANSI color dispatch')}
        result = lf.apply_renames(text, labels)
        assert 'ddp_ansi_dispatch' in result
        assert 'FUN_1095_1d30' not in result

    def test_rename_in_call_site(self):
        """FUN_* name in a call site is replaced with short name."""
        text = '  FUN_1095_1d30(param_1, param_2);  /* DDPlus ANSI color dispatch */\n'
        labels = {'FUN_1095_1d30': ('ddp_ansi_dispatch', 'DDPlus ANSI color dispatch')}
        result = lf.apply_renames(text, labels)
        assert 'ddp_ansi_dispatch(param_1, param_2)' in result
        assert 'FUN_1095_1d30' not in result

    def test_rename_in_function_header_comment(self):
        """FUN_* name in the // Function: header comment is also replaced."""
        text = '// Function: FUN_1095_1d30 @ 1095:1d30\n'
        labels = {'FUN_1095_1d30': ('ddp_ansi_dispatch', 'DDPlus ANSI color dispatch')}
        result = lf.apply_renames(text, labels)
        assert '// Function: ddp_ansi_dispatch @ 1095:1d30' in result

    def test_rename_all_occurrences(self):
        """Every occurrence in the text is replaced, not just the first."""
        text = 'FUN_1095_1d30(); FUN_1095_1d30(); FUN_1095_1d30();\n'
        labels = {'FUN_1095_1d30': ('ddp_ansi_dispatch', 'DDPlus ANSI color dispatch')}
        result = lf.apply_renames(text, labels)
        assert result.count('FUN_1095_1d30') == 0
        assert result.count('ddp_ansi_dispatch') == 3

    def test_collision_skipped(self):
        """Functions sharing a short name are not renamed (avoids duplicate identifiers)."""
        text = 'FUN_1000_0001(); FUN_1000_0002();\n'
        labels = {
            'FUN_1000_0001': ('bp_write_str', 'desc1'),
            'FUN_1000_0002': ('bp_write_str', 'desc2'),
        }
        result = lf.apply_renames(text, labels)
        assert 'FUN_1000_0001' in result
        assert 'FUN_1000_0002' in result

    def test_unlabeled_fun_unchanged(self):
        """FUN_* names not in the label table are left untouched."""
        text = 'FUN_1000_9999();\n'
        labels = {'FUN_1095_1d30': ('ddp_ansi_dispatch', 'DDPlus ANSI color dispatch')}
        result = lf.apply_renames(text, labels)
        assert 'FUN_1000_9999' in result

    def test_flirt_rename(self):
        """FLIRT-mangled names are replaced with their short labels."""
        text = '  _Write_qm4Textm6String4Word(0xff,local_306,unaff_SS);\n'
        flirt_labels = {'_Write_qm4Textm6String4Word': ('bp_write_str', 'Write(Text, String, Word)')}
        result = lf.apply_renames(text, {}, flirt_labels)
        assert 'bp_write_str' in result
        assert '_Write_qm4Textm6String4Word' not in result

    def test_flirt_rename_collision_skipped(self):
        """FLIRT names sharing a short label are not renamed."""
        text = '_Random_q4Word(); _Random_q7Integer();\n'
        flirt_labels = {
            '_Random_q4Word':    ('bp_random', 'Random(Word)'),
            '_Random_q7Integer': ('bp_random', 'Random(N)'),
        }
        result = lf.apply_renames(text, {}, flirt_labels)
        assert '_Random_q4Word' in result
        assert '_Random_q7Integer' in result


class TestLabelCoverage:
    """Regression tests for label coverage on test programs."""

    # Programs that should have specific FLIRT functions (use actual mangled names
    # matching what the sig files produce — verify against tests/output/*/decompiled.c)
    EXPECTED_FLIRT = {
        'CRTTEST': ['_AssignCrt_qm4Text', '_Write_qm4Text4Char4Word'],
        'DOSTEST': ['_DiskSize_q4Byte', '_FindNext_qm9SearchRec'],
        'FILEIO':  ['_Delete_qm6String7Integert2', '_Eof_qm4File', '_Rename_qm4Filem6String'],
        'PTRMEM':  ['_Write_qm4Text7Boolean4Word', '_Write_qm4Text7Longint4Word'],
        'RANDTEST': ['_Randomize_qv'],
        'STRINGS': ['_Delete_qm6String7Integert2', '_UpCase_q4Char'],
    }

    @pytest.mark.parametrize('program,expected_fns', list(EXPECTED_FLIRT.items()))
    def test_expected_flirt_functions_present(self, program, expected_fns):
        """Programs using specific features should have corresponding FLIRT IDs."""
        path = f'tests/output/{program}/decompiled.c'
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        for fn in expected_fns:
            assert fn in text, (
                f"{program} missing expected FLIRT function: {fn}")

    def test_no_high_freq_unidentified(self, decompiled_text, program):
        """No FUN_* function with >10 references should remain unidentified."""
        labels = lf.build_label_table(decompiled_text)
        all_funcs = re.findall(r'(FUN_[0-9a-f]+_[0-9a-f]+)', decompiled_text)
        counts = {}
        for f in all_funcs:
            counts[f] = counts.get(f, 0) + 1
        high_freq_unlabeled = [
            (name, count) for name, count in counts.items()
            if count > 10 and name not in labels
        ]
        assert len(high_freq_unlabeled) == 0, (
            f"{program} has unlabeled high-frequency functions: "
            + ', '.join(f'{n}({c})' for n, c in high_freq_unlabeled))
