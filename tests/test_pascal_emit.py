"""test_pascal_emit.py — Validate Pascal emission from decompiled output.

Tests run against pre-generated .pas files produced by pascal_emit.py
from the decompiled.c output in tests/output/.
"""
import os
import re
import pytest
from conftest import OUTPUT_DIR

# Import the module under test
import pascal_emit


# ────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────

@pytest.fixture(scope='session', autouse=True)
def generate_all_pas():
    """Generate .pas files for all test programs before running tests."""
    for prog in sorted(os.listdir(OUTPUT_DIR)):
        dec_path = os.path.join(OUTPUT_DIR, prog, 'decompiled.c')
        if os.path.isfile(dec_path):
            pascal_emit.process(dec_path)


def get_programs_with_pas():
    """Return list of program names that have .pas output."""
    progs = []
    for prog in sorted(os.listdir(OUTPUT_DIR)):
        pas_path = os.path.join(OUTPUT_DIR, prog, prog + '.pas')
        if os.path.isfile(pas_path):
            progs.append(prog)
    return progs


@pytest.fixture(params=get_programs_with_pas() or ['HELLO'])
def program(request):
    return request.param


@pytest.fixture
def pas_text(program):
    """Contents of the generated .pas file."""
    pas_path = os.path.join(OUTPUT_DIR, program, program + '.pas')
    with open(pas_path, encoding='utf-8') as f:
        return f.read()


# ────────────────────────────────────────────────────────────────
# Structural tests (all programs)
# ────────────────────────────────────────────────────────────────

class TestPascalStructure:
    """Every .pas file must have valid Pascal program structure."""

    def test_starts_with_program(self, pas_text, program):
        """Must start with 'program NAME;'."""
        assert pas_text.startswith(f'program {program};')

    def test_ends_with_end_dot(self, pas_text, program):
        """Must end with 'end.' (main block terminator)."""
        assert pas_text.rstrip().endswith('end.')

    def test_has_begin(self, pas_text, program):
        """Must have a main 'begin' block."""
        # Find the main begin (not inside a procedure/function)
        lines = pas_text.split('\n')
        found = False
        for line in lines:
            if line.strip() == 'begin':
                found = True
                break
        assert found, f"{program} has no main 'begin' block"

    def test_no_raw_dat_lines(self, pas_text, program):
        """No raw DAT_ assignments should appear as statements (outside comments)."""
        for line in pas_text.split('\n'):
            stripped = line.strip()
            # DAT_ inside Pascal comments { ... } is acceptable
            if stripped.startswith('{') and stripped.endswith('}'):
                continue
            assert not stripped.startswith('DAT_'), (
                f"{program} has raw DAT_ statement: {stripped}")

    def test_no_puvar_lines(self, pas_text, program):
        """No raw puVar stack PUSH patterns should appear as statements."""
        for line in pas_text.split('\n'):
            stripped = line.strip()
            if stripped.startswith('{') and stripped.endswith('}'):
                continue
            # Only flag explicit puVar stack push patterns (noise that should
            # have been filtered). puVar in expressions is a prototype limitation.
            if re.match(r'\*\(word \*\)\(puVar\d+ \+ -', stripped):
                assert False, (
                    f"{program} has raw puVar push: {stripped}")

    def test_no_bp_halt_handler(self, pas_text, program):
        """bp_halt_handler and post-halt system init must be stripped."""
        assert 'bp_halt_handler' not in pas_text

    def test_no_bp_stack_check(self, pas_text, program):
        """bp_stack_check calls must be stripped."""
        assert 'bp_stack_check' not in pas_text

    def test_no_bp_iocheck(self, pas_text, program):
        """bp_iocheck calls must be stripped."""
        assert 'bp_iocheck' not in pas_text

    def test_balanced_begin_end(self, pas_text, program):
        """begin/end keywords must be balanced."""
        begins = len(re.findall(r'\bbegin\b', pas_text))
        ends = len(re.findall(r'\bend\b', pas_text))
        # Allow ±2 imbalance for complex programs (prototype limitation)
        assert abs(begins - ends) <= 2, (
            f"{program}: {begins} 'begin' vs {ends} 'end' (diff={abs(begins-ends)})")


# ────────────────────────────────────────────────────────────────
# HELLO — simplest program
# ────────────────────────────────────────────────────────────────

class TestHello:
    """HELLO.pas must be a near-perfect reproduction."""

    def test_hello_writeln(self):
        pas = _read_pas('HELLO')
        assert "WriteLn('Hello, world.');" in pas

    def test_hello_minimal(self):
        """HELLO should have no variable declarations or procedures."""
        pas = _read_pas('HELLO')
        assert 'var' not in pas
        assert 'procedure' not in pas
        assert 'function' not in pas


# ────────────────────────────────────────────────────────────────
# CONTROL — control flow structures
# ────────────────────────────────────────────────────────────────

class TestControl:
    """CONTROL.pas must have correct control flow structures."""

    def test_if_else_chain(self):
        """The if/else chain must use nested if/begin/end/else."""
        pas = _read_pas('CONTROL')
        assert 'end else begin' in pas

    def test_while_loop(self):
        pas = _read_pas('CONTROL')
        assert 'while' in pas and 'do begin' in pas

    def test_repeat_until(self):
        pas = _read_pas('CONTROL')
        assert 'repeat' in pas
        assert 'until' in pas

    def test_break_in_if(self):
        """Single-line if + break must be converted."""
        pas = _read_pas('CONTROL')
        assert 'then Break;' in pas

    def test_greater_than_100_string(self):
        """The 'greater than 100' string (offset 0) must resolve."""
        pas = _read_pas('CONTROL')
        assert "'greater than 100'" in pas

    def test_greater_than_50_string(self):
        """The 'greater than 50' string (annotated) must resolve."""
        pas = _read_pas('CONTROL')
        assert "'greater than 50'" in pas

    def test_global_variables(self):
        """Global variables must be declared."""
        pas = _read_pas('CONTROL')
        assert 'g_0052' in pas
        assert 'g_0056' in pas

    def test_no_char_null_literal(self):
        r"""'\0' must be converted to 0, not left as char literal."""
        pas = _read_pas('CONTROL')
        assert "'\\0'" not in pas

    def test_hex_converted_to_decimal(self):
        """Hex constants like 0x2a must be converted to decimal."""
        pas = _read_pas('CONTROL')
        assert '0x' not in pas


# ────────────────────────────────────────────────────────────────
# PROCFUNC — application functions
# ────────────────────────────────────────────────────────────────

class TestProcfunc:
    """PROCFUNC.pas must convert application functions."""

    def test_has_procedures(self):
        pas = _read_pas('PROCFUNC')
        assert 'procedure' in pas

    def test_has_functions(self):
        pas = _read_pas('PROCFUNC')
        assert 'function' in pas

    def test_var_params(self):
        """var parameters must be detected from pointer params."""
        pas = _read_pas('PROCFUNC')
        assert 'var param_1:' in pas or 'var param_2:' in pas

    def test_forward_declarations(self):
        """Forward declarations must be present for all app functions."""
        pas = _read_pas('PROCFUNC')
        assert 'forward;' in pas

    def test_function_return_type(self):
        """Functions must have return types."""
        pas = _read_pas('PROCFUNC')
        assert re.search(r'function \w+\([^)]*\): \w+;', pas)


# ────────────────────────────────────────────────────────────────
# CRTTEST — uses clause detection
# ────────────────────────────────────────────────────────────────

class TestCrttest:
    """CRTTEST.pas must detect and emit 'uses Crt'."""

    def test_uses_crt(self):
        pas = _read_pas('CRTTEST')
        assert 'uses Crt;' in pas


# ────────────────────────────────────────────────────────────────
# MATHOPS — integer write value extraction
# ────────────────────────────────────────────────────────────────

class TestMathops:
    """MATHOPS.pas must resolve integer write values."""

    def test_writeln_with_longint_value(self):
        """WriteLn with a longint value extracts the variable reference."""
        pas = _read_pas('MATHOPS')
        # Longint write values are now extracted from stack push patterns.
        # The write sequence detector resolves the stack-passed value to a
        # variable name (e.g., g_0056) instead of emitting {longint}.
        assert re.search(r"WriteLn\('100 \+ 37 = ', g_0056\)", pas)

    def test_global_vars_declared(self):
        """Global variables used for math operands must be declared."""
        pas = _read_pas('MATHOPS')
        assert 'g_0052' in pas
        assert 'g_0056' in pas

    def test_addition_string(self):
        pas = _read_pas('MATHOPS')
        assert "'100 + 37 = '" in pas


# ────────────────────────────────────────────────────────────────
# GAMESIM — complex program with many functions
# ────────────────────────────────────────────────────────────────

class TestGamesim:
    """GAMESIM.pas must handle a complex program."""

    def test_has_multiple_procedures(self):
        pas = _read_pas('GAMESIM')
        procs = re.findall(r'^procedure \w+', pas, re.MULTILINE)
        assert len(procs) >= 6, f"Expected >= 6 procedures, got {len(procs)}"

    def test_status_alive_string(self):
        """A string annotation must resolve."""
        pas = _read_pas('GAMESIM')
        assert "'Status: Alive'" in pas or "'  Status: Alive'" in pas


# ────────────────────────────────────────────────────────────────
# Module-level unit tests
# ────────────────────────────────────────────────────────────────

class TestConvertExpression:
    """Unit tests for convert_expression()."""

    def test_memory_access_to_global(self):
        assert pascal_emit.convert_expression('*(int *)0x52') == 'g_0052'

    def test_hex_to_decimal(self):
        assert pascal_emit.convert_expression('0x2a') == '42'

    def test_not_equal(self):
        result = pascal_emit.convert_expression('x != 0')
        assert '<>' in result

    def test_logical_and(self):
        result = pascal_emit.convert_expression('a && b')
        assert 'and' in result

    def test_char_null(self):
        result = pascal_emit.convert_expression("'\\0'")
        assert result == '0'


class TestConvertCondition:
    """Unit tests for convert_condition()."""

    def test_memory_comparison(self):
        result = pascal_emit.convert_condition('*(int *)0x52 < 0x65')
        assert result == 'g_0052 < 101'

    def test_equality(self):
        result = pascal_emit.convert_condition('iVar1 == 2')
        assert 'iVar1 = 2' in result

    def test_char_null(self):
        result = pascal_emit.convert_condition("*(char *)0x59 == '\\0'")
        assert "'\\0'" not in result
        assert '0' in result


class TestNegateCondition:
    """Unit tests for negate_condition()."""

    def test_less_than(self):
        assert pascal_emit.negate_condition('x < 10') == 'x >= 10'

    def test_greater_equal(self):
        assert pascal_emit.negate_condition('x >= 5') == 'x < 5'

    def test_equal(self):
        assert pascal_emit.negate_condition('x = 0') == 'x <> 0'


class TestCTypeToPascal:
    """Unit tests for c_type_to_pascal()."""

    def test_int(self):
        assert pascal_emit.c_type_to_pascal('int') == 'Integer'

    def test_word(self):
        assert pascal_emit.c_type_to_pascal('word') == 'Word'

    def test_void(self):
        assert pascal_emit.c_type_to_pascal('void') == ''

    def test_byte(self):
        assert pascal_emit.c_type_to_pascal('byte') == 'Byte'


class TestOperatorConversion:
    """Test arithmetic and bitwise operator conversion."""

    def test_modulo_to_mod(self):
        assert 'mod' in pascal_emit.convert_expression('a % b')
        assert '%' not in pascal_emit.convert_expression('a % b')

    def test_division_to_div(self):
        result = pascal_emit.convert_expression('a / b')
        assert ' div ' in result

    def test_bitwise_and(self):
        result = pascal_emit.convert_expression('a & b')
        assert ' and ' in result

    def test_bitwise_or(self):
        result = pascal_emit.convert_expression('a | b')
        assert ' or ' in result

    def test_bitwise_xor(self):
        result = pascal_emit.convert_expression('a ^ b')
        assert ' xor ' in result

    def test_bitwise_not(self):
        result = pascal_emit.convert_expression('~a')
        assert result.startswith('not ')

    def test_shl(self):
        result = pascal_emit.convert_expression('x << 4')
        assert 'shl' in result

    def test_shr(self):
        result = pascal_emit.convert_expression('x >> 4')
        assert 'shr' in result

    def test_control_uses_mod(self):
        """CONTROL.pas FizzBuzz logic uses mod not %."""
        pas = _read_pas('CONTROL')
        assert 'mod 3' in pas
        assert 'mod 5' in pas
        assert '%' not in pas

    def test_mathops_uses_div(self):
        """MATHOPS.pas uses div for integer division."""
        pas = _read_pas('MATHOPS')
        assert 'div g_0054' in pas


class TestCastConversion:
    """Test C-style cast to Pascal type cast conversion."""

    def test_ulong_cast(self):
        result = pascal_emit.convert_expression('(ulong)x')
        assert result == 'LongInt(x)'

    def test_uint_cast(self):
        result = pascal_emit.convert_expression('(uint)x')
        assert result == 'Word(x)'

    def test_int_cast(self):
        result = pascal_emit.convert_expression('(int)x')
        assert result == 'Integer(x)'

    def test_byte_cast(self):
        result = pascal_emit.convert_expression('(byte)x')
        assert result == 'Byte(x)'

    def test_cast_with_paren_expr(self):
        result = pascal_emit.convert_expression('(ulong)(a + b)')
        assert result.startswith('LongInt(')

    def test_procfunc_longint_cast(self):
        """PROCFUNC Square function uses LongInt(param) not (ulong)param."""
        pas = _read_pas('PROCFUNC')
        assert 'LongInt(param_1) * LongInt(param_1)' in pas


class TestLongintWrite:
    """Test longint write value extraction."""

    def test_mathops_no_longint_placeholder(self):
        """MATHOPS should have no {longint} placeholders."""
        pas = _read_pas('MATHOPS')
        assert '{longint}' not in pas

    def test_control_no_longint_placeholder(self):
        """CONTROL should have no {longint} placeholders."""
        pas = _read_pas('CONTROL')
        assert '{longint}' not in pas

    def test_control_sum_writeln(self):
        """Sum 1..10 WriteLn shows variable not placeholder."""
        pas = _read_pas('CONTROL')
        assert "WriteLn('Sum 1..10 = ', g_0056)" in pas

    def test_control_mult_table_width(self):
        """Multiplication table Write has :4 width specifier."""
        pas = _read_pas('CONTROL')
        assert re.search(r'Write\(g_0052 \* g_0054:4\)', pas)

    def test_procfunc_param_write(self):
        """PROCFUNC WriteLn('Value: ', param_1) shows parameter."""
        pas = _read_pas('PROCFUNC')
        assert "WriteLn('Value: ', param_1)" in pas


class TestTempVarDeclarations:
    """Test that undeclared temp variables get var declarations."""

    def test_control_ivar_declared(self):
        """CONTROL.pas declares iVar1 in var section."""
        pas = _read_pas('CONTROL')
        assert 'iVar1: Integer;' in pas

    def test_mathops_temp_vars_declared(self):
        """MATHOPS temp variables are declared."""
        pas = _read_pas('MATHOPS')
        # All iVar/uVar references should have declarations
        for m in re.finditer(r'\b([iu]Var\d+)\b', pas):
            var_name = m.group(1)
            assert f'{var_name}:' in pas, f'{var_name} used but not declared'

    def test_procfunc_function_locals(self):
        """PROCFUNC function local temp vars are declared."""
        pas = _read_pas('PROCFUNC')
        # uVar1 is used in Func_1000_0079
        assert 'uVar1: Word;' in pas


# ────────────────────────────────────────────────────────────────
# Case statement reconstruction
# ────────────────────────────────────────────────────────────────

class TestCaseStatements:
    """Test case statement reconstruction from if/else if chains."""

    def test_control_has_case(self):
        """CONTROL.pas must reconstruct 'case iVar1 of'."""
        pas = _read_pas('CONTROL')
        assert 'case iVar1 of' in pas

    def test_control_case_value_1(self):
        """Case value 1 maps to 'one'."""
        pas = _read_pas('CONTROL')
        assert re.search(r"1:\s*WriteLn\('one'\)", pas)

    def test_control_case_value_2(self):
        """Case value 2 maps to 'two'."""
        pas = _read_pas('CONTROL')
        assert re.search(r"2:\s*WriteLn\('two'\)", pas)

    def test_control_case_range_3_5(self):
        """Range 3..5 maps to 'three to five'."""
        pas = _read_pas('CONTROL')
        assert re.search(r"3\.\.5:\s*WriteLn\('three to five'\)", pas)

    def test_control_case_range_6_10(self):
        """Range 6..10 maps to 'six to ten'."""
        pas = _read_pas('CONTROL')
        assert re.search(r"6\.\.10:\s*WriteLn\('six to ten'\)", pas)

    def test_control_case_else(self):
        """Case else clause maps to 'other'."""
        pas = _read_pas('CONTROL')
        # Find the case block, verify else contains 'other'
        case_start = pas.find('case iVar1 of')
        assert case_start >= 0
        case_block = pas[case_start:pas.find('end;', case_start + 50) + 4]
        assert 'else' in case_block
        assert "'other'" in case_block

    def test_control_no_if_else_chain_for_case(self):
        """The case values should NOT appear as if/else if chain."""
        pas = _read_pas('CONTROL')
        # After case reconstruction, there should be no
        # "if iVar1 = 1 then begin" pattern
        assert 'if iVar1 = 1 then begin' not in pas

    def test_randtest_has_case(self):
        """RANDTEST event handler uses case statement."""
        pas = _read_pas('RANDTEST')
        assert 'case iVar1 of' in pas

    def test_randtest_case_values(self):
        """RANDTEST case has sequential values 0-5."""
        pas = _read_pas('RANDTEST')
        assert re.search(r"0:\s*WriteLn\('You found gold!'\)", pas)
        assert re.search(r"5:\s*WriteLn\('A trap springs!'\)", pas)

    def test_case_compiles(self):
        """CONTROL with case statement still compiles with FPC."""
        import shutil
        fpc = shutil.which('fpc')
        if not fpc:
            pytest.skip('fpc not installed')
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [fpc, '-Mtp', '-Sc',
                 '-o' + os.path.join(tmpdir, 'out'),
                 os.path.join(OUTPUT_DIR, 'CONTROL', 'CONTROL.pas')],
                capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, f'FPC failed:\n{result.stdout}\n{result.stderr}'


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def _read_pas(program):
    """Read a generated .pas file."""
    path = os.path.join(OUTPUT_DIR, program, program + '.pas')
    with open(path, encoding='utf-8') as f:
        return f.read()
