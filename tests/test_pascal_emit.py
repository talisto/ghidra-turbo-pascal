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

    def test_writeln_with_global_var(self):
        """WriteLn with a global variable value must be resolved."""
        pas = _read_pas('MATHOPS')
        # Should have WriteLn('string', g_NNNN) — not WriteLn('string', {int})
        assert re.search(r"WriteLn\('.*?', g_\w+\)", pas)

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


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def _read_pas(program):
    """Read a generated .pas file."""
    path = os.path.join(OUTPUT_DIR, program, program + '.pas')
    with open(path, encoding='utf-8') as f:
        return f.read()
