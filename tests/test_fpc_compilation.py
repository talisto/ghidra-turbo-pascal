"""test_fpc_compilation.py — Validate generated .pas files compile with Free Pascal.

Tests use Free Pascal Compiler (fpc) in Turbo Pascal compatibility mode (-Mtp).
The test is automatically skipped if fpc is not available.

This tracks which programs compile as a quality metric. Programs that currently
compile are enforced (regression); programs that don't compile yet are tracked
as expected failures.

A program is NOT considered successfully transpiled unless it compiles AND has
zero non-stub commented-out lines. Any commented-out code represents missing
functionality — the program won't behave like the original.
"""
import os
import re
import subprocess
import shutil
import tempfile
import pytest
from conftest import OUTPUT_DIR


# Check if FPC is available
FPC_PATH = shutil.which('fpc')
pytestmark = pytest.mark.skipif(FPC_PATH is None, reason='fpc not installed')


def _compile_pas(pas_path):
    """Compile a .pas file with FPC in TP mode. Returns (success, output)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [FPC_PATH, '-Mtp', '-Sc', '-o' + os.path.join(tmpdir, 'out'),
             pas_path],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0
        return success, output


def get_all_pas_programs():
    """Return list of program names that have .pas output."""
    progs = []
    for prog in sorted(os.listdir(OUTPUT_DIR)):
        pas_path = os.path.join(OUTPUT_DIR, prog, prog + '.pas')
        if os.path.isfile(pas_path):
            progs.append(prog)
    return progs


# Programs that currently compile (regression protection)
COMPILING_PROGRAMS = {
    'CONTROL',
    'CRTTEST',
    'DOSTEST',
    'EXITPROC',
    'GAMESIM',
    'HELLO',
    'MATHOPS',
    'OVRTEST',
    'PROCFUNC',
    'PTRMEM',
    'RANDTEST',
    'RECORDS',
    'STRINGS',
    'TYPECAST',
}

# Programs that are expected to fail (not yet fixed)
EXPECTED_FAILURES = {
    'DDTEST',   # needs external ddplus unit (not available in FPC)
    'FILEIO',
}


class TestFPCCompilation:
    """Test that generated .pas files compile with Free Pascal."""

    @pytest.fixture(autouse=True, scope='class')
    def _compile_results(self):
        """Compile all .pas files once per test class."""
        results = {}
        for prog in get_all_pas_programs():
            pas_path = os.path.join(OUTPUT_DIR, prog, prog + '.pas')
            success, output = _compile_pas(pas_path)
            results[prog] = {'success': success, 'output': output}
        self.__class__._results = results

    @pytest.mark.parametrize('program', sorted(COMPILING_PROGRAMS))
    def test_compiling_program(self, program):
        """Programs that currently compile must continue to compile."""
        if program not in self._results:
            pytest.skip(f'{program} not in output')
        result = self._results[program]
        assert result['success'], (
            f'{program} should compile but failed:\n{result["output"]}'
        )

    @pytest.mark.parametrize('program', sorted(EXPECTED_FAILURES))
    def test_expected_failure(self, program):
        """Track expected compilation failures — remove from this set when fixed."""
        if program not in self._results:
            pytest.skip(f'{program} not in output')
        result = self._results[program]
        if result['success']:
            pytest.fail(
                f'{program} now compiles! Remove it from EXPECTED_FAILURES '
                f'and add to COMPILING_PROGRAMS.'
            )

    def test_compilation_summary(self):
        """Print compilation summary for visibility."""
        compiled = [p for p, r in self._results.items() if r['success']]
        failed = [p for p, r in self._results.items() if not r['success']]
        total = len(self._results)
        pct = len(compiled) / total * 100 if total else 0
        # This test always passes — it's for reporting
        print(f'\n  FPC Compilation: {len(compiled)}/{total} ({pct:.0f}%)')
        if failed:
            print(f'  Failing: {", ".join(sorted(failed))}')

    def test_no_warnings_hello(self):
        """HELLO should compile with zero warnings."""
        if 'HELLO' not in self._results:
            pytest.skip('HELLO not in output')
        output = self._results['HELLO']['output']
        assert 'Warning' not in output


# ────────────────────────────────────────────────────────────────
# Output quality validation — hollow body detection
# ────────────────────────────────────────────────────────────────

def _count_commented_lines(pas_path):
    """Count non-stub commented lines in a .pas file.

    Every non-stub commented line represents missing functionality.
    Cross-segment stubs are excluded as they are expected placeholders.
    """
    count = 0
    with open(pas_path, encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if (stripped.startswith('{') and stripped.endswith('}')
                    and '{ cross-segment stub }' not in stripped):
                count += 1
    return count



# Programs that are successfully transpiled (compile + 0 non-stub commented lines).
# These must remain clean — any regression adds commented-out code = missing functionality.
CLEAN_PROGRAMS = {
    'CONTROL',
    'CRTTEST',
    'DDTEST',
    'EXITPROC',
    'GAMESIM',
    'HELLO',
    'MATHOPS',
    'OVRTEST',
    'TYPECAST',
}

# Programs that compile but have commented-out code (missing functionality).
# Move to CLEAN_PROGRAMS when all commented lines are resolved.
INCOMPLETE_PROGRAMS = {
    'DOSTEST',
    'PROCFUNC',
    'PTRMEM',
    'RANDTEST',
    'RECORDS',
    'STRINGS',
}


class TestOutputQuality:
    """Validate that .pas output quality meets tier definitions.

    A program is only successfully transpiled if it compiles AND has zero
    non-stub commented-out lines. Any commented-out code means missing
    functionality — the program won't behave like the original.
    """

    @pytest.mark.parametrize('program', sorted(CLEAN_PROGRAMS))
    def test_clean_program(self, program):
        """Clean programs must have zero non-stub commented lines."""
        pas_path = os.path.join(OUTPUT_DIR, program, program + '.pas')
        if not os.path.isfile(pas_path):
            pytest.skip(f'{program} not in output')
        commented = _count_commented_lines(pas_path)
        assert commented == 0, (
            f'{program} has {commented} non-stub commented lines — '
            f'each one is missing functionality'
        )

    @pytest.mark.parametrize('program', sorted(INCOMPLETE_PROGRAMS))
    def test_incomplete_program_tracked(self, program):
        """Incomplete programs must be tracked — move to CLEAN when fixed."""
        pas_path = os.path.join(OUTPUT_DIR, program, program + '.pas')
        if not os.path.isfile(pas_path):
            pytest.skip(f'{program} not in output')
        commented = _count_commented_lines(pas_path)
        if commented == 0:
            pytest.fail(
                f'{program} now has 0 commented lines! Move it from '
                f'INCOMPLETE_PROGRAMS to CLEAN_PROGRAMS.'
            )

    def test_quality_summary(self):
        """Print output quality summary for visibility."""
        clean = []
        incomplete = []
        for prog in sorted(get_all_pas_programs()):
            pas_path = os.path.join(OUTPUT_DIR, prog, prog + '.pas')
            commented = _count_commented_lines(pas_path)
            if commented == 0:
                clean.append(prog)
            else:
                incomplete.append(f'{prog}({commented})')
        total = len(clean) + len(incomplete)
        print(f'\n  Quality Tiers ({total} programs):')
        print(f'    Clean (0 commented):  {", ".join(clean) if clean else "none"}')
        print(f'    Incomplete (missing functionality): {", ".join(incomplete) if incomplete else "none"}')
