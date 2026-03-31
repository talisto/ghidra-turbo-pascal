"""test_fpc_compilation.py — Validate generated .pas files compile with Free Pascal.

Tests use Free Pascal Compiler (fpc) in Turbo Pascal compatibility mode (-Mtp).
The test is automatically skipped if fpc is not available.

This tracks which programs compile as a quality metric. Programs that currently
compile are enforced (regression); programs that don't compile yet are tracked
as expected failures.
"""
import os
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
    'DDTEST',
    'DOSTEST',
    'EXITPROC',
    'GAMESIM',
    'HELLO',
    'MATHOPS',
    'OVRTEST',
    'RANDTEST',
    'STRINGS',
    'TYPECAST',
}

# Programs that are expected to fail (not yet fixed)
EXPECTED_FAILURES = {
    'FILEIO',
    'PROCFUNC',
    'PTRMEM',
    'RECORDS',
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
