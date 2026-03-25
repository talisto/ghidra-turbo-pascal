"""conftest.py — Shared fixtures for BPdecompiler test suite."""
import os
import pytest
import sys

# Add project root to Python path so we can import the scripts
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUTPUT_DIR = os.path.join(ROOT, 'tests', 'output')
DATA_DIR = os.path.join(ROOT, 'tests', 'data')


def get_test_programs():
    """Return list of test program names that have decompiled output."""
    if not os.path.isdir(OUTPUT_DIR):
        return []
    return sorted(d for d in os.listdir(OUTPUT_DIR)
                  if os.path.isdir(os.path.join(OUTPUT_DIR, d))
                  and os.path.isfile(os.path.join(OUTPUT_DIR, d, 'decompiled.c')))


@pytest.fixture(params=get_test_programs())
def program(request):
    """Fixture that yields each test program name."""
    return request.param


@pytest.fixture
def decompiled_path(program):
    """Path to the decompiled.c for a program."""
    return os.path.join(OUTPUT_DIR, program, 'decompiled.c')


@pytest.fixture
def decompiled_text(decompiled_path):
    """Contents of decompiled.c."""
    with open(decompiled_path, encoding='utf-8', errors='replace') as f:
        return f.read()


@pytest.fixture
def annotated_path(program):
    """Path to the annotated output."""
    return os.path.join(OUTPUT_DIR, program, 'decompiled.annotated.c')


@pytest.fixture
def annotated_text(annotated_path):
    """Contents of decompiled.annotated.c."""
    with open(annotated_path, encoding='utf-8', errors='replace') as f:
        return f.read()


@pytest.fixture
def labeled_path(program):
    """Path to the labeled output."""
    return os.path.join(OUTPUT_DIR, program, 'decompiled.labeled.c')


@pytest.fixture
def labeled_text(labeled_path):
    """Contents of decompiled.labeled.c."""
    with open(labeled_path, encoding='utf-8', errors='replace') as f:
        return f.read()
