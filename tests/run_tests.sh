#!/usr/bin/env bash
# run_tests.sh — Run the decompiler pipeline on all test EXEs and validate output
#
# Usage:
#   tests/run_tests.sh [--verbose]
#
# Each .EXE file in tests/data/ is run through the full pipeline.
# Basic validation checks are performed on the output.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
OUTPUT_DIR="$SCRIPT_DIR/output"
DECOMPILE="$PROJECT_DIR/decompile.sh"

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

passed=0
failed=0
skipped=0
errors=""

echo "=== BPdecompiler Test Suite ==="
echo "  Data dir:   $DATA_DIR"
echo "  Output dir: $OUTPUT_DIR"
echo ""

# Ensure decompile.sh is executable
chmod +x "$DECOMPILE"

# Find all EXE files
shopt -s nullglob
exe_files=("$DATA_DIR"/*.EXE "$DATA_DIR"/*.exe)
shopt -u nullglob

if [[ ${#exe_files[@]} -eq 0 ]]; then
    echo "No .EXE files found in $DATA_DIR"
    echo "Compile the .PAS source files using Turbo Pascal 7 in DOSBox first."
    exit 1
fi

echo "Found ${#exe_files[@]} test binaries."
echo ""

for exe_file in "${exe_files[@]}"; do
    exe_name="$(basename "$exe_file" | sed 's/\.[eE][xX][eE]$//')"
    test_output="$OUTPUT_DIR/$exe_name"

    echo "--- Testing: $exe_name ---"

    # Run the decompiler
    mkdir -p "$test_output"
    if ! "$DECOMPILE" --sigs --output "$test_output" "$exe_file" > "$test_output/pipeline.log" 2>&1; then
        echo "  FAIL: Pipeline returned non-zero exit code"
        errors="$errors\n  $exe_name: pipeline error"
        failed=$((failed + 1))
        if [[ "$VERBOSE" == "true" ]]; then
            tail -20 "$test_output/pipeline.log"
        fi
        continue
    fi

    # Validate output files exist
    decompiled="$test_output/decompiled.c"


    if [[ ! -f "$decompiled" ]]; then
        echo "  FAIL: decompiled.c not created"
        errors="$errors\n  $exe_name: decompiled.c missing"
        failed=$((failed + 1))
        continue
    fi

    # Count functions and lines
    func_count=$(grep -c "^// Function:" "$decompiled" 2>/dev/null || echo "0")
    line_count=$(wc -l < "$decompiled" | tr -d ' ')

    # Validate minimum function count (even HELLO.EXE has 30 functions)
    if [[ "$func_count" -lt 5 ]]; then
        echo "  FAIL: Only $func_count functions decompiled (expected >= 5)"
        errors="$errors\n  $exe_name: too few functions ($func_count)"
        failed=$((failed + 1))
        continue
    fi

    # Count annotations and labels in decompiled.c
    ann_lines=$(grep -c '/\*.*".*"\s*\*/' "$decompiled" 2>/dev/null || echo "0")
    label_lines=$(grep -c 'bp_\|crt_\|dos_\|rhp_\|ovr_' "$decompiled" 2>/dev/null || echo "0")

    # Check for the PAS source to verify expected features
    pas_file="$DATA_DIR/$exe_name.PAS"
    expected_features=""
    if [[ -f "$pas_file" ]]; then
        # Check if the source uses specific features
        if grep -qi "writeln" "$pas_file"; then
            expected_features="$expected_features writeln"
        fi
        if grep -qi "random" "$pas_file"; then
            expected_features="$expected_features random"
        fi
        if grep -qi "uses Crt" "$pas_file"; then
            expected_features="$expected_features CRT"
        fi
        if grep -qi "uses Dos" "$pas_file"; then
            expected_features="$expected_features DOS"
        fi
    fi

    echo "  PASS: $func_count functions, $line_count lines"
    echo "        Annotations: $ann_lines, Labels: $label_lines"
    if [[ -n "$expected_features" ]]; then
        echo "        Features:$expected_features"
    fi

    passed=$((passed + 1))

    if [[ "$VERBOSE" == "true" ]]; then
        echo "  Functions:"
        grep "^// Function:" "$decompiled" | head -10
        echo "  ..."
    fi
done

echo ""
echo "=== Results ==="
echo "  Passed:  $passed"
echo "  Failed:  $failed"
echo "  Skipped: $skipped"
echo "  Total:   ${#exe_files[@]}"

if [[ -n "$errors" ]]; then
    echo ""
    echo "Errors:"
    echo -e "$errors"
fi

if [[ "$failed" -gt 0 ]]; then
    exit 1
fi
