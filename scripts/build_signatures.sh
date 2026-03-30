#!/usr/bin/env bash
# build_signatures.sh — Build Borland Pascal 7 hash-based signature database
#
# One-time operation: imports test binaries, applies IDA FLIRT signatures
# (one last time), then hashes the identified functions to create a Ghidra-
# native signature database (sigs/bp7_signatures.json).
#
# After this, the IDA .sig files and PyGhidra dependency are no longer needed.
#
# Prerequisites:
#   - Ghidra installed (brew install ghidra)
#   - PyGhidra installed (one last time, for FLIRT application)
#   - Test EXEs compiled in tests/data/
#
# Output: sigs/bp7_signatures.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="/tmp/ghidra_sigbuild"
OUTPUT="$PROJECT_DIR/sigs/bp7_signatures.json"

# ── Find tools ────────────────────────────────────────────────────────────────
GHIDRA=""
for path in /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
            /opt/ghidra/support/analyzeHeadless \
            /usr/share/ghidra/support/analyzeHeadless; do
    [[ -x "$path" ]] && { GHIDRA="$path"; break; }
done
[[ -z "$GHIDRA" ]] && GHIDRA="$(command -v analyzeHeadless 2>/dev/null || true)"
if [[ -z "$GHIDRA" ]]; then
    echo "ERROR: analyzeHeadless not found. Install Ghidra." >&2
    exit 1
fi

PYGHIDRA=""
for path in /opt/homebrew/opt/ghidra/libexec/support/pyghidraRun \
            /opt/homebrew/Cellar/ghidra/12.0.4/libexec/support/pyghidraRun \
            /opt/ghidra/support/pyghidraRun \
            /usr/share/ghidra/support/pyghidraRun; do
    [[ -x "$path" ]] && { PYGHIDRA="$path"; break; }
done
[[ -z "$PYGHIDRA" ]] && PYGHIDRA="$(command -v pyghidraRun 2>/dev/null || true)"
if [[ -z "$PYGHIDRA" ]]; then
    echo "ERROR: pyghidraRun required (one last time) for FLIRT signature extraction." >&2
    echo "       After this build, PyGhidra will no longer be needed." >&2
    exit 1
fi

# ── Collect test EXEs ─────────────────────────────────────────────────────────
EXES=()
for exe in "$PROJECT_DIR/tests/data/"*.EXE; do
    [[ -f "$exe" ]] && EXES+=("$exe")
done

if [[ ${#EXES[@]} -eq 0 ]]; then
    echo "ERROR: No test EXEs found in $PROJECT_DIR/tests/data/" >&2
    exit 1
fi

echo "=== Building BP7 Signature Database ==="
echo "  Test binaries: ${#EXES[@]}"
echo "  Output:        $OUTPUT"
echo ""

# ── Clean build ───────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
rm -f "$OUTPUT"

# ── Process each test EXE ─────────────────────────────────────────────────────
# Each binary is imported, FLIRT sigs are applied, then functions are hashed.
# We process one at a time to avoid Ghidra project conflicts.

SIG_FILES=()
for sig in tpdos tpdpmi ddplus; do
    sigpath="$PROJECT_DIR/sigs/$sig.sig"
    [[ -f "$sigpath" ]] && SIG_FILES+=("$sigpath")
done

for exe in "${EXES[@]}"; do
    name=$(basename "$exe")
    echo "--- $name ---"

    # Phase 1: Import
    "$GHIDRA" "$BUILD_DIR" SigBuild \
        -import "$exe" -overwrite \
        2>&1 | grep -E 'INFO.*Import|ERROR' || true

    # Phase 2: Apply FLIRT signatures
    SIG_ARGS=()
    for sig in "${SIG_FILES[@]}"; do
        SIG_ARGS+=("-postScript" "$PROJECT_DIR/ApplySigHeadless.py" "$sig")
    done

    if [[ ${#SIG_ARGS[@]} -gt 0 ]]; then
        "$PYGHIDRA" -H "$BUILD_DIR" SigBuild \
            -process "$name" \
            "${SIG_ARGS[@]}" \
            -scriptPath "$PROJECT_DIR" \
            2>&1 | grep -E 'renamed|Name:|Count:|ERROR' || true
    fi

    # Phase 3: Hash FLIRT-identified functions → append to JSON
    "$GHIDRA" "$BUILD_DIR" SigBuild \
        -process "$name" -noanalysis \
        -postScript CreateBPSignatures.java "$OUTPUT" \
        -scriptPath "$SCRIPT_DIR" \
        2>&1 | grep -E '^\s*\+|Program:|Loaded|ERROR' || true

    # Remove program from project for next iteration
    rm -rf "$BUILD_DIR/SigBuild.rep/"*"/$name" 2>/dev/null || true

    echo ""
done

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"

# ── Report ────────────────────────────────────────────────────────────────────
echo "=== Done ==="
if [[ -f "$OUTPUT" ]]; then
    count=$(grep -c '"[0-9a-f]\{16\}"' "$OUTPUT" 2>/dev/null || echo "0")
    echo "Created: $OUTPUT"
    echo "Signatures: $count functions"
else
    echo "ERROR: Signature file was not created" >&2
    exit 1
fi
