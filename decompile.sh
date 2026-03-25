#!/usr/bin/env bash
# decompile.sh — Ghidra headless decompiler wrapper for DOS executables
#
# Automates the full two-pass pipeline:
#   Pass 1a: Import + analyze EXE into Ghidra project
#   Pass 1b: (optional) Apply IDA FLIRT signatures to rename RTL stubs
#   Pass 2:  Decompile all functions to a .c file
#
# Usage:
#   decompile.sh [options] <exe-path>
#
# Options:
#   --sigs              Apply all bundled FLIRT sigs before decompiling
#                       (recommended for Borland Pascal / Turbo Pascal binaries)
#   --sig <file.sig>    Apply a specific .sig file (can repeat; implies --sigs)
#   --output <dir>      Directory for decompiled.c (default: same dir as EXE)
#   --output-file <f>   Full path for output file (overrides --output naming)
#   --project <dir>     Ghidra project storage dir (default: /tmp/ghidra_<name>)
#   --keep-project      Don't delete the Ghidra project after decompilation
#   --no-import         Skip Pass 1a (project already exists)
#   --ovr <file.ovr>    Load an external Borland overlay file (.OVR with
#                       FBOV header) as additional memory blocks.
#                       Auto-detected if <exe-dir>/<name>.ovr exists.
#
# Examples:
#   # Basic decompile (no sig renames)
#   decompile.sh /path/to/project/GAME.EXE
#
#   # With all bundled Borland Pascal sigs, output to project dir
#   decompile.sh --sigs --output /path/to/project /path/to/project/GAME.EXE
#
#   # With specific sigs only
#   decompile.sh --sig sigs/tpdos.sig /path/to/project/GAME.EXE
#
#   # Keep project for later re-use (e.g. Ghidra GUI inspection)
#   decompile.sh --sigs --keep-project /path/to/project/GAME.EXE
#
# Requirements:
#   - Ghidra installed (brew install ghidra on macOS)
#   - For --sigs: PyGhidra working (pyghidraRun must be available)
#     See README.md for PyGhidra setup notes.
#
# Output:
#   <output-dir>/decompiled.c   (or --output-file path)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGS_DIR="$SCRIPT_DIR/sigs"
SCRIPTS_DIR="$SCRIPT_DIR"

# ── Defaults ──────────────────────────────────────────────────────────────────
APPLY_SIGS=false
CUSTOM_SIGS=()
OUTPUT_DIR=""
OUTPUT_FILE_OVERRIDE=""
PROJECT_DIR=""
KEEP_PROJECT=false
SKIP_IMPORT=false
OVR_PATH=""
EXE_PATH=""

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sigs)            APPLY_SIGS=true; shift ;;
        --sig)             CUSTOM_SIGS+=("$2"); APPLY_SIGS=true; shift 2 ;;
        --output)          OUTPUT_DIR="$2"; shift 2 ;;
        --output-file)     OUTPUT_FILE_OVERRIDE="$2"; shift 2 ;;
        --project)         PROJECT_DIR="$2"; shift 2 ;;
        --keep-project)    KEEP_PROJECT=true; shift ;;
        --no-import)       SKIP_IMPORT=true; shift ;;
        --ovr)             OVR_PATH="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        -*)  echo "Unknown option: $1" >&2; exit 1 ;;
        *)   EXE_PATH="$1"; shift ;;
    esac
done

if [[ -z "$EXE_PATH" ]]; then
    echo "Usage: decompile.sh [--sigs] [--output <dir>] <exe-path>" >&2
    echo "       decompile.sh --help  for full usage" >&2
    exit 1
fi

# ── Resolve paths ─────────────────────────────────────────────────────────────
EXE_ABS="$(cd "$(dirname "$EXE_PATH")" && pwd)/$(basename "$EXE_PATH")"
EXE_BASENAME="$(basename "$EXE_ABS")"
# Strip extension for project name (handles .EXE, .exe, .COM, etc.)
EXE_NAME="${EXE_BASENAME%.*}"

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$(dirname "$EXE_ABS")"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

if [[ -n "$OUTPUT_FILE_OVERRIDE" ]]; then
    OUTPUT_FILE="$OUTPUT_FILE_OVERRIDE"
else
    OUTPUT_FILE="$OUTPUT_DIR/decompiled.c"
fi

[[ -z "$PROJECT_DIR" ]] && PROJECT_DIR="/tmp/ghidra_${EXE_NAME}"

# Auto-detect .ovr file if not explicitly specified
if [[ -z "$OVR_PATH" ]]; then
    for ext in ovr OVR; do
        candidate="$(dirname "$EXE_ABS")/${EXE_NAME}.$ext"
        if [[ -f "$candidate" ]]; then
            OVR_PATH="$candidate"
            break
        fi
    done
fi
if [[ -n "$OVR_PATH" ]]; then
    OVR_ABS="$(cd "$(dirname "$OVR_PATH")" && pwd)/$(basename "$OVR_PATH")"
fi

# ── Find Ghidra tools ─────────────────────────────────────────────────────────
find_ghidra_tool() {
    local name="$1"
    # macOS Homebrew
    local path="/opt/homebrew/opt/ghidra/libexec/support/$name"
    [[ -x "$path" ]] && { echo "$path"; return 0; }
    # Linux common locations
    for dir in /opt/ghidra /usr/share/ghidra /usr/local/share/ghidra; do
        path="$dir/support/$name"
        [[ -x "$path" ]] && { echo "$path"; return 0; }
    done
    # PATH
    command -v "$name" 2>/dev/null && return 0
    echo ""
    return 1
}

GHIDRA="$(find_ghidra_tool analyzeHeadless || true)"
PYGHIDRA="$(find_ghidra_tool pyghidraRun || true)"

if [[ -z "$GHIDRA" ]]; then
    echo "ERROR: analyzeHeadless not found. Install Ghidra (brew install ghidra)." >&2
    exit 1
fi

# ── Build sig list ────────────────────────────────────────────────────────────
# If --sigs (all bundled sigs), use the full set; otherwise use custom list
ALL_SIG_ARGS=()
if [[ "$APPLY_SIGS" == "true" ]]; then
    if [[ "${#CUSTOM_SIGS[@]}" -gt 0 ]]; then
        # Use only the explicitly specified sigs
        for sig in "${CUSTOM_SIGS[@]}"; do
            ALL_SIG_ARGS+=("-postScript" "ApplySigHeadless.py" "$sig")
        done
    else
        # Use all bundled sigs in recommended application order
        for sig in tpdos tpdpmi tptv tptvdpmi bc31rtd; do
            if [[ -f "$SIGS_DIR/$sig.sig" ]]; then
                ALL_SIG_ARGS+=("-postScript" "ApplySigHeadless.py" "$SIGS_DIR/$sig.sig")
            fi
        done
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "=== Ghidra DOS Decompiler ==="
echo "  EXE:         $EXE_ABS"
echo "  Output:      $OUTPUT_FILE"
echo "  Project:     $PROJECT_DIR"
echo "  Apply sigs:  $APPLY_SIGS"
if [[ "$APPLY_SIGS" == "true" ]]; then
    echo "  Sig count:   ${#ALL_SIG_ARGS[@]} args ($(( ${#ALL_SIG_ARGS[@]} / 3 )) files)"
fi
if [[ -n "${OVR_ABS:-}" ]]; then
    echo "  Overlay:     $OVR_ABS"
fi
echo ""

mkdir -p "$PROJECT_DIR"

# ── Pass 1a: Import and analyze ───────────────────────────────────────────────
if [[ "$SKIP_IMPORT" == "false" ]]; then
    echo "--- Pass 1a: Importing and analyzing $EXE_BASENAME ..."
    "$GHIDRA" "$PROJECT_DIR" "${EXE_NAME}Project" \
        -import "$EXE_ABS" \
        -overwrite \
        2>&1 | tail -8
    echo ""
fi

# ── Pass 1b: Apply FLIRT signatures (requires pyghidraRun -H) ─────────────────
if [[ "$APPLY_SIGS" == "true" ]]; then
    if [[ -z "$PYGHIDRA" ]]; then
        echo "WARNING: pyghidraRun not found — skipping sig application." >&2
        echo "         See README.md for PyGhidra setup." >&2
    else
        echo "--- Pass 1b: Applying FLIRT signatures ..."
        "$PYGHIDRA" -H "$PROJECT_DIR" "${EXE_NAME}Project" \
            -process "$EXE_BASENAME" \
            "${ALL_SIG_ARGS[@]}" \
            -scriptPath "$SCRIPTS_DIR" \
            2>&1 | grep -E 'renamed|Name:|Count:|Parse|ERROR|WARN|Aborting'
        echo ""
    fi
fi

# ── Pass 1c: Load external overlay (if present) ──────────────────────────────
if [[ -n "${OVR_ABS:-}" ]]; then
    echo "--- Pass 1c: Loading Borland overlay $OVR_ABS ..."
    "$GHIDRA" "$PROJECT_DIR" "${EXE_NAME}Project" \
        -process "$EXE_BASENAME" \
        -postScript LoadExternalOverlay.java "$OVR_ABS" \
        -scriptPath "$SCRIPTS_DIR" \
        2>&1 | tail -10
    echo ""
fi

# ── Pass 2: Decompile ─────────────────────────────────────────────────────────
echo "--- Pass 2: Decompiling to $OUTPUT_FILE ..."
"$GHIDRA" "$PROJECT_DIR" "${EXE_NAME}Project" \
    -process "$EXE_BASENAME" \
    -postScript DecompileAll.java "$OUTPUT_FILE" \
    -scriptPath "$SCRIPTS_DIR" \
    2>&1 | tail -10
echo ""

# ── Pass 3: Annotate string references ───────────────────────────────────────
# Uses annotate_strings.py to look up Pascal length-prefixed strings at the
# constant pairs that appear in Borland Pascal display-function calls, and adds
# inline /* "text" */ comments to the decompiled output.
ANNOTATED_FILE="${OUTPUT_FILE%.c}.annotated.c"
ANNOTATE_PY="$SCRIPT_DIR/annotate_strings.py"
if [[ -f "$ANNOTATE_PY" ]] && command -v python3 &>/dev/null; then
    echo "--- Pass 3: Annotating string references → $ANNOTATED_FILE ..."
    ANNOTATE_ARGS=("$OUTPUT_FILE" "$EXE_ABS")
    if [[ -n "${OVR_ABS:-}" ]]; then
        ANNOTATE_ARGS+=("$OVR_ABS")
    fi
    ANNOTATE_ARGS+=("-o" "$ANNOTATED_FILE")
    python3 "$ANNOTATE_PY" "${ANNOTATE_ARGS[@]}"
    echo ""
else
    echo "--- Pass 3: Skipping string annotation (annotate_strings.py or python3 not found)"
    echo ""
fi

# ── Pass 4: Label known Borland Pascal / RHP functions ──────────────────────
# Uses label_functions.py to identify common RTL, display, input, file I/O, and
# string manipulation functions and add descriptive comments.
LABELED_FILE="${OUTPUT_FILE%.c}.labeled.c"
LABEL_PY="$SCRIPT_DIR/label_functions.py"
if [[ -f "$LABEL_PY" ]] && command -v python3 &>/dev/null; then
    # Prefer annotated file as input so labels augment string annotations
    LABEL_INPUT="${ANNOTATED_FILE}"
    if [[ ! -f "$LABEL_INPUT" ]]; then
        LABEL_INPUT="$OUTPUT_FILE"
    fi
    echo "--- Pass 4: Labeling known functions → $LABELED_FILE ..."
    python3 "$LABEL_PY" "$LABEL_INPUT" -o "$LABELED_FILE"
    echo ""
else
    echo "--- Pass 4: Skipping function labeling (label_functions.py or python3 not found)"
    echo ""
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
if [[ "$KEEP_PROJECT" == "false" ]]; then
    echo "--- Cleaning up Ghidra project at $PROJECT_DIR ..."
    rm -rf "$PROJECT_DIR"
fi

# ── Report ────────────────────────────────────────────────────────────────────
echo "=== Done ==="
echo "Output: $OUTPUT_FILE"
if [[ -f "$ANNOTATED_FILE" ]]; then
    echo "Annotated: $ANNOTATED_FILE"
fi
if [[ -f "$LABELED_FILE" ]]; then
    echo "Labeled:   $LABELED_FILE"
fi
if [[ -f "$OUTPUT_FILE" ]]; then
    FUNC_COUNT=$(grep -c "^// Function:" "$OUTPUT_FILE" 2>/dev/null || echo "?")
    LINE_COUNT=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
    echo "Functions: $FUNC_COUNT"
    echo "Lines:     $LINE_COUNT"
fi
