# ghidra-turbo-pascal

A Ghidra-based decompilation pipeline for **DOS MZ executables compiled with Borland Pascal 7 / Turbo Pascal 7**. Automates the full workflow: importing, applying FLIRT signatures to rename anonymous RTL stubs, handling Borland VROOMM overlay files, decompiling to C pseudocode, annotating string references, and labeling known library functions.

## What's Included

| Path | Description |
|------|-------------|
| `decompile.sh` | Shell wrapper — the recommended entry point for the full pipeline |
| `DecompileAll.java` | Ghidra headless script: decompiles all functions to C pseudocode |
| `LoadExternalOverlay.java` | Ghidra headless script: loads Borland VROOMM `.OVR` overlay files |
| `ApplySigHeadless.py` | PyGhidra script: applies IDA FLIRT `.sig` files to rename RTL stubs |
| `annotate_strings.py` | Post-processor: adds inline string comments to decompiled C output |
| `label_functions.py` | Post-processor: identifies and labels known library function patterns |
| `analyze_exe.py` | Structural analyser: segment map, string table, cross-reference report |
| `sigs/` | Pre-extracted IDA FLIRT sig files for Borland Pascal / Turbo Pascal |
| `tests/` | Test programs and expected outputs for validating the pipeline |

## Quick Start

```bash
# Make the script executable (first use only)
chmod +x decompile.sh

# Decompile with Borland Pascal sig renames (recommended)
./decompile.sh --sigs --output /path/to/output /path/to/MYPROG.EXE

# Decompile without sig renames
./decompile.sh --output /path/to/output /path/to/MYPROG.EXE

# Get full usage
./decompile.sh --help
```

The script runs a full multi-pass pipeline:

1. **Pass 1a** — Import and analyze the EXE in Ghidra
2. **Pass 1b** — Apply FLIRT signatures to rename anonymous RTL stubs (with `--sigs`)
3. **Pass 1c** — Load external Borland overlay (if a `.OVR` file is detected or specified with `--ovr`)
4. **Pass 2** — Decompile all functions to `decompiled.c`
5. **Pass 3** — Annotate with inline string comments → `decompiled.annotated.c`
6. **Pass 4** — Label known library function patterns → `decompiled.labeled.c`

The labeled file is the richest output — it has both string annotations AND function labels.

## Requirements

- **Ghidra** ≥ 11.0 — `brew install ghidra` on macOS, or [ghidra-sre.org](https://ghidra-sre.org)
- **Python 3** ≤ 3.13 — required for PyGhidra (jpype1 has no wheel for Python 3.14+)
- **PyGhidra** — bundled with Ghidra; `pyghidraRun` must be on your PATH for sig application

### Ghidra Setup

The headless analyzer location varies by platform:
```bash
# macOS (Homebrew)
ls /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless

# Linux (common locations)
ls /opt/ghidra/support/analyzeHeadless
ls /usr/share/ghidra/support/analyzeHeadless
```

Verify installation: `which analyzeHeadless`

### PyGhidra Setup

If `pyghidraRun -H` fails:
- `pyghidraRun` creates a Python venv the first time it's run
- It requires Python 3.13 or older (jpype1 has no wheel for Python 3.14+)
- If the venv was created with Python 3.14, recreate it:
  ```bash
  python3.13 -m venv ~/Library/ghidra/<version>/venv --clear
  # Then re-run pyghidraRun — it will install packages from bundled wheels
  ```

## Usage

### Full Pipeline (recommended)

```bash
# Import, apply TP7 sigs, decompile, annotate, and label:
./decompile.sh --sigs --output /path/to/output /path/to/MYPROG.EXE
```

### All Options

```
--sigs              Apply all bundled FLIRT sigs before decompiling
--sig <file.sig>    Apply a specific .sig file (can repeat; implies --sigs)
--output <dir>      Directory for output files (default: same dir as EXE)
--output-file <f>   Full path for output file (overrides --output naming)
--project <dir>     Ghidra project storage dir (default: /tmp/ghidra_<name>)
--keep-project      Don't delete the Ghidra project after decompilation
--no-import         Skip import pass (project already exists)
--ovr <file.ovr>    Load an external Borland overlay file
```

### Examples

```bash
# Basic decompile (no sig renames)
./decompile.sh /path/to/MYPROG.EXE

# With explicit output directory
./decompile.sh --sigs --output /path/to/output /path/to/MYPROG.EXE

# Keep the Ghidra project for GUI inspection
./decompile.sh --sigs --keep-project /path/to/MYPROG.EXE

# With explicit overlay path
./decompile.sh --sigs --ovr /path/to/MYPROG.OVR /path/to/MYPROG.EXE

# With a specific sig file only
./decompile.sh --sig sigs/tpdos.sig /path/to/MYPROG.EXE

# Different output filename
./decompile.sh --sigs --output-file /path/to/output/decompiled-sig.c /path/to/MYPROG.EXE
```

### Using from Another Project

The scripts accept absolute paths, so you can invoke them from anywhere:

```bash
/path/to/ghidra-turbo-pascal/decompile.sh --sigs \
    --output /path/to/project/output \
    /path/to/project/MYPROG.EXE
```

### Post-Processing Scripts

The pipeline runs these automatically, but they can also be used standalone:

#### String Annotation

Ghidra's decompiled output for Borland Pascal contains no string literals — display calls appear as raw integer constants. `annotate_strings.py` resolves these to inline `/* "..." */` comments:

```bash
python3 annotate_strings.py \
    /path/to/output/decompiled.c \
    /path/to/MYPROG.EXE \
    [/path/to/MYPROG.OVR]          # optional — for overlay binaries

# Output: /path/to/output/decompiled.annotated.c
```

Before/after:
```c
// Before:
FUN_265c_02a8(0x1ebf,0x32e9);

// After:
FUN_265c_02a8(0x1ebf,0x32e9);  /* "`2  While walking down a tunnel, you hear a scary voice." */
```

#### Function Labeling

`label_functions.py` identifies known Borland Pascal RTL patterns and labels them:

```bash
python3 label_functions.py \
    /path/to/output/decompiled.annotated.c \
    -o /path/to/output/decompiled.labeled.c
```

Labels include Borland Pascal RTL functions (`bp_str_concat`, `bp_random`, `bp_file_assign`, etc.), display/input library functions, and conversion utilities.

#### Structural Analysis

`analyze_exe.py` produces a detailed report of the binary's structure:

```bash
python3 analyze_exe.py /path/to/MYPROG.EXE \
    --xref /path/to/output/decompiled.c \
    --all -o /path/to/output/analysis.txt
```

Output includes: EXE header fields, Borland Pascal segment map, complete string table with image offsets, string cross-references, and function prologue detection.

### Manual Pipeline

If you need to run the Ghidra passes manually (e.g., to add more sigs later without re-importing):

```bash
GHIDRA=/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless
PYGHIDRA=/opt/homebrew/opt/ghidra/libexec/support/pyghidraRun
PROJ=/tmp/ghidra_project
SIGS=/path/to/ghidra-turbo-pascal/sigs

# Pass 1a: Import and analyze
"$GHIDRA" "$PROJ" MyProject -import /path/to/MYPROG.EXE -overwrite

# Pass 1b: Apply FLIRT sigs (requires pyghidraRun)
"$PYGHIDRA" -H "$PROJ" MyProject -process MYPROG.EXE \
  -postScript ApplySigHeadless.py "$SIGS/tpdos.sig" \
  -postScript ApplySigHeadless.py "$SIGS/tpdpmi.sig" \
  -postScript ApplySigHeadless.py "$SIGS/tptv.sig" \
  -scriptPath /path/to/ghidra-turbo-pascal

# Pass 2: Decompile (Java scripts use regular analyzeHeadless)
"$GHIDRA" "$PROJ" MyProject -process MYPROG.EXE \
  -postScript DecompileAll.java /path/to/output/decompiled.c \
  -scriptPath /path/to/ghidra-turbo-pascal
```

**Note**: Python scripts (`.py`) require `pyghidraRun -H`; Java scripts (`.java`) require regular `analyzeHeadless`. These cannot be mixed in a single pass. `decompile.sh` handles this automatically.

## FLIRT Signature Files

Pre-extracted from IDA Free 9.3. See [sigs/README.md](sigs/README.md) for details.

| File | Covers |
|------|--------|
| `tpdos.sig` | Turbo Pascal 5–7 DOS runtime |
| `tpdpmi.sig` | Turbo Pascal 7 DPMI runtime |
| `tptv.sig` | Turbo Vision 6–7 (TUI framework) |
| `tptvdpmi.sig` | Turbo Vision 7 DPMI |
| `bc31rtd.sig` | Borland C/C++ 3.1 16-bit DOS runtime |

### Generating Custom Sig Files

To generate additional FLIRT signatures from Borland Pascal `.OBJ` / `.LIB` files using the [FLAIR toolkit](https://hex-rays.com/products/ida/support/ida/flair.zip) (free from Hex-Rays):

```bash
# Create .pat pattern files from .OBJ files
./pcf SYSTEM.OBJ system.pat
./pcf CRT.OBJ crt.pat

# Compile to .sig
./sigmake system.pat system.sig
./sigmake crt.pat crt.sig

# Apply via decompile.sh
./decompile.sh --sig system.sig /path/to/MYPROG.EXE
```

## Borland Overlay Support

Borland's VROOMM overlay system stores code in external `.OVR` files alongside the main EXE.

- **Auto-detection**: If a `.ovr` file shares a name with the EXE in the same directory, `decompile.sh` detects and loads it automatically.
- **Explicit path**: Use `--ovr /path/to/file.ovr` for overlay files with different names or locations.
- **What it does**: `LoadExternalOverlay.java` parses the FBOV-format overlay, creates memory blocks at segment `0x8000`, identifies overlay entry points from INT 3F stubs in the EXE, and patches trap instructions with far JMPs to create cross-references.

## Tests

The test suite validates the pipeline against 14 compiled Turbo Pascal test programs:

```bash
python -m pytest tests/ --tb=short -q
```
