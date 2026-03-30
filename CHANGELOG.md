# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Decompile.java`: consolidated single-pass GhidraScript replacing the previous 3-step pipeline (`DecompileAll.java` + `annotate_strings.py` + `label_functions.py`); performs Pascal string discovery, string database construction, function labeling (offset tables + FLIRT renaming + pattern detection), decompilation with inline string annotations, and `strings.json` output — all in one `analyzeHeadless` invocation
- `Decompile.java`: full port of all label tables — `BP_SYSTEM_LABELS`, `BP_SYSTEM_CORE_LABELS`, `RHP_DISPLAY_LABELS`, `RHP_INPUT_LABELS`, `CONV_LABELS`, `TIMER_LABELS`, `RECORD_LABELS`, `DDPLUS_LABELS`, `DDPLUS_IO_LABELS`, `CRT_UNIT_LABELS`, plus `FLIRT_DESCRIPTIONS` and `FLIRT_PLAIN_DESCRIPTIONS` (~100+ entries)
- `Decompile.java`: pattern-based function identification using Ghidra's `HighFunction` and PcodeOps API — structural analysis of decompiled IR

### Changed
- `decompile.sh`: pipeline reduced from 4 passes (import → FLIRT → decompile → annotate → label) to 2 passes (import → FLIRT → Decompile.java); backward-compatible `.annotated.c` and `.labeled.c` copies still produced

### Removed
- `DecompileAll.java`: replaced by `Decompile.java`
- `annotate_strings.py`: string annotation consolidated into `Decompile.java`
- `label_functions.py`: function labeling consolidated into `Decompile.java`
- `TestGhidraAPIs.java`, `MinimalTest.java`, `fix_test_script.py`: temporary test/diagnostic files
- `tests/test_annotate_strings.py::TestStringExtractionFromEXE`: tests that imported `annotate_strings` module
- `tests/test_label_functions.py::TestPatternDetection`, `TestFlirtDecoding`, `TestLabelLine`, `TestApplyRenames`: tests that imported `label_functions` module

## [1.2.2] - 2026-03-29

### Added
- `annotate_strings.py`: segment-relative string resolution — for cross-unit string references like `FUN_265c_02a8(0x3571, 0x32e9)`, the annotator now also tries `(seg - 0x1000) * 16 + offset` as the image address in addition to the existing absolute-offset path; this resolves strings in `_Delete_qm6String7Integert2` calls and other inter-unit display calls that were previously silently skipped
- `label_functions.py`: added `__basg_qm6Stringt1` and `__basg_qm6Stringt14Byte` (double-underscore Ghidra variants) to `FLIRT_DESCRIPTIONS` — some FLIRT sig versions emit the double-underscore form; previously they fell through to the generic fallback and got a useless label
- `label_functions.py`: added `_bp_stackcheck_q4Word` to `FLIRT_DESCRIPTIONS` mapped to the `bp_unit_init` short name — prevents the raw FLIRT identifier from appearing in labeled output when Ghidra identifies the stack check entry point by signature rather than by offset

### Changed
- `annotate_strings.py`: segment-relative candidate generation extended to both argument orderings in each `(a, b)` / `(b, a)` pair — covers cases where Ghidra decompiles the far-call ABI with swapped argument order
- `label_functions.py`: `flirt_pattern` regex and `label_line` regex widened from `__[A-Z]\w+` to `__[A-Za-z]\w+` so double-underscore names starting with a lowercase letter (e.g., `__basg_qm6Stringt1`) are scanned and decoded
- `label_functions.py`: `decode_flirt_name` generic `_q` splitter now only fires for **single-underscore** names (`_Foo_qBar`); double-underscore names not in the explicit tables return `None` instead of being decoded generically — prevents name-count collisions that silently blocked both the `__foo` and `_foo` renames

### Fixed
- `analyze_exe.py`: `build_xref` now tries both `(a as offset, b as segment)` and `(b as offset, a as segment)` orderings — previously only the first ordering was checked, missing xrefs where Ghidra emitted arguments in reverse order; also adds a segment-relative fallback: `(seg - 0x1000) * 16 + offset` for cross-unit string references
- `analyze_exe.py`: added `_delete_qm6string7integert2` (lowercased) to `KNOWN_STRING_FUNCS` — the segment-relative string assignment function used heavily in stats-screen rendering
- `tests/test_label_functions.py`: hardcoded `'tests/output/...'` paths replaced with `os.path.join(OUTPUT_DIR, ...)` and `pytest.skip` guards — tests now pass from any working directory, matching the pattern used throughout the rest of the suite



### Changed
- `annotate_strings.py`: removed game-specific processing from `_render()` (backtick colour code collapsing, `0x01` → space mapping); control bytes are now rendered as `\xNN` escape sequences; deleted unused `_is_lord_printable()` helper; removed backtick from letter-ratio counter

## [1.2.0] - 2026-03-25

### Changed
- `label_functions.py`: labeled functions are now **renamed** in the output — `FUN_xxxx_yyyy` identifiers are replaced with their short labels (e.g., `ddp_ansi_dispatch`) throughout the file, covering both declarations and all call sites; functions sharing a short name (collision) are skipped to avoid duplicate identifiers
- `label_functions.py`: FLIRT-mangled function names (e.g., `_Write_qm4Textm6String4Word`) are now also renamed to their short labels (e.g., `bp_write_str`) throughout the labeled output; label comments now show only the description, since the name is present in the identifier itself

### Fixed
- `label_functions.py`: added 13 entries to `BP_SYSTEM_LABELS` for large-binary TP7 System unit functions (`bp_textrec_init`, `bp_writeln_impl`, `bp_str_append`, `bp_val_parse`, etc.) present in DDTEST but absent from previous tables
- `label_functions.py`: added `CRT_UNIT_LABELS` dict and detection (keyed on WhereX/WhereY offsets `024b`/`0257`) for the standalone CRT unit segment in DDTEST, covering `crt_gotoxy_impl`, `crt_wherex_impl`, `crt_wherey_impl`, `crt_textattr_set`
- `label_functions.py`: added `DDPLUS_IO_LABELS` dict and detection (keyed on characteristic low-offset cluster `0000/004a/00bb/0143`) for the DDPlus IO utility segment (`ddp_str_input`, `ddp_str_parse`)
- `label_functions.py`: `identify_by_pattern` — added 6 new structural patterns: `bp_write_str` (string length byte + field-width check), `bp_write_int` (`__Str2Int` + CX), `bp_write_char_flush` (`in_ZF` + TextRec `+0x1a`), `bp_write_inoutproc` (`__InOutProc` + `+0x1a`), `bp_flush_text_cond` (conditional flush, no write), `bp_str_copy_bounded` (min-length copy), `dos_intr` (`swi(0)` + `uRam`)
- `tests/test_label_functions.py`: updated `EXPECTED_FLIRT` to use the actual FLIRT-mangled names present in the test output files (previously listed aspirational names that the sig files never produced)

## [1.1.0] - 2026-03-25

### Added
- `sigs/ddplus.sig`: FLIRT signature file for DDPlus 7.1 Door Driver Toolkit (19 function signatures) — generated directly from compiled DDTEST.EXE via `scripts/gen_sig.py`
- `scripts/gen_sig.py`: generates IDA FLIRT `.sig` files directly from a DOS MZ executable, bypassing non-functional `sigmake` in IDA Free 9.3 — writes version 5 format compatible with both `dumpsig` and `ApplySigHeadless.py`; fully generic with CLI args for segment, library name, and external `.funcs` mapping files
- `sigs/ddplus.funcs`: DDPlus 7.1 function mapping file (19 entries) — used by `gen_sig.py` to regenerate `ddplus.sig`
- `scripts/test_sig.py`: standalone FLIRT `.sig` parser for validating sig files without Ghidra
- `DDTEST.PAS`: DDPlus 7.1 door driver test program exercising all DDPlus exported functions (swrite, sread_char, set_color, InitDoorDriver, etc.)
- `label_functions.py`: 16 DDPlus offset-based function labels (`DDPLUS_LABELS` dict) verified against compiled DDTEST.EXE — auto-detects DDPlus segment by characteristic offsets (swriteln at 13b6, swrite at 130c, sclrscr at 11b7, sgoto_xy at 281e)
- `label_functions.py`: 47 DDPlus/COMIO FLIRT name predictions in `FLIRT_DESCRIPTIONS` for future `ddplus.sig` extraction

### Changed
- `sigs/README.md`: expanded with comprehensive guide for generating new `.sig` files — covers `gen_sig.py` usage, `.funcs` file format, FLIRT name mangling rules, binary format reference, and step-by-step instructions

### Removed
- `scripts/gen_pat.py`: removed — generated `.pat` files for `sigmake`, which is non-functional in IDA Free 9.3

## [1.0.0] - 2026-03-25

### Added

- Full multi-pass decompilation pipeline via `decompile.sh` (import → FLIRT sig rename → overlay load → decompile → annotate → label)
- `DecompileAll.java`: Ghidra headless script to decompile all functions to C pseudocode; accepts output file path as a script argument
- `LoadExternalOverlay.java`: Ghidra headless script to load Borland VROOMM `.OVR` external overlay files
- `ApplySigHeadless.py`: PyGhidra script that applies IDA FLIRT `.sig` files to rename anonymous RTL stubs
- `annotate_strings.py`: post-processor that adds inline Pascal string comments to decompiled C output
- `label_functions.py`: post-processor that identifies and labels known Borland Pascal RTL function patterns
- `analyze_exe.py`: structural analyser producing a segment map, string table, and cross-reference report
- FLIRT signature files for Borland/Turbo Pascal: `tpdos.sig`, `tpdpmi.sig`, `tptv.sig`, `tptvdpmi.sig`
- Test suite: 14 Turbo Pascal test programs compiled to EXE with full pipeline validation (220 pytest tests)
- `tests/conftest.py`, `tests/test_annotate_strings.py`, `tests/test_decompile_output.py`, `tests/test_label_functions.py`
- `BP_SYSTEM_CORE_LABELS` (21 entries) in `label_functions.py` for correct labeling of small binaries
- Callee-based pattern detection in `label_functions.py` (Write(String), INT 10h, INT 21h call-site inference)

### Fixed

- `annotate_strings.py`: skip annotation on pointer arithmetic constants (e.g., `puVar8 + -0x10a`) to eliminate false positives
- `label_functions.py`: system segment detection now uses core offset counting instead of fixed markers (`3fca`/`3f65`) for broader compatibility
- `label_functions.py`: FLIRT description table expanded with `t1`-style mangled names (e.g., `_GotoXY_q4Bytet1`)

[Unreleased]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/talisto/ghidra-turbo-pascal/releases/tag/v1.0.0
