# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `ROADMAP.md`: Complete rewrite focused on producing compilable Pascal source files as the primary goal; reorganized into 6 phases (pascal_emit.py fixes → Ghidra output quality → language feature recovery → program structure → validation → advanced recovery); added concrete milestone targets (M1–M5) and detailed current output quality assessment against all 16 test programs
- `pascal_emit.py` → `pascal_emit/` package: refactored 1451-line monolith into 7 focused modules (`strings`, `parser`, `types`, `expressions`, `write_sequences`, `body_converter`, `globals_scanner`, `emitter`, `pipeline`); backward-compatible `__init__.py` re-exports all public API; CLI now invoked via `python3 -m pascal_emit`

## [2.1.0] - 2026-04-01

### Added
- `pascal_emit.py`: C-to-Pascal transpiler post-processor that converts decompiled C pseudocode to Pascal source; handles application function conversion (procedures/functions with proper signatures, var params, return types), Write/WriteLn sequence detection, global variable declarations from memory addresses, hex-to-decimal constant conversion, `if/else/while/repeat-until/break` control flow, `uses Crt`/`uses Dos` detection, and proper indentation
- `pascal_emit.py`: `ExeStringReader` class reads Pascal length-prefixed strings directly from the original EXE binary at given offsets, bypassing incomplete `strings.json` entries; integrated as fallback in Write/WriteLn string resolution
- `pascal_emit.py`: multi-strategy string resolution — inline `/* "text" */` annotations (highest priority), `bp_write_str(width, offset, segment)` argument extraction, position-based DAT_ stack frame lookup (positions [1], [2], [3] depending on frame size), direct EXE binary reading for all resolution paths
- `pascal_emit.py`: supports three stack manipulation styles: `DAT_` named globals, `*(word *)(puVarN + -N)` casts, and `puVarN[-N]` bracket syntax (each with different string offset positions in the stack frame)
- `tests/test_pascal_emit.py`: 180-test suite covering Pascal structure (16 programs × 8 structural checks), per-program output validation (HELLO, CONTROL, PROCFUNC, CRTTEST, MATHOPS, GAMESIM), and unit tests for expression/condition/type conversion functions
- `Decompile.java`: Phase 2b — custom code-segment string scanner (`scanCodeSegmentStrings`) supplements Ghidra's `findPascalStrings()` which only scans data regions; reads raw bytes from initialized memory blocks looking for Pascal length-prefixed strings packed at the start of code segments; accepts strings as short as 2 characters
- `Decompile.java`: Phase 3.2 — Library code elimination: library functions (`bp_*`, FLIRT-identified `@Name$...` and `__Name` functions) have their C bodies replaced with a `// [LIBRARY]` marker, dramatically reducing output noise; application functions retain full bodies; a summary section at the end lists all identified library functions with addresses
- `Decompile.java`: Phase 3.4 — CONCAT11 artifact cleanup: `CONCAT11(extraout_AH..., value)` expressions simplified to just `value` (in BP7, the AH portion is irrelevant); handles nested parentheses in value arguments; complex non-extraout CONCAT11 patterns left untouched
- `Decompile.java`: Phase 3.4 — Unused variable declaration cleanup: removes `unaff_DS` and `extraout_AH` variable declarations when the variable is not referenced elsewhere in the function body
- `Decompile.java`: Phase 5 — `__stdcall16far` calling convention noise now also stripped from output (was missing alongside `__cdecl16near`/`__cdecl16far`)
- `Decompile.java`: Phase 2.5 — `registerBP7Types()` registers 7 Borland Pascal standard data types in Ghidra's DataTypeManager under `/BP7` category: `TextRec`, `FileRec`, `SearchRec`, `DateTime`, `Registers`, `ShortString`, and `FileMode` enum (foundation for future parameter type application)
- `postprocess.py`: standalone Python post-processor that applies the same text-based transformations as `Decompile.java` Phase 5; can be used to update pre-generated test outputs without re-running Ghidra
- `tests/test_output_cleanup.py`: 8 new test classes covering library elimination (`TestLibraryElimination`: marked, no body, app functions have body, summary section, summary lists functions) and artifact cleanup (`TestArtifactCleanup`: no CONCAT11 extraout, no unused unaff_DS/extraout_AH declarations) — 128 tests across 16 binaries
- `tests/test_decompile_output.py`: `TestTypeCleanup` class with 3 tests — `test_no_undefined_types`, `test_no_cdecl16_calling_convention`, `test_uses_standard_type_names`
- `debug/string_analysis.py`: diagnostic script for tracing string offset mapping

### Changed
- `Decompile.java`: Phase 6 strings.json writer now emits from `stringDb` (HashMap) instead of `pascalStrings` (FoundString list), so custom-scanned strings are included in the output; offsets are sorted for stable output
- `Decompile.java`, `postprocess.py`, `tests/test_output_cleanup.py`: expanded library function detection to include `ddp_*`, `crt_*`, `dos_*`, `comio_*`, `ovr_*` prefixes (previously only `bp_*`); DDTEST output reduced by ~1000 lines as DDPlus/CRT/DOS library functions are now eliminated
- `Decompile.java`: `buildFlirtLabels()` now handles `@Name$q...` Borland mangled format (in addition to `_Name_q...`); converts `@Name$q` → `_Name_q` for lookup in `FLIRT_DESCRIPTIONS`, with generic fallback decode
- `postprocess.py`: library summary now shows friendly names for `@Name$...` FLIRT functions (e.g., `bp_write_char (@Write$qm4Text4Char4Word)` instead of raw mangled name); includes lookup table for 28 common FLIRT names with generic fallback decode

### Fixed
- `pascal_emit.py`: WriteLn/Write handlers no longer consume DAT_/puVar argument lines belonging to the NEXT write sequence; uses tentative-skip with rollback when `bp_iocheck` is not found after the terminator
- `pascal_emit.py`: standalone `bp_iocheck` without preceding write parts now acts as a sequence boundary (break) instead of continuing to scan and merging with the next sequence
- `Decompile.java`: `_Randomize_qv` FLIRT signature now maps to `bp_random` (Random(Word)) instead of `bp_randomize` — FLIRT consistently misidentifies `Random(Word)` with the `Randomize` signature because the byte patterns collide; this was causing the RANDTEST test failure and leaving `_Randomize_qv` unrenamed in GAMESIM/RANDTEST output
- Test output files: applied `undefined1→byte`, `undefined2→word`, `undefined4→dword`, `undefined8→qword` type cleanup and calling convention removal to all 16 test output files (was defined in Decompile.java but outputs were never regenerated), fixing 31 pre-existing test failures

## [2.0.0] - 2026-03-30

### Added
- `Decompile.java`: consolidated single-pass GhidraScript replacing the previous 3-step pipeline (`DecompileAll.java` + `annotate_strings.py` + `label_functions.py`); performs Pascal string discovery, string database construction, function labeling (offset tables + FLIRT renaming + pattern detection), decompilation with inline string annotations, and `strings.json` output — all in one `analyzeHeadless` invocation
- `Decompile.java`: full port of all label tables — `BP_SYSTEM_LABELS`, `BP_SYSTEM_CORE_LABELS`, `RHP_DISPLAY_LABELS`, `RHP_INPUT_LABELS`, `CONV_LABELS`, `TIMER_LABELS`, `RECORD_LABELS`, `DDPLUS_LABELS`, `DDPLUS_IO_LABELS`, `CRT_UNIT_LABELS`, plus `FLIRT_DESCRIPTIONS` and `FLIRT_PLAIN_DESCRIPTIONS` (~100+ entries)
- `Decompile.java`: pattern-based function identification using Ghidra's `HighFunction` and PcodeOps API — structural analysis of decompiled IR
- `Decompile.java`: `bp_str_temp_read` offset label for atomic read & clear temporary string pointer (offset `04ed`)
- `scripts/CreateBPSignatures.java`: GhidraScript that hashes FLIRT-identified functions to build a JSON signature database using Ghidra's FID service (FNV1a 64-bit hashes); retained for future use
- `scripts/build_signatures.sh`: one-time orchestration script to build `sigs/bp7_signatures.json` from test binaries; retained for future use
- `sigs/bp7_signatures.json`: hash-based function signature database (90 entries, 89 unique names) — experimental alternative to FLIRT `.sig` files; retained for future use

### Changed
- `decompile.sh`: pipeline reduced from 4 passes (import → FLIRT → decompile → annotate → label) to 2 passes (import → FLIRT → Decompile.java); single `decompiled.c` output (removed redundant `.annotated.c` and `.labeled.c` copies)

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

[Unreleased]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.2...v2.0.0
[1.2.2]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/talisto/ghidra-turbo-pascal/releases/tag/v1.0.0
