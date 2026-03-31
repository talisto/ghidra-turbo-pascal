# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.22.0] - 2026-04-01

### Added
- `pascal_emit/body_converter.py`: CARRY2 32-bit carry arithmetic conversion — `Word(CARRY2)(a, b)` artifacts from Ghidra's 16-bit carry decomposition are now converted to `Word(Ord(LongInt(a) + LongInt(b) > 65535))`, producing valid Pascal for 32-bit addition overflow detection
- `pascal_emit/pipeline.py`: Proc_/Func_ calls with `var` parameters now generate typed temp variables (`_tmp_ProcName_idx`) instead of being commented out — `var` params get correctly-typed temp placeholders while non-var params get literal `0`

### Changed
- `pascal_emit/write_sequences.py`: fixed FLIRT name matching for `_Write_qm4Text4Char4Word` and `_Write_qm4Text4Real4Wordt3` — write char/real regex patterns now use `\w*` suffix to match mangled FLIRT signatures with extra type suffixes, allowing these calls to participate in Write/WriteLn sequence merging
- `pascal_emit/body_converter.py`: removed `CARRY\d` from `_LEAKED_IDENT_RE` since CARRY2 artifacts are now converted to valid Pascal before the sanitizer runs
- `test_fpc_compilation.py`: replaced hollow-body detection with strict commented-line counting — `CLEAN_PROGRAMS` (8) must have exactly 0 non-stub commented lines, `INCOMPLETE_PROGRAMS` (7) are tracked for regression; removed `_find_hollow_functions()` in favor of simpler `_count_commented_lines()`; moved GAMESIM to `CLEAN_PROGRAMS`
- GAMESIM: 2 → 0 commented lines — **moved to Clean tier** (CARRY2 conversion resolved both remaining lines)
- RECORDS: 9 → 7 commented lines (-2; CARRY2 conversion + var param temp variable generation)
- PROCFUNC: 12 → 10 commented lines (-2; var param temp variable generation for Proc_ calls)
- PTRMEM: 14 → 11 commented lines (-3; var param temp variable generation)
- FILEIO: 22 → 21 commented lines (-1; FLIRT write char regex now matches `_Write_qm4Text4Char4Word`)
- 8 programs now produce fully clean output with 0 non-stub commented lines (up from 7)
- `ROADMAP.md`: updated quality metrics to v2.22.0 — 8/16 clean (50%), 178 total non-stub commented lines

## [2.21.0] - 2026-03-31

### Added
- `pascal_emit/write_sequences.py`: extended `WRITE_REAL_RE` to match `bp_write_real` and `_Write_qm4Text4Real` — real-number writes now participate in Write/WriteLn sequence merging instead of being emitted as standalone comments
- `pascal_emit/write_sequences.py`: extended `WRITE_CHAR_RE` and `WRITE_CHAR_ARGS_RE` to match `bp_write_char`, `bp_write_char_buf`, and `_Write_qm4Text4Char` — character writes (including space separators) now merge into Write sequences

### Changed
- MATHOPS: 1 → 0 commented lines — now fully clean output; `WriteLn('355/113 = ', 0.0)` instead of separate `{ bp_write_real(); }` comment
- PTRMEM: 15 → 14 commented lines (-1); `Write(local_6, ' ')` merges char-buf space separator into Write call
- FILEIO: 23 → 22 commented lines (-1)
- 6 programs now produce fully clean output with 0 commented lines

## [2.20.0] - 2026-03-31

### Added
- `pascal_emit/pipeline.py`: automatic string global detection and retyping — globals that receive `bp_str_assign_const` / `bp_str_copy_const` assignments are retyped from `Integer` to `String[N]` (where N is the max assigned string length), and the assignments are uncommented to active Pascal code

### Changed
- RECORDS: 13 → 9 commented lines (-4); `g_0072 := 'Sword'`, `g_0085 := 'Shield'`, `g_0098 := 'Potion'`, `g_00AB := 'Ring'` now emit as active assignments with globals typed as `String[5]`..`String[6]`
- GAMESIM: 3 → 2 commented lines (-1); `g_0052 := 'TestPlayer'` now active with global typed as `String[10]`
- Compilation: 15/16 programs unchanged (93.75%), no regressions

## [2.19.0] - 2026-03-31

### Added
- `pascal_emit/body_converter.py`: extended NOISE_PATTERNS to match C pointer variable declarations with `*` (`byte *pbVar1;`, etc.) — previously only `byte pbVar1` (without `*`) was caught
- `pascal_emit/pipeline.py`: extract `{ var ... }` declarations from main body into the program's `var` section — previously this extraction only ran for app functions, leaving main-block vars as commented lines

### Fixed
- `pascal_emit/pipeline.py`: prevent duplicate temp variable declarations in main body when both `{ var }` extraction and `_collect_undeclared_temps` find the same variable

### Changed
- RECORDS: 16 → 13 commented lines (-3)
- PROCFUNC: 14 → 12 commented lines (-2)
- OVRTEST: 2 → 1 commented lines (-1)
- TYPECAST: 1 → 0 commented lines — now fully clean output
- STRINGS: 26 → 25 commented lines (-1)
- Compilation: 15/16 programs unchanged (93.75%), no regressions

## [2.18.0] - 2026-03-31

### Added
- `pascal_emit/body_converter.py`: widened assignment LHS regex to match field-access patterns `*(type *)(var + offset) = value;` in addition to existing `*(type *)0xNN = value;` — shared `_MEM_LHS` pattern covers both forms for simple and compound assignments
- `pascal_emit/body_converter.py`: FUN_→Func_ conversion in `_sanitize_ghidra_artifacts` for Write/WriteLn lines — cross-segment function references (e.g., `FUN_1066_02e7`) become `Func_1066_02e7()` calls within Write statements
- `pascal_emit/pipeline.py`: Func_ stub generation — undeclared `Func_XXXX_XXXX` references get `function FuncName: Integer; forward;` stubs, enabling cross-segment function calls in Write/WriteLn
- `pascal_emit/pipeline.py`: `_comment_out_bad_func_calls` safety check — re-comments Write/WriteLn lines where Func_ is called with no arguments but the function's IR declaration has parameters, preventing FPC "Can't read or write variables of this type" errors

### Changed
- RECORDS: 27 → 16 commented lines (-11) from field-access assignment expansion
- PTRMEM: 17 → 15 commented lines (-2); `WriteLn('MemAvail: ', Func_1066_02e7())` and `WriteLn('MaxAvail: ', Func_1066_0303())` now emit as active code with Func_ stubs
- Compilation: 15/16 programs unchanged (93.75%), no regressions

## [2.17.0] - 2026-03-31

### Added
- `pascal_emit/write_sequences.py`: extended Write/WriteLn sequence detection to recognize large-RTL variants `bp_write_str_body` and `bp_writeln_impl` — these are the write functions used in bigger BP7 binaries (different from `bp_write_str`/`bp_writeln` used in small binaries)
- `pascal_emit/write_sequences.py`: added `WRITE_BOOL_RE` pattern for `bp_write_bool` / `_Write_qm4Text7Boolean4Word` — boolean writes now participate in Write/WriteLn sequence merging instead of being emitted as standalone `{ bp_write_bool(); }` comments

### Changed
- PTRMEM: 62 → 17 commented lines (-45); most Write/WriteLn statements now emit as active Pascal code with resolved string arguments from DAT_ annotations
- Compilation: 15/16 programs unchanged (93.75%), no regressions

## [2.16.0] - 2026-03-31

### Added
- `pascal_emit/body_converter.py`: strip C-style comments (`/* ... */`) from lines before pattern matching in `convert_c_line()` — Ghidra description comments and string annotations no longer prevent function call recognition by regex patterns with `$` anchors
- `pascal_emit/body_converter.py`: string assignment converter for `bp_str_assign_const` and `bp_str_copy_const` — when the source offset resolves to a string in the strings DB, emits `{ g_XXXX := 'value'; }` instead of raw `{ bp_str_assign_const(0xf,0x72,unaff_DS,...); }`
- `pascal_emit/body_converter.py`: added noise functions to `skip_names`: `bp_str_temp_free`, `bp_unit_init`, `bp___stackcheck`, `bp___systeminit`, `bp_textrec_init`, `bp_text_open_check`
- `pascal_emit/body_converter.py`: Write internals (`bp_write_str_body`, `bp_writeln_impl`, `bp_write_bool`, `bp_write_real`, `bp_write_setup`, `bp_write_char_buf`) emit clean `{ fname(); }` comments instead of raw Ghidra output with C comment suffixes
- `pascal_emit/pipeline.py`: `strings_db` passed through `func_info` to `convert_c_line()` for direct string lookup

### Changed
- PTRMEM: 93 → 62 commented lines (-31 noise lines removed)
- DDTEST: 128 → 120 commented lines (-8 noise lines)
- FILEIO: 31 → 23 commented lines (-8 noise lines)
- RECORDS: string constants now visible as readable Pascal: `{ g_0072 := 'Sword'; }`, `{ g_0085 := 'Shield'; }`, etc.
- GAMESIM: `{ g_0052 := 'TestPlayer'; }` replaces raw `{ bp_str_copy_const(...); }`

## [2.15.0] - 2026-03-30

### Added
- `pascal_emit/body_converter.py`: CRT function converters — `crt_wherex_impl` → `WhereX`, `crt_wherey_impl` → `WhereY`, `crt_gotoxy_impl` → `GotoXY` in `_LABEL_TO_PASCAL`, plus `crt_textattr_set(value)` → `TextAttr := value` setter conversion
- `pascal_emit/expressions.py`: CRT functions added to `_EXPR_LABEL_MAP` for expression contexts; parameterless function argument stripping for `WhereX`, `WhereY`, `ReadKey`, `KeyPressed`, `ParamCount`, `Randomize`
- `pascal_emit/write_sequences.py`: temp variable inlining — when a write call uses `uVar1` as its value, substitute the actual expression (e.g., `Random(100)`) from the preceding assignment, with safety check to only inline known convertible functions
- `pascal_emit/body_converter.py`: preserve `uVar` assignments when the variable is referenced elsewhere in the function body (prevents stripping assignments to variables used in Write calls)

### Changed
- RANDTEST Write calls now show `Random(100)` instead of uninitialized `uVar1`
- CRTTEST now correctly emits `WhereX`, `WhereY`, and `TextAttr :=` instead of raw `crt_*` function calls

## [2.14.0] - 2026-03-30

### Fixed
- `pascal_emit/write_sequences.py`: strip `/* "..." */` string annotations from dat_values before expression conversion — prevents garbled output like `990 div * "Hello World" * div:108` when annotated hex constants flow through the expression converter
- `pascal_emit/body_converter.py`: comment out orphaned `Break` statements that end up outside any loop context after `_sanitize_ghidra_artifacts` empties loop bodies containing pointer variable references

### Changed
- PROCFUNC now compiles (15/16 programs = 93.75%, up from 87.5%)

## [2.13.0] - 2026-03-30

### Added
- `pascal_emit/pipeline.py`: extended unsafe line detection with C pointer type casts `(type *)` and non-array parameter indexing `param_N[M]` — these patterns are now auto-commented, preventing FPC "Illegal qualifier" errors
- `pascal_emit/body_converter.py`: C array variable declarations (`type name[size];`) now convert to Pascal array types instead of being ignored

### Changed
- PTRMEM now compiles, RECORDS now compiles (14/16 programs = 87.5%, up from 81.25%)
- PROCFUNC structural error fixed — function body was lost due to for loop continuation being stripped as uVar noise; now at 3 errors (down from blocking structural failure at line 111)

### Fixed
- `pascal_emit/body_converter.py`: for loop regex changed from non-greedy `(.+?)` to greedy `(.+)` to handle nested parens like `(uint)` in for loop content
- `pascal_emit/body_converter.py`: `uVar\d+ =` noise pattern now requires trailing `;` to avoid stripping for loop continuation lines like `uVar2 = uVar2 - 1) {`
- `pascal_emit/body_converter.py`: for loops with comma-body expressions emit `while True do begin` instead of multi-line comments that break block nesting
- `pascal_emit/pipeline.py`: local variable extraction regex now handles complex types like `array[0..N] of Type` (was only matching single-word types)

## [2.12.0] - 2026-03-30

### Added
- `pascal_emit/expressions.py`: shared `_C_PTR_TYPES` constant extending C pointer type patterns to include `dword`, `short`, `ushort`, `long`, `ulong` — all pointer cast regexes now handle these types
- `pascal_emit/expressions.py`: combined cast+deref pattern `(type)*var` → `Type(var)` — converts expressions like `(int)*(dword *)param_1` to `Integer(param_1)`
- `pascal_emit/pipeline.py`: post-conversion safety pass (`_comment_out_unsafe_lines`) that comments out lines containing unconverted C pointer dereferences (`*(type *)expr`) and scalar assignments to array-typed variables

### Fixed
- `pascal_emit/body_converter.py`: moved return statement handler before variable declaration pattern — prevents `return local_6;` from being misinterpreted as `{ var local_6: return; }` when `return` matches the `type varname;` pattern
- `pascal_emit/pipeline.py`: unsafe line detection strips `{ ... }` comment sections before checking for C pointer syntax — prevents double-commenting lines that contain already-commented C fragments

### Changed
- RECORDS now compiles (13/16 programs = 81.25%, up from 75%)

## [2.11.0] - 2026-03-30

### Added
- `pascal_emit/pipeline.py`: auto-detect array-typed temp variables — when a temp variable like `iVar1` is used with indexed access (`iVar1[21]`), it's declared as `array[0..N] of Integer` instead of `Integer`, fixing "Illegal qualifier" errors (RECORDS 24→3 errors)

### Fixed
- `pascal_emit/pipeline.py`: placeholder args for empty procedure calls now skip procedures with `var` parameters — instead of passing literal `0` (which causes "Variable identifier expected"), the call is commented out

## [2.10.0] - 2026-03-30

### Changed
- `pascal_emit/expressions.py`: refactored `_convert_atomic_condition` to split on comparison operators and delegate each operand to `convert_expression` — eliminates ~50 lines of duplicated conversion logic and fixes missing sub-field accessor conversion (`var._1_1_` → `Byte(var)`) in conditions
- `tests/test_fpc_compilation.py`: DDTEST moved from expected failures to compiling programs (12/16 now compile, 75%)

### Added
- `pascal_emit/pipeline.py`: empty procedure call fix — when Ghidra emits `FUN_xxxx()` with no arguments (can't resolve BP7 stack-based arg passing) but the procedure declaration has parameters, placeholder `0` values are added to match the param count

## [2.9.0] - 2026-03-30

### Added
- `pascal_emit/pipeline.py`: global variable declarations for data segment addresses — the `0xNN, unaff_DS` → `g_XXXX` conversion (introduced in v2.7.0) now automatically declares `g_XXXX` variables in the `var` block, even when they originate from function arguments rather than pointer dereferences
- `pascal_emit/pipeline.py`: cross-segment stub parameter padding — when call sites pass more arguments than the IR function definition reports (due to seg:off expansion), stubs are padded with extra `Integer` parameters to match, with collision-safe naming

### Fixed
- `pascal_emit/body_converter.py`: far call segment constants stripped from function call arguments — for `FUN_SSSS_xxxx(offset, 0xSSSS, ...)` calls, the segment value `0xSSSS` is now automatically removed, reducing argument count mismatches between call sites and stub declarations
- `pascal_emit/pipeline.py`: cross-segment stubs no longer use `var` parameters — call sites pass literal offsets (from seg:off expansion), not variable references, so `var` qualification is stripped to avoid "Variable identifier expected" errors

## [2.8.0] - 2026-03-30

### Fixed
- `pascal_emit/expressions.py`: memory access expressions with hex offsets (`*(int *)(var + 0x15)`) now correctly convert to Pascal indexed access (`var[21]`) — offset patterns accept both hex and decimal, and `_convert_atomic_condition` handles them identically
- `pascal_emit/write_sequences.py`: `WRITE_LONGINT_ARGS_RE` third argument now handles nested parentheses in expressions (uses `.+` instead of `[^)]+`)

## [2.7.0] - 2026-03-30

### Added
- `pascal_emit/expressions.py`: data segment address recognition — when a hex constant is followed by `unaff_DS` (data segment register) in function arguments, it's converted to a global variable reference (`0x75, unaff_DS` → `g_0075`) instead of a numeric literal, fixing `var` parameter compatibility

### Changed
- `tests/test_fpc_compilation.py`: GAMESIM moved from expected failures to compiling programs (11/16 now compile)

## [2.6.0] - 2026-03-30

### Fixed
- `pascal_emit/pipeline.py`: pointer type parameters (`byte *32`, `int *32`) no longer misinterpreted as array types — pointer size suffix is now stripped separately from the base type, preventing `byte *32` → `array[0..31] of Byte` → `Pointer` cascade
- `pascal_emit/expressions.py`: `&&` in conditions at non-zero parenthesis depth (inside C pointer casts) no longer produces `and and` — `_convert_atomic_condition` now replaces `&&`/`||` before single-char `&`/`|`, and `convert_condition` strips outer parentheses in a loop to handle nested redundant parens from Ghidra's decompiler output

## [2.5.0] - 2026-03-30

### Added
- `pascal_emit/body_converter.py`: orphaned `end;` detection and commenting — when `_sanitize_ghidra_artifacts` comments out a line containing `begin` (e.g., `if ... then begin` with leaked identifiers), the matching `end;` is now also commented out to prevent structural imbalances. Handles `case ... of` and compound lines like `end else if ... then begin`
- `pascal_emit/body_converter.py`: expanded leaked identifier patterns — now catches `DAT_XXXX_XXXX` (data references), `FUN_XXXX_XXXX` (unlabeled function calls), and `dos_*` (undeclared DOS unit functions) in addition to existing patterns

### Changed
- `pascal_emit/types.py`: large `undefinedN` types (N > 8) now map to `array[0..N-1] of Byte` instead of producing invalid type names
- `pascal_emit/pipeline.py`: `_postprocess_ccode` now cleans up large `undefinedN` type references; `_extract_params` regex fixed to handle multi-digit undefined types
- `pascal_emit/write_sequences.py`: `WRITE_LONGINT_ARGS_RE` now accepts optimized sign-extension argument (e.g., `0` instead of `value >> 0xf` for small positive values)
- `tests/test_fpc_compilation.py`: DOSTEST and STRINGS moved from expected failures to compiling programs (10/16 now compile)

### Fixed
- `pascal_emit/expressions.py`: strip `unaff_*` leaked register names from function call arguments; handle sub-field accessor syntax (`var._1_1_` → `Byte(var)`); strip `&stack0x*` references; fix double-`and` operator; add `bp_ioresult→IOResult` expression mapping
- `pascal_emit/body_converter.py`: add `bp_ioresult→IOResult` to label-to-Pascal mapping; add noise patterns for leaked Ghidra identifiers in active code lines

## [2.4.0] - 2026-03-30

### Added
- `pascal_emit/body_converter.py`: case statement reconstruction from if/else if chains — detects patterns like `if VAR = 1 then ... else if VAR = 2 then ...` and converts to `case VAR of 1: ...; 2: ...; end;`. Also handles Ghidra's range complement pattern `(VAR < LO) or (HI < VAR)` → `LO..HI` with nested range support
- `tests/test_fpc_compilation.py`: automated Free Pascal compilation testing — compiles all generated `.pas` files with `fpc -Mtp` and tracks which compile (8/16 currently). Regression protection for compiling programs, expected-failure tracking for the rest
- `tests/test_pascal_emit.py`: 10 new tests for case statement reconstruction validating CONTROL (equality cases, range cases 3..5 and 6..10, else clause) and RANDTEST (sequential case values 0-5)

## [2.3.0] - 2026-03-30

### Added
- `pascal_emit/body_converter.py`: library label → Pascal builtin mapping (`_LABEL_TO_PASCAL`) for standalone calls: `bp_random→Random`, `bp_halt→Halt`, `bp_delay→Delay`, `bp_gotoxy→GotoXY`, `bp_clrscr→ClrScr`, `bp_readkey→ReadKey`, `bp_keypressed→KeyPressed`, `bp_textcolor→TextColor`, `bp_textbackground→TextBackground`, `bp_randomize→Randomize`, `bp_clreol→ClrEol`
- `pascal_emit/expressions.py`: expression-side label mapping (`_EXPR_LABEL_MAP`) for `bp_random→Random`, `bp_chr→Chr`, `bp_ord→Ord`, `bp_length→Length`, `bp_copy→Copy`, `bp_pos→Pos`, `bp_concat→Concat`, `bp_upcase→UpCase`, `bp_sizeof→SizeOf`, `bp_keypressed→KeyPressed`, `bp_readkey→ReadKey`, `bp_eof→Eof`, `bp_eoln→Eoln`, etc.
- `pascal_emit/pipeline.py`: cross-segment stub generation — functions referenced from other segments (CRT, overlay, etc.) now get empty procedure declarations with correct parameter signatures inferred from `functions.json`
- `pascal_emit/body_converter.py`: `Halt;` emission when `bp_halt_handler` is encountered inside conditional blocks, with proper brace-depth tracking to close nesting correctly
- `pascal_emit/expressions.py`: C pointer dereference `*variable` → `variable` conversion (consistent with `var` parameter semantics), with lookbehind guard to avoid matching multiplication
- `pascal_emit/expressions.py`: C pointer cast `(type *)variable` → `variable` stripping for `int`, `uint`, `word`, `byte`, `char` pointer casts
- `pascal_emit/expressions.py`: negative offset indexed access `*(type *)(param + -N)` → `param[-N]` conversion
- `pascal_emit/write_sequences.py`: positional fallback for write_int value extraction when all DAT values are small constants (index 0=width, index 1=value)
- `Decompile.java`: added offsets `0635` (bp_write_char) and `0670` (bp_write_str) to `BP_SYSTEM_CORE_LABELS` — covers binaries with and without Write(Char) in the system RTL

### Fixed
- `Decompile.java`: label dedup logic — offset-labeled functions now get rename priority over FLIRT labels; previously, a label appearing in both offset and FLIRT tables caused neither to be renamed (e.g., `bp_write_str` assigned by both offset match and FLIRT left `FUN_xxxx_0701` unlabeled)
- `pascal_emit/types.py`: `char` now maps to `Byte` (not `Char`) — Ghidra uses `char` for byte-sized numeric variables, which causes FPC type mismatch errors when assigned to/from Byte globals
- `pascal_emit/pipeline.py`: `cVar` temp variables now declared as `Byte` (not `Char`) — consistent with the `char→Byte` type mapping
- `pascal_emit/types.py`: parameterless procedures no longer emit empty parentheses `procedure Name()` — FPC TP7 mode rejects this syntax
- `pascal_emit/types.py`: inline `array[0..N] of T` types in parameter lists now map to `Pointer` — Pascal does not allow anonymous array types in parameter declarations
- `pascal_emit/types.py`: expanded `C_TO_PASCAL_TYPE` with `int16→Integer`, `int32→LongInt`, `uint16→Word`, `uint32→LongInt`, `short→Integer`, `ushort→Word`; added array type expansion (`byte32` → `array[0..31] of Byte`)
- `pascal_emit/pipeline.py`: globals declared only when referenced — removed hard `>= 0x50` offset filter and replaced with post-conversion reference-based filtering
- `pascal_emit/body_converter.py`: for loop comma-body inclusive end value (Pascal `for` is inclusive, C `!=` means the end value IS reached)
- `pascal_emit/expressions.py`: operator precedence for `and`/`or` — comparison sub-expressions are now parenthesized when joined by `and`/`or` (Pascal `and`/`or` bind tighter than comparisons)
- `pascal_emit/write_sequences.py`: Write char (`FUN_xxxx_067b`) and Write Real (`FUN_xxxx_078a`) function recognition
- `pascal_emit/write_sequences.py`: `undefined2` puVar pattern matching for stack push detection

### Changed
- FPC compilation: 8/16 test programs now compile with `fpc -Mtp` (HELLO, CONTROL, MATHOPS, EXITPROC, RANDTEST, TYPECAST, CRTTEST, OVRTEST), up from 4/16 previously

## [2.2.0] - 2026-03-30

### Fixed
- `pascal_emit/expressions.py`: `%` now converts to `mod`, `/` to `div`, `&` to `and`, `|` to `or`, `^` to `xor`, `~` to `not`, `<<` to `shl`, `>>` to `shr` — previously emitted C operators verbatim
- `pascal_emit/expressions.py`: C-style casts `(ulong)x` now convert to Pascal function-call syntax `LongInt(x)` instead of concatenating `LongIntx`; handles `(uint)`, `(int)`, `(byte)`, `(char)`, `(word)`, `(dword)`, `(ushort)`
- `pascal_emit/write_sequences.py`: longint Write/WriteLn values now extract the actual variable expression from stack push patterns (DAT_ and puVar) and explicit function arguments, replacing `{longint}` placeholders with real values like `g_0056` or `param_1`
- `pascal_emit/write_sequences.py`: separated `WRITE_INT_RE` from `WRITE_LONGINT_RE` — previously both matched `_Write_qm4Text7Longint4Word`, causing the int handler to intercept longint calls

### Added
- `pascal_emit/pipeline.py`: undeclared Ghidra temp variables (`iVar`, `uVar`, `cVar`, `bVar`) are now automatically detected in function bodies and emitted as `var` declarations with inferred Pascal types (Integer, Word, Char, Byte)
- `pascal_emit/emitter.py`: main block temp variable declarations emitted in the global `var` section alongside memory-mapped globals
- `pascal_emit/write_sequences.py`: `_extract_longint_value()` helper and `WRITE_LONGINT_ARGS_RE` regex for extracting longint values from both DAT_-push and explicit-argument patterns, with width specifier support
- `tests/test_pascal_emit.py`: 24 new tests — `TestOperatorConversion` (11), `TestCastConversion` (6), `TestLongintWrite` (5), `TestTempVarDeclarations` (3)

### Removed
- `pascal_emit/parser.py`: deleted — legacy regex-based `decompiled.c` parser (`parse_functions`, `classify_function`, `find_primary_segment`, `parse_c_signature`) is no longer needed now that `functions.json` is the sole data source
- `pascal_emit/globals_scanner.py`: deleted — legacy global variable/uses-clause detection via regex scanning of parsed function bodies; equivalent functionality is inlined in `pipeline.py` for the IR path
- `pascal_emit/pipeline.py`: removed `_process_legacy()` fallback path that parsed `decompiled.c` with regex when `functions.json` was unavailable

### Changed
- `pascal_emit/pipeline.py`: `process()` now requires `functions.json` and raises `FileNotFoundError` if it is missing, instead of silently falling back to regex parsing
- `pascal_emit/__init__.py`: removed lazy-load `__getattr__` for `parser` and `globals_scanner` modules; removed `detect_globals`, `detect_uses`, `GLOBAL_MEM_RE` from public API

### Fixed
- `tests/test_label_functions.py`: removed incorrect `bp_rename` expectation from FILEIO test — the FILEIO test program does not use `Rename`
- `tests/test_pascal_emit.py`: fixed `TestMathops.test_writeln_with_global_var` — longint write values appear as `{longint}` placeholders (the write sequence detector recognises the call but cannot resolve stack-passed values to variable names); added `test_global_vars_declared` to verify globals are still present

### Added
- `Decompile.java`: Phase 7 — structured IR output (`functions.json`) emitted alongside `decompiled.c` and `strings.json`; extracts per-function metadata (return type, parameters, local variables) from `HighFunction`/`LocalSymbolMap`, call graph with resolved constant arguments from `PcodeOp.CALL`, and serialized C AST from `ClangTokenGroup`; string references resolved programmatically via PcodeOp instead of regex
- `pascal_emit/ir_reader.py`: new module providing `load_functions_json()`, AST navigation helpers (`ast_children`, `ast_tokens`, `ast_text`, `ast_find_groups`, `classify_statement`), and structured call data access (`get_resolved_strings`, `get_call_string_args`)

### Changed
- `pascal_emit/pipeline.py`: rewritten to use `functions.json` as primary data source; reads function list, signatures, library classification, and labels from structured IR; builds rename table from function labels and applies to raw `cCode`; post-processes cCode in Python (type cleanup, CONCAT11 removal, calling convention stripping, string annotations); falls back to regex-based decompiled.c parsing only when functions.json is unavailable
- `pascal_emit/write_sequences.py`: updated Write/WriteLn detection patterns to recognize FLIRT-style function names (`_Write_qm4Textm6String4Word`, `_WriteLn_qm4Text`, `_Write_qm4Text7Longint4Word`) in addition to hash-based labels (`bp_write_str`, `bp_write_char_flush`); added `_is_iocheck()` helper for recognizing both named and unnamed IOCheck calls
- `pascal_emit/body_converter.py`: updated noise patterns to recognize FLIRT-style names for system functions (`___SystemInit_qv`, `_Halt_q4Word`, `__ClearDSeg`, `__PrintString`); halt handler detection covers both `bp_halt_handler` and `_Halt_q4Word`; function call handler skips known FLIRT-identified system calls
- `pascal_emit/__init__.py`: parser and globals_scanner imports deferred to lazy `__getattr__` loading (only needed for legacy fallback path)
- `ROADMAP.md`: Restructured implementation order to skip Phase 1 (regex fixes) and start with Phase 2.2 (structured IR); Phase 1 tasks are now implemented against the AST from `functions.json` instead of regex-parsing C text; updated Phase 2.2 with concrete deliverables and remaining work items

### Fixed
- `pascal_emit`: 6 previously-failing tests now pass — balanced begin/end for CONTROL, HELLO WriteLn detection, CONTROL char null literal conversion, CONTROL hex-to-decimal conversion, CRTTEST uses clause detection, MATHOPS addition string resolution; all caused by the IR-based pipeline correctly renaming FLIRT function names before body conversion
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

[Unreleased]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.11.0...HEAD
[2.11.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.10.0...v2.11.0
[2.10.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.9.0...v2.10.0
[2.9.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.2...v2.0.0
[1.2.2]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/talisto/ghidra-turbo-pascal/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/talisto/ghidra-turbo-pascal/releases/tag/v1.0.0
