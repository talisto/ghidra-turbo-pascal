# Roadmap: From Decompiled C to Compilable Pascal Source

> A prioritized plan for producing working Turbo Pascal 7 source files from Ghidra-decompiled DOS MZ executables. The goal is not byte-identical reproduction — it's **functional Pascal programs** that compile with TP7/FPC and produce the same observable behavior as the original.

## Current State (v2.24.0)

| Capability | Status |
|------------|--------|
| String annotation (Pascal length-prefixed strings) | ✅ Complete |
| FLIRT + hash-based RTL function labeling (~90 signatures) | ✅ Complete |
| Single-pass headless decompilation pipeline | ✅ Complete |
| Overlay (.OVR) loading | ✅ Complete |
| 16 test binaries with full pytest coverage | ✅ Complete (659 tests) |
| C-to-Pascal transpiler (`pascal_emit/`) | ✅ Functional — 14/16 compile |
| Library code elimination in decompiled output | ✅ Complete |
| Artifact cleanup (CONCAT11, unaff_DS, calling conventions) | ✅ Complete |
| BP7 type definitions registered in Ghidra (TextRec, FileRec, etc.) | ✅ Registered (not yet applied) |
| Write/WriteLn sequence detection and merging | ✅ Complete (str, int, longint, char, real, bool) |
| Case statement reconstruction | ✅ Complete (if/else chains → case..of with ranges) |
| For loop conversion | ✅ Complete (counting loops to for..to/downto) |
| Auto-declared temp variables | ✅ Complete (iVar, uVar, cVar, bVar) |
| Global variable detection and declaration | ✅ Complete |
| String global auto-retyping | ✅ Complete (Integer → String[N] when string-assigned) |
| Cross-segment Proc_/Func_ stub generation | ✅ Complete |
| Noise line suppression | ✅ Complete (~50 patterns) |
| CARRY2 32-bit carry arithmetic conversion | ✅ Complete |
| Proc_ var parameter temp variable generation | ✅ Complete |
| Array element assignment conversion | ✅ Complete |
| Func_() placeholder args in WriteLn | ✅ Complete |
| DDPlus library function conversion | ✅ Complete (16 functions + string resolution) |
| String concatenation sequence merging | ✅ Complete (bp_delete + bp_str_append → Concat) |

### Current Pascal Output Quality (v2.24.0)

Assessed against 16 test programs with known original source:

| Metric | Value |
|--------|-------|
| Programs that compile (FPC -Mtp -Sc) | **14/16** (87.5%) |
| Programs **successfully transpiled** (compile + 0 non-stub commented lines) | **9/16** (56.25%) |
| Total commented lines (non-stub) | **79** across all programs |

**Quality tier breakdown:**

| Tier | Programs | Count |
|------|----------|-------|
| **Clean** (compiles, 0 non-stub commented lines) | CONTROL, CRTTEST, DDTEST, EXITPROC, GAMESIM, HELLO, MATHOPS, OVRTEST, TYPECAST | 9 |
| **Incomplete** (compiles, but has commented-out code = missing functionality) | DOSTEST(18), PROCFUNC(5), PTRMEM(8), RANDTEST(1), RECORDS(7), STRINGS(25) | 6 |
| **Broken** (does not compile) | DDTEST(ddplus unit), FILEIO(15) | 2 |

> **Note**: DDTEST has 0 commented lines (Clean tier) but cannot compile with FPC because it requires the external `ddplus` unit. FILEIO has unresolved file I/O operations.

| Area | Status | Notes |
|------|--------|-------|
| Trivial programs (WriteLn only) | ✅ Works | HELLO.pas compiles and runs |
| Global variables | ✅ Working | Named as `g_XXXX`, auto-typed (Integer/Word/Byte/String[N]) |
| WriteLn/Write sequences | ✅ Working | Str, Int, LongInt, Char, Real, Bool merged into Write calls |
| Arithmetic operators | ✅ Fixed | `div`, `mod`, `and`, `or`, `xor`, `not`, `shl`, `shr` |
| Bitwise/logical operators | ✅ Fixed | `and`/`or`/`xor`/`not`/`shl`/`shr` converted |
| For loops | ✅ Fixed | Counting loops converted to `for..to/downto` |
| Case statements | ✅ Fixed | `if/else if` chains → `case...of` with ranges |
| DDPlus library functions | ✅ Working | 16 functions with string resolution and char conversion |
| String concatenation sequences | ✅ Working | bp_delete + bp_str_append → swriteln('s' + g_XXXX) |
| String operations | ❌ Non-functional | String type lost; Concat/Copy/Pos/Length/Delete/Insert are raw calls |
| Record types | ❌ Not recovered | Field access as `*(int *)(ptr + 0x15)` |
| Nested procedures | ❌ Not recovered | Flattened to separate procedures with frame pointer params |
| File I/O | ❌ Non-functional | Assign/Reset/Rewrite/ReadLn are unresolved FUN_xxxx calls |
| Type casts | ✅ Fixed | `(ulong)x` → `LongInt(x)`, `(uint)x` → `Word(x)`, etc. |
| 32-bit arithmetic | ❌ Broken | LongInt operations decomposed to 16-bit carry pairs |
| Undeclared variables | ✅ Fixed | `iVar1`, `uVar5` auto-declared with inferred types |
| WriteLn longint values | ✅ Fixed | Values extracted from stack push patterns |
| Array types | ❌ Not recovered | Array access as pointer arithmetic |
| CRT functions | ✅ Working | WhereX, WhereY, GotoXY, TextAttr, ReadKey, KeyPressed |
| Case statements | ✅ Fixed | `if/else if` chains reconstructed to `case...of` with ranges |
| String operations | ❌ Non-functional | String type lost; Concat/Copy/Pos/Length/Delete/Insert are raw calls |
| Record types | ❌ Not recovered | Field access as `*(int *)(ptr + 0x15)` |
| Nested procedures | ❌ Not recovered | Flattened to separate procedures with frame pointer params |
| File I/O | ❌ Non-functional | Assign/Reset/Rewrite/ReadLn are unresolved FUN_xxxx calls |
| Function return values | ❌ Broken | C `return` not always converted to `FuncName := value` |
| Type casts | ✅ Fixed | `(ulong)x` → `LongInt(x)`, `(uint)x` → `Word(x)`, etc. |
| 32-bit arithmetic | ❌ Broken | LongInt operations decomposed to 16-bit carry pairs |
| Undeclared variables | ✅ Fixed | `iVar1`, `uVar5` auto-declared with inferred types |
| WriteLn longint values | ✅ Fixed | Values extracted from stack push patterns, no more `{longint}` |
| Array types | ❌ Not recovered | Array access as pointer arithmetic |

---

## Phase 1 — Fix pascal_emit.py Fundamentals

**Priority**: Critical | **Impact**: Makes simple programs compile | **Difficulty**: Low–Medium

These are pure Python fixes in `pascal_emit.py` that don't require any Ghidra changes. They address syntax errors and missing Pascal constructs.

### 1.1 Fix Arithmetic and Bitwise Operators ✅

**Status**: Complete — `convert_expression()` and `convert_condition()` now convert all C operators to Pascal equivalents.

| C Pattern | Output |
|-----------|--------|
| `a / b` (integer context) | `a div b` |
| `a % b` | `a mod b` |
| `a & b` | `a and b` |
| `a \| b` | `a or b` |
| `a ^ b` | `a xor b` |
| `~a` | `not a` |
| `a << n` | `a shl n` |
| `a >> n` | `a shr n` |
| `(ulong)x` | `LongInt(x)` |
| `(uint)x` | `Word(x)` |

### 1.2 Implement For Loop Conversion ✅

**Status**: Complete — `_convert_for_loop()` in `body_converter.py` converts C `for` loops to Pascal `for..to/downto` for simple counting patterns. Complex loops fall back to `while` with initialization.

### 1.3 Fix Case Statement Reconstruction ✅

**Status**: Complete — `_reconstruct_case_statements()` post-processes Pascal output to detect if/else if chains comparing the same variable to integer constants and converts them to `case VAR of` blocks. Handles Ghidra's range complement pattern `(VAR < LO) or (HI < VAR)` → `LO..HI` with nested range support.

| Input Pattern | Output |
|---------------|--------|
| `if V = 1 then ... else if V = 2 then ...` | `case V of 1: ...; 2: ...; end;` |
| `(V < 3) or (5 < V)` (complement) | `3..5: ...` (range case) |
| Nested complements | Multiple range cases in single case statement |

### 1.4 Fix Variable Declarations ✅

**Status**: Complete — Ghidra temp variables (`iVar`, `uVar`, `cVar`, `bVar`) are now auto-detected in function bodies and emitted as `var` declarations with inferred Pascal types. For the main block, they're added to the global `var` section.

### 1.5 Fix Function Return Value Assignment

C `return expr;` must become `FuncName := expr;` in Pascal. The current code handles this but breaks on:
- Complex return expressions with casts: `return CONCAT22(a, b);`
- Functions where the return type detection fails
- Multiple return paths

### 1.6 Remove C Cast Syntax ✅

**Status**: Complete — C-style casts now convert to Pascal function-call syntax: `(ulong)x` → `LongInt(x)`, `(uint)x` → `Word(x)`, etc. CONCAT11/CONCAT22 patterns are also handled.

---

## Phase 2 — Improve Ghidra Output Quality (Decompile.java)

**Priority**: High | **Impact**: Makes complex programs decompilable | **Difficulty**: Medium

Changes to `Decompile.java` that improve the C output fed to `pascal_emit.py`.

### 2.1 Apply Function Signatures to RTL Functions

The ~90 labeled `bp_*` functions currently have no type information in the Ghidra program model. Setting correct signatures via `Function.setReturnType()` and `func.replaceParameters()` will:
- Eliminate `unaff_DS`, `extraout_AH` artifacts in callers
- Enable Ghidra's type propagation engine
- Produce cleaner C output with correct parameter counts

**Priority signatures:**

| Function | Signature | Impact |
|----------|-----------|--------|
| `bp_write_str` | `(TextRec*, Word, PChar, Word): void` | Cleaner WriteLn reconstruction |
| `bp_write_int` | `(TextRec*, Integer, Integer): void` | Fix `{int}` placeholders |
| `bp_random` | `(Word): Word` | Type propagation to callers |
| `bp_str_copy_bounded` | `(Byte, PChar, Word, PChar, Word): void` | String operation recovery |
| `bp_file_assign` | `(var FileRec, PChar): void` | File I/O recovery |

### 2.2 Structured IR: HighFunction/PcodeOp/ClangTokenGroup → functions.json

**Status**: ✅ Infrastructure complete — `Decompile.java` Phase 7 emits `functions.json`, `pascal_emit/ir_reader.py` provides navigation API.

The old approach: `Decompile.java` emits flat C text → `pascal_emit` regex-parses it. Fragile, lossy, and error-prone.

The new approach: `Decompile.java` extracts structured data from Ghidra's decompiler internals and emits `functions.json` alongside `decompiled.c`. The `pascal_emit` pipeline consumes the structured IR directly and walks the AST to emit Pascal code, eliminating regex-based parsing.

**`functions.json` schema** (per function):
- `name`, `address`, `returnType`: function identification and signature
- `parameters`: name, type, size from `HighFunction.LocalSymbolMap`
- `locals`: name, type from decompiler-inferred local variables
- `calls`: `PcodeOp.CALL` targets with argument constants and **resolved string references** (replaces `annotateLine()` regex)
- `isLibrary`, `label`, `description`: function classification
- `cCode`: flat C text (debugging fallback)
- `ast`: serialized `ClangTokenGroup` tree — the structured C statement/token hierarchy

**Remaining work for 2.2:**
1. ✅ `Decompile.java` Phase 7: emit `functions.json` with AST, params, locals, calls
2. ✅ `pascal_emit/ir_reader.py`: load + navigate structured IR (AST helpers, call data access)
3. ✅ `pascal_emit/pipeline.py`: load `functions.json` when available, attach IR to `func_info`
4. ⬜ Regenerate test outputs (`./tests/run_tests.sh`) to produce `functions.json` files
5. ⬜ Rewrite `body_converter.py` to walk AST nodes instead of regex-parsing C lines
6. ⬜ Rewrite `write_sequences.py` to use resolved call data from `calls[]` field
7. ⬜ Rewrite `expressions.py` to convert AST expression subtrees instead of regex
8. ⬜ Rewrite `parser.py` to read function metadata from `functions.json` instead of parsing C signatures
9. ⬜ Update `globals_scanner.py` to use AST variable references
10. ⬜ Write tests for `ir_reader.py` and JSON-based conversion

### 2.3 Label More Library Functions

Only ~90 RTL functions are currently identified. Many remain as `FUN_xxxx_xxxx`, especially:
- String manipulation: `FUN_xxxx_07ab` (likely `Pos`), `FUN_xxxx_076a` (likely `Copy`)
- File I/O: `FUN_1094_08b1` (likely `Assign`), `FUN_1094_0ae3` (likely `Reset`)
- CRT: `FUN_xxxx_067b` (likely `Write` variant)

**Approach:** Expand the hash-based signature database by running `CreateBPSignatures.java` against more test binaries that exercise different RTL functions. Each newly identified function directly improves the transpiled output.

### 2.4 Global Variable Labeling in Ghidra

Create named labels at known global variable addresses using `createLabel(address, name)` and `createData(address, type)`. This makes the decompiler output use names instead of `*(int *)0x52`.

**Initial approach:** For test binaries where we know the original source, extract the variable→offset mapping and apply it. For unknown binaries, use heuristic naming (`g_XXXX` is already done by `pascal_emit.py` — push this into Ghidra so the decompiler itself produces better output).

### 2.5 Struct Recovery from Pointer Offset Patterns

When a parameter is dereferenced at multiple fixed offsets (`*(int *)(param + 0x15)`, `*(int *)(param + 0x17)`, `*(byte *)(param + 0x1e)`), auto-create a `StructureDataType` and apply it.

**BP7 advantage**: Records are always byte-packed — no alignment padding to guess. The offset pattern directly reveals the struct layout.

**Implementation**: After initial decompilation, scan `HighFunction` for `LOAD`/`STORE` operations with `base + constant_offset` patterns. Group by base parameter. Create struct types. Re-decompile to get field names in output.

---

## Phase 3 — Pascal Language Feature Recovery

**Priority**: High | **Impact**: Converts from C-like to idiomatic Pascal | **Difficulty**: Medium–High

### 3.1 String Type and Operations

This is the **single hardest problem**. Borland Pascal strings are length-prefixed (`string[N]` = 1 length byte + N data bytes). Ghidra sees them as byte arrays.

**What needs to happen:**
1. **In Decompile.java**: Define a `ShortString` type and apply it where string parameters are detected (functions receiving `byte *` that's passed to `bp_str_*` calls)
2. **In pascal_emit.py**: Map labeled RTL calls to Pascal built-ins:
   - `bp_str_copy_bounded()` → string assignment (`:=`)
   - `bp_str_concat()` → `+` operator or `Concat()`
   - `_Copy_qm6String7Integert2()` → `Copy(s, idx, len)`
   - `_Delete_qm6String7Integert2()` → `Delete(s, idx, len)`
   - `_Pos_qm6Stringt1()` → `Pos(substr, s)`
   - `_Length_q6String()` → `Length(s)`
   - `_Val__Longint_qm6Stringm7Integer()` → `Val(s, v, code)`
   - `_Str__Longint_qm7Integerm6String()` → `Str(v, s)`

3. **String literal recovery**: The current 3-tier strategy (annotation → DAT_ position → puVar try-all) works for WriteLn but fails for string assignments. Need to resolve string constants used in `bp_str_copy_bounded` calls.

### 3.2 Record Type Reconstruction

Even without Ghidra struct recovery (Phase 2.5), `pascal_emit.py` can reconstruct record-style access:

1. **Detect record parameters**: functions where `param_N` is cast to `int` and then accessed at fixed offsets (`*(int *)(iVar + 0x15)`)
2. **Build offset→field map**: for each function, collect all offsets accessed through the same base pointer
3. **Emit record type**: generate `type RecN = record field_00: ...; field_02: ...; end;`
4. **Replace access patterns**: `*(int *)(iVar1 + 0x15)` → `p.field_15` (or `p.hp` if named)

### 3.3 Nested Procedure Recovery

Ghidra flattens nested procedures. The parent's stack frame is passed as a parameter. Detection:
- Inner function receives a pointer parameter that accesses parent's local variables at fixed offsets
- Call site passes `&stack0xfffe` (address of stack frame)

**Approach**: Detect `&stackN` arguments at call sites. Mark the called function as a nested procedure. In the emitted Pascal, re-nest it inside the parent and replace frame pointer access with direct variable references.

### 3.4 File I/O Operation Recovery

File operations use a specific pattern:
1. `bp_file_assign(var f, name)` — `Assign(f, name)`
2. `bp_file_reset(var f)` or `bp_file_rewrite(var f)` — `Reset(f)` / `Rewrite(f)`
3. `bp_read_*` / `bp_write_*` — `Read(f, ...)` / `Write(f, ...)`
4. `bp_file_close(var f)` — `Close(f)`

Many of these are currently unlabeled `FUN_xxxx_xxxx` calls. Labeling them (Phase 2.3) is prerequisite. Then `pascal_emit.py` maps bp_* names to Pascal built-ins.

### 3.5 32-bit (LongInt) Arithmetic Recovery

Ghidra decomposes 32-bit operations on 16-bit DOS into two-word carry-propagation patterns:
```c
// Adding 1000 to a longint:
uVar1 = *(uint *)LOW_WORD;
*(int *)LOW_WORD = uVar1 + 1000;
*(int *)HIGH_WORD = *(int *)HIGH_WORD + (uint)(0xfc17 < uVar1);
```

**Approach**: Pattern-match the carry idiom in `pascal_emit.py`. Detect paired high/low word accesses at adjacent addresses. Emit as single LongInt operations: `longvar := longvar + 1000`.

---

## Phase 4 — Program Structure Recovery

**Priority**: Medium | **Impact**: Produces idiomatic Pascal | **Difficulty**: Medium

### 4.1 Type Block Emission

Recover and emit Pascal `type` declarations:
- Record types (from Phase 3.2)
- Array types: detect pointer arithmetic with element-size multiplication (`ptr + i * 2`)
- Enum types: detect switch/case on a variable with small integer constants

### 4.2 Const Block Emission

Recover `const` declarations:
- String constants already in `strings.json` — emit as named consts
- Numeric constants used in multiple places — heuristic naming
- Typed constants (initialized variables; Borland Pascal stores these differently from `var`)

### 4.3 Uses Clause Detection

Already partially implemented (detects `Crt`, `Dos` from library function names). Extend:
- Detect `Overlay` unit usage from overlay-related calls
- Detect `Printer` unit from printer-specific I/O
- Detect custom units from segment boundaries (each unit compiles to its own segment)

### 4.4 Entry Point / Main Block Cleanup

The entry function contains system initialization code (runtime init, I/O init, module init) mixed with user code. Current noise stripping is extensive but incomplete. Improve:
- Better boundary detection between init code and user's `begin...end.`
- Handle `ExitProc` setup patterns
- Support `{$M stacksize, heapmin, heapmax}` directives from stack check parameters

---

## Phase 5 — Validation & Iteration

**Priority**: Medium | **Impact**: Confidence in output | **Difficulty**: Medium

### 5.1 Compilation Testing with Free Pascal ✅

**Status**: Complete — `tests/test_fpc_compilation.py` automatically compiles all generated `.pas` files with `fpc -Mtp` (Turbo Pascal mode). Regression protection for 8 currently-compiling programs, expected-failure tracking for 8 programs with known issues. Run with `pytest tests/test_fpc_compilation.py -v`.

**Current scorecard** (15/16 compile, 7/16 successfully transpiled):
| Tier | Programs |
|------|----------|
| Clean (0 non-stub commented lines) | CONTROL, CRTTEST, EXITPROC, HELLO, MATHOPS, OVRTEST, TYPECAST |
| Incomplete (commented-out code = missing functionality) | DDTEST, DOSTEST, GAMESIM, PROCFUNC, PTRMEM, RANDTEST, RECORDS, STRINGS |
| Broken (does not compile) | FILEIO |

### 5.2 Behavioral Comparison Testing

For programs that compile:
- Run original EXE in DOSBox (capturing stdout)
- Run FPC-compiled version natively (capturing stdout)
- Diff the outputs

This gives a definitive answer: does the decompiled program produce the same behavior?

### 5.3 Test-Driven Development Loop

Each generated `.pas` file has a corresponding original `.PAS` in `tests/data/`. Use the originals as ground truth:
- Compare control flow structure
- Compare variable usage
- Compare string output
- Track which constructs are correctly recovered vs. still broken

---

## Phase 6 — Advanced Recovery (Stretch Goals)

**Priority**: Low | **Impact**: High for complex programs | **Difficulty**: High

### 6.1 Assembly-Level Matching (asm-differ)

Adapt [asm-differ](https://github.com/simonlindholm/asm-differ) for x86-16 to compare original vs. recompiled functions instruction-by-instruction. This is the gold standard from matching decomp projects (zeldaret/oot, decomp.me).

### 6.2 Calling Convention Refinement

Define a proper BP7 calling convention via Ghidra's `.cspec` mechanism or `setCallingConvention("__pascal")`. This eliminates most register artifacts at the Ghidra level rather than cleaning them up in post-processing.

### 6.3 Data Section Reproduction

Extract initialized data directly from the EXE to produce Pascal `const` and `var` blocks matching original layout. Combined with string table extraction, this recovers all static data.

### 6.4 BP7 Ghidra Data Type Archive (.gdt)

Package all BP7 types, function signatures, and calling conventions into a reusable `.gdt` archive. Valuable community contribution for anyone working with Borland Pascal binaries in Ghidra.

### 6.5 Dynamic Analysis with DOSBox

Run original EXE in DOSBox with instrumentation to trace function calls, memory writes, and I/O operations. Compare traces against reconstructed source for verification.

---

## Implementation Order

The recommended sequence, prioritizing structured IR over regex-based conversion:

1. **Phase 2.2** — ✅ Emit structured IR (`functions.json`) from Ghidra *(infrastructure complete)*
2. **Phase 2.2 cont.** — Rewrite `pascal_emit` modules to consume AST from `functions.json`
3. **Phase 2.1** — Apply RTL function signatures in Ghidra (improves IR quality)
4. **Phase 2.3** — Label more library functions
5. **Phase 3.1** — String operation recovery (using structured call data)
6. **Phase 5.1** — Set up FPC compilation testing
7. **Phase 3.2** — Record type reconstruction (using AST pointer patterns)
8. **Phase 3.4** — File I/O recovery
9. **Phase 3.5** — LongInt arithmetic recovery
10. **Phase 2.5** — Ghidra-level struct recovery
11. **Phase 4** — Program structure (types, consts, uses)
12. **Phase 5.2–5.3** — Behavioral comparison testing
13. **Phase 6** — Advanced recovery (as needed)

> **Note on Phase 1**: The original Phase 1 (fix regex-based operators, for loops, case statements, etc.) is **superseded by Phase 2.2**. Instead of fixing fragile regex patterns, we implement these conversions against the structured AST from `functions.json`. The Phase 1 tasks describe *what* to convert — the approach is now structured IR, not regex.

**Milestone targets:**
- **M1**: HELLO, CONTROL, MATHOPS compile with FPC (Phase 1 complete)
- **M2**: PROCFUNC, DOSTEST, EXITPROC compile (Phase 2+3 partial)
- **M3**: STRINGS, RECORDS, FILEIO compile (Phase 3 complete)
- **M4**: All 16 test programs compile (Phase 4 complete)
- **M5**: All programs produce identical stdout output (Phase 5 complete)
