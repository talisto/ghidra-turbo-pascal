# Roadmap: From Decompiled C to Reproducible Executable

> A prioritized plan for improving the ghidra-turbo-pascal decompilation pipeline, with the ultimate goal of producing source code that can be recompiled into a byte-identical executable.

## Current State (v2.0.0)

| Capability | Status |
|------------|--------|
| String annotation (Pascal length-prefixed strings) | ✅ Complete |
| FLIRT + hash-based RTL function labeling (~90 signatures) | ✅ Complete |
| Single-pass headless decompilation pipeline | ✅ Complete |
| Overlay (.OVR) loading | ✅ Complete |
| 16 test binaries with full pytest coverage (234 tests) | ✅ Complete |

### What's Still Missing

The decompiled output still has:
- Raw memory addresses (`*(undefined2 *)0x71 = 100`) instead of named variables
- Unnamed application functions (`FUN_1000_000b`)
- No data types — everything is `undefined1`/`undefined2`/`int`
- No record/struct recovery
- No function signatures (parameter types, return types)
- Ghidra register artifacts (`unaff_DS`, `extraout_AH`, `CONCAT11`)

---

## Phase 1 — Data Type & Struct Recovery

**Priority**: High | **Impact**: Transformational | **Difficulty**: Medium

### 1.1 Define Borland Pascal RTL Types in Ghidra

Create Ghidra `StructureDataType` definitions for standard BP7 types and register them via `Decompile.java` before decompilation begins.

**Key types to define:**

| Type | Size | Key Fields |
|------|------|------------|
| `TextRec` | 263 bytes | `Handle`, `Mode`, `BufSize`, `Private`, `BufPos`, `BufEnd`, `BufPtr`, `OpenFunc`, `InOutFunc`, `FlushFunc`, `CloseFunc`, `UserData`, `Name`, `Buffer` |
| `FileRec` | 128 bytes | `Handle`, `Mode`, `RecSize`, `Private`, `UserData`, `Name` |
| `SearchRec` | 43 bytes | `Fill`, `Attr`, `Time`, `Size`, `Name` |
| `DateTime` | 12 bytes | `Year`, `Month`, `Day`, `Hour`, `Min`, `Sec` |
| `Registers` | 16 bytes | `AX`/`AL`/`AH`, `BX`/`BL`/`BH`, `CX`/`CL`/`CH`, `DX`/`DL`/`DH`, `BP`, `SI`, `DI`, `DS`, `ES`, `Flags` |
| `ShortString` | 256 bytes | `Length` (byte) + `Data` (255 bytes) |

**Implementation**: Add a `registerBP7Types()` method to `Decompile.java` that creates these via `currentProgram.getDataTypeManager().addDataType()`.

**Impact**: Every `*(undefined2 *)(param_1 + 0x1a)` in TextRec-handling code becomes `file.bufPos`.

### 1.2 Function Signature Annotation

Apply correct parameter and return types to labeled RTL functions via the Ghidra API.

**Priority signatures:**

| Function | Signature |
|----------|-----------|
| `bp_random` | `Random(Range: Word): Word` |
| `bp_str_copy` | `Copy(S: String; Index, Count: Word): String` |
| `bp_str_pos` | `Pos(Substr, S: String): Byte` |
| `bp_str_concat` | `Concat(S1, S2: String): String` |
| `bp_int_to_str` | `Str(Value: Integer; var S: String)` |
| `bp_file_assign` | `Assign(var F: File; Name: String)` |
| `bp_file_reset` | `Reset(var F: File)` |
| `bp_file_close` | `Close(var F: File)` |
| `bp_halt` | `Halt(ExitCode: Word)` |

**Implementation**: After labeling functions, call `func.setReturnType()` and `func.replaceParameters()` with the correct types.

**Impact**: Eliminates `unaff_DS`, `extraout_AH` artifacts; propagates types through callers.

### 1.3 Automated Global Variable Recovery

Borland Pascal stores all globals at fixed DS-relative offsets, packed sequentially in declaration order with no alignment padding.

**Approach:**
1. Scan all decompiled functions for memory references to the data segment
2. Cluster references by offset range
3. Infer field sizes from Ghidra's assigned types (`undefined1` = Byte, `undefined2` = Word/Integer, etc.)
4. Emit a "memory map" JSON mapping offset ranges to inferred types
5. Apply as labeled data at those offsets in the Ghidra program

**Impact**: Transforms `*(undefined2 *)0x71 = 100` → `player_hp = 100`.

### 1.4 Record (Struct) Detection from Access Patterns

When a pointer parameter is dereferenced at multiple offsets (`param + 0`, `param + 2`, `param + 50`), auto-create a struct type.

**BP7-specific advantage**: Records are always byte-packed (`{$A-}` semantics), so struct layout is straightforward — no padding to guess.

**Implementation**: Use Ghidra's `StructureDataType` API to create structs from observed offset patterns, then apply them to function parameters.

---

## Phase 2 — Function Signature & Type Propagation

**Priority**: High | **Impact**: High | **Difficulty**: Medium

### 2.1 Borland Pascal Calling Convention Modeling

BP7 uses a custom near-call convention:
- Parameters pushed right-to-left on the stack
- Caller cleans up stack
- Results in AX (byte/word) or DX:AX (longint)
- String parameters passed as `seg:off` far pointers even in near-call models
- `var` parameters passed as near/far pointers

**Implementation**: Define a custom calling convention via `func.setCallingConvention()`, or create a BP7-specific `.cspec` CompilerSpec if needed. This eliminates most `unaff_DS` and `extraout_AH` artifacts.

### 2.2 Return Type & Parameter Type Propagation

Once library functions have correct signatures, Ghidra's decompiler will propagate types through callers automatically. The key is seeding the right types on the ~90 known RTL functions.

**Chain reaction**: `uVar1 = bp_random(10)` → typed as `Word` → propagates through switch cases → eliminates casts.

### 2.3 Enum Type Creation

For known value sets, define `EnumDataType` instances:

| Enum | Values | Usage |
|------|--------|-------|
| `FileMode` | `fmClosed=0xD7B0, fmInput=0xD7B1, fmOutput=0xD7B2, fmInOut=0xD7B3` | TextRec.Mode field |
| `Boolean` | `False=0, True=1` | Boolean parameters/globals |

**Impact**: `*(char *)0x83 == 3` → `player.class == WARRIOR`.

---

## Phase 3 — Control Flow & Code Quality

**Priority**: Medium | **Impact**: Medium | **Difficulty**: Low–Medium

### 3.1 Var Parameter (Pass-by-Reference) Detection

BP7 `var` parameters are passed as pointers. The decompiler already shows `int *param_3` — post-process to recognize the Pascal idiom and simplify the mental model.

### 3.2 Library Code Elimination

The decompiled output contains all functions including RTL internals. Emit a separate "application-only" view excluding labeled library functions.

**Current state**: FLIRT/hash labeling identifies ~90 functions. Extend to mark them as library stubs or skip them in output.

**Impact**: User sees 20–50 application functions instead of 200+.

### 3.3 Switch Statement Recovery

Ghidra sometimes fails to recover `case X of` from computed jumps. Use `DecompInterface.toggleJumpLoads(true)` to get jump table recovery data. Post-process chains of `if/else` into switch statements where the pattern matches.

### 3.4 Dead Store / Artifact Cleanup

Post-process decompiled output to:
- Remove `CONCAT11(extraout_AH, value)` → just `value`
- Remove `unaff_DS` / `unaff_SS` parameters from function signatures
- Simplify `(uint)(ushort)` chains from 16-bit type widening

---

## Phase 4 — Matching Decompilation

**Priority**: Medium | **Impact**: High (for reproduction goal) | **Difficulty**: High

### 4.1 Assembly-Level Comparison Framework

Adapt [asm-differ](https://github.com/simonlindholm/asm-differ) for x86-16:
- Disassemble original EXE functions with Ghidra
- Compile reconstructed Pascal source with TP7 or FPC (in TP7 compat mode)
- Diff at the instruction level, function by function

This is the gold standard from the matching decomp community (zeldaret/oot, decomp.me). It tells you exactly which functions match and which don't.

### 4.2 Function-by-Function Pascal Reconstruction

Instead of trying to make C output compilable, write actual Pascal source targeting TP7/FPC:
- Start with leaf functions (no calls to other app functions)
- Use asm-differ to verify each function matches
- Work inward through the call graph

### 4.3 Linker Map & Segment Layout Recovery

BP7's linker emits segments in order: System unit → used units (dependency order) → program code. Recover the segment map and produce a linker script that TP7/FPC can use to match the original layout.

For overlay (VROOMM) binaries, model the overlay stub segments and runtime buffer allocation.

### 4.4 Data Section Reproduction

Extract initialized data directly from the EXE:
- Global variables, const strings, typed constants
- Produce Pascal `const` and `var` blocks matching original layout byte-for-byte
- The string table already extracted is the foundation — extend to non-string typed constants

---

## Phase 5 — Moonshot: Automated Re-synthesis

**Priority**: Low | **Impact**: Very High | **Difficulty**: Very High

### 5.1 C-to-Pascal Transpilation

Post-processor converting Ghidra C output to syntactically valid Pascal:

| C Pattern | Pascal Pattern |
|-----------|----------------|
| `*(int *)addr` | Typed variable access |
| `if/else if` chains | `case ... of` |
| `while(1) { ... break; }` | `repeat ... until condition` |
| `param_1 + offset` → deref | Record field access |

### 5.2 Dynamic Analysis with DOSBox

Run original EXE in DOSBox with instrumentation:
- Trace function calls, memory writes, I/O operations
- Compare dynamic traces against reconstructed source
- Tools: DOSBox debugger, custom DOSBox instrumentation patches

### 5.3 BP7 Ghidra Data Type Archive (.gdt)

Package all BP7 types, function signatures, and calling conventions into a reusable `.gdt` archive. Loadable by any Ghidra user working with BP7 binaries — valuable community contribution.

---

## Reference: Matching Decomp Community Practices

The most successful decompilation-to-recompilation projects (Zelda OoT, Mario 64, Pokémon) follow this workflow:

1. **Disassemble** the original ROM/binary into relocatable assembly
2. **Build infrastructure** so the assembly can be reassembled into an identical binary
3. **Replace functions one at a time** with C/Pascal source, verifying each one matches
4. **Use asm-differ** to compare original vs. recompiled instruction sequences
5. **Track progress** as "% of functions matching" (decomp.me leaderboard style)

Key insight: they don't try to decompile everything at once. They build a framework where assembly and source coexist, then incrementally replace assembly with source.

For DOS MZ + Borland Pascal, the equivalent would be:
1. Extract all function bodies as assembly (Ghidra can do this)
2. Build a TP7/FPC project that links the assembly
3. Replace functions one by one with Pascal, verifying with asm-differ
4. Track which functions match

---

## Suggested Starting Order

1. **Phase 1.1** — BP7 type definitions (TextRec, FileRec, etc.)
2. **Phase 1.2** — Function signature annotation for RTL functions
3. **Phase 1.3** — Global variable recovery
4. **Phase 2.1** — Calling convention fixes
5. **Phase 3.2** — Library code elimination
6. **Phase 4.1** — asm-differ framework
7. Everything else follows naturally
