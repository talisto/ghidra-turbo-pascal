# FLIRT Signature Files

IDA FLIRT `.sig` files for automatic function identification. Applied to a Ghidra project using `ApplySigHeadless.py` to rename anonymous `FUN_XXXX_YYYY` stubs to their real names.

The easiest way to use them is via `decompile.sh --sigs`.

## Files

| File | Size | Covers | Relevant For |
|------|------|--------|--------------|
| `tpdos.sig` | 12 KB | Turbo Pascal 5.0 / 5.5 / 6.0 / **7.0** DOS runtime | All TP7 DOS binaries (core stdlib: `Write`, `Read`, `Val`, `Str`, heap, etc.) |
| `tpdpmi.sig` | 7.8 KB | Turbo Pascal 7.0 DPMI runtime | TP7 binaries compiled with DPMI memory manager |
| `tptv.sig` | 33 KB | **Turbo Vision 6.0 / 7.0** (DOS) | Games/apps using the Turbo Vision TUI framework |
| `tptvdpmi.sig` | 23 KB | Turbo Vision 7.0 DPMI | TV binaries compiled with DPMI |
| `bc31rtd.sig` | 110 KB | Borland C / C++ 3.1 16-bit DOS runtime | DOS binaries built with Borland C or Turbo C |
| `ddplus.sig` | ~1 KB | **DDPlus 7.1** Door Driver Toolkit | BBS door games using DDPlus (swrite, sread, set_color, etc.) |

### Sources

- `tpdos.sig` through `bc31rtd.sig`: Extracted from **IDA Free 9.3** sig directory
- `ddplus.sig`: Generated with `scripts/gen_sig.py` from compiled DDTEST.EXE

## Using Sigs in the Pipeline

```bash
# Apply all sigs in sigs/ during decompilation:
./decompile.sh --sigs --output /path/to/output /path/to/MYPROG.EXE
```

`ApplySigHeadless.py` iterates over every `.sig` file in the `sigs/` directory, so adding a new `.sig` file is all that's needed — no code changes required.

---

## Generating New Sig Files

### Why Not sigmake?

IDA's standard FLAIR workflow is: extract `.pat` patterns → run `sigmake` to produce `.sig`. However, **`sigmake` in IDA Free 9.3 is non-functional** — it returns `"Bad xdigit"` on any `.pat` input, regardless of format. This appears to be intentionally disabled in the free edition.

Additionally, the FLAIR extraction tools (`plb`, `ptmobj`, `pcf`, `pelf`) cannot parse Borland's proprietary `.TPU` / `.TPL` formats, so there's no way to extract patterns from Turbo Pascal unit files directly.

### gen_sig.py — Direct Sig Generation

`scripts/gen_sig.py` generates `.sig` files directly from a compiled DOS MZ executable, bypassing `sigmake` entirely. It writes the FLIRT binary format that both IDA's `dumpsig` and our `ApplySigHeadless.py` can read.

#### Quick Start

```bash
# Generate a sig from a function mapping file:
python3 scripts/gen_sig.py path/to/COMPILED.EXE sigs/mylib.sig sigs/mylib.funcs \
    --segment 0x1095 --name "My Library v1.0"

# Regenerate the bundled DDPlus sig:
python3 scripts/gen_sig.py tests/data/DDTEST.EXE sigs/ddplus.sig sigs/ddplus.funcs \
    --segment 0x1095 --name "DDPlus 7.1 Door Driver Toolkit"

# Verify with IDA's dumpsig (optional):
/path/to/flair/dumpsig sigs/mylib.sig

# Verify with the standalone parser:
python3 scripts/test_sig.py sigs/mylib.sig
```

#### How It Works

1. **Parse the MZ header** — finds the load image offset and builds a relocation set
2. **Extract 32-byte patterns** — reads leading bytes of each function, marking relocated bytes as variant (wildcard)
3. **Compute CRC16** — calculates a checksum over bytes 33+ of each function body (X.25 variant with reversed bit order, matching `ApplySigHeadless.py`)
4. **Build a FLIRT tree** — encodes patterns, variant masks, CRC groups, and FLIRT-mangled function names into a binary tree
5. **Write the `.sig` file** — version 5 header + raw-deflate compressed tree data

#### Function Mapping Files (`.funcs`)

Function mappings live in plain text `.funcs` files — one `hex_offset flirt_name` pair per line. Comments (`#`) and blank lines are ignored.

Example (`sigs/ddplus.funcs`):
```
# DDPlus 7.1 Door Driver Toolkit
0080 _Clear_Region_q4Bytet1t2
130c _swrite_q6String
13b6 _swriteln_q6String
```

To create sigs for a different library, create a new `.funcs` file with that library's offsets and names, then run `gen_sig.py` pointing at it.

#### Finding Function Offsets

Function offsets come from Ghidra's decompiled output. Each function header shows the address:

```c
// Function: FUN_1095_130c @ 1095:130c
```

The offset is the part after the colon (`130c`). The segment (`1095`) is passed via `--segment 0x1095`. The script subtracts the Ghidra base segment (`0x1000`, configurable with `--ghidra-base`) to get the actual segment in the EXE (`0x0095`).

#### FLIRT Name Mangling Convention

FLIRT names follow IDA's Borland Pascal mangling format:

| Pascal Declaration | FLIRT Name |
|---|---|
| `procedure Foo;` | `_Foo_qv` |
| `procedure Foo(x: Byte);` | `_Foo_q4Byte` |
| `procedure Foo(x, y: Byte);` | `_Foo_q4Bytet1` |
| `procedure Foo(s: String);` | `_Foo_q6String` |
| `procedure Foo(x: Integer; s: String);` | `_Foo_q7Integert16String` |
| `procedure Foo(x: Longint; a,b,c,d,e: Byte; var w,x: Word);` | `_Foo_q7Longintt1t2t3t4t5m4Wordt1t2` |

Rules:
- Prefix: `_` + PascalCase name + `_q`
- Each parameter type: length digit(s) + type name (e.g., `4Byte`, `6String`, `7Integer`, `7Longint`)
- Repeated types: `t1`, `t2`, etc. (not the full type name again)
- `var` parameters: prefix `m` instead of length (e.g., `m4Word`)
- No parameters: `qv` (void)

These names must match what `tpdos.sig` and other IDA sigs use, so that `FLIRT_DESCRIPTIONS` in `label_functions.py` can map them to human-readable labels.

### Sig File Binary Format (Version 5)

For anyone needing to understand or debug the `.sig` format:

```
Header (39 bytes for version 5):
  [6]  Magic: "IDASGN"
  [1]  Version: 5
  [1]  Architecture: 0 = Intel 80x86
  [4]  File types: LE u32 (0x0000100F for DOS)
  [2]  OS types: LE u16 (0x0001 = MSDOS)
  [2]  App types: LE u16 (0x0087 = console+graphics+exe+16bit)
  [2]  Features: LE u16 (0x0010 = compressed)
  [2]  Old n_functions: LE u16
  [2]  CRC16 of tree data (before compression): LE u16
  [12] ctype: zeroed
  [1]  Library name length: u8
  [2]  ctypes_crc16: LE u16
  --- Version 6+ adds: n_functions (LE u32)
  --- Version 8+ adds: pattern_size (LE u16)

  [N]  Library name: ASCII bytes (N = lib name length)
  [...]  Tree data: raw deflate compressed
```

**Version matters**: `tpdos.sig` and all bundled sigs report as version 5 (despite dumpsig printing "Version: 7" — it adds 2 to the stored value). Use version 5 to avoid needing the extra header fields.

#### Tree Data Encoding

The tree uses two variable-length integer encodings:

**`max_2_bytes`** (used for version < 9: module length, function offset, variant mask when pattern < 16 bytes):
- `0x00-0x7F`: 1 byte, value = byte
- `0x80-0xFF`: 2 bytes, value = `((b & 0x7F) << 8) | next_byte`

**`multiple_bytes`** (used for: child count, variant mask when pattern ≥ 16 bytes):
- `0x00-0x7F`: 1 byte
- `0x80-0xBF`: 2 bytes, value = `((b & 0x7F) << 8) | next`
- `0xC0-0xDF`: 4 bytes, value = `((b & 0x3F) << 24) | next3`
- `0xE0-0xFF`: 5 bytes, value = `next4`

Tree structure:
```
Root node:
  [multi] child_count
  For each child:
    [1]    pattern_length (32 for standard patterns)
    [var]  variant_mask (which bytes are wildcards)
    [N]    non-variant pattern bytes
    [multi] child_count (0 = leaf node with modules)
    If leaf (child_count == 0):
      Module group:
        [1]    crc_length
        [2]    crc16 (BE)
        [max2] func_length
        [max2] public_func_offset (0 for first/only function)
        [N]    function name bytes (each >= 0x20)
        [1]    flags byte (< 0x20): 0x01=more_public, 0x08=more_same_crc, 0x10=more_modules
```

### Tips for Creating Sigs for Other Libraries

1. **Compile a test program** that calls every exported function of the library
2. **Run the decompile pipeline** to get function addresses in Ghidra's output
3. **Cross-reference with source code** to identify which decompiled function corresponds to which library export
4. **Map offsets to FLIRT names** following the mangling convention above
5. **Create a `.funcs` file** in `sigs/` with the offset-to-name mappings (see `sigs/ddplus.funcs` for format)
6. **Generate and validate**: run `gen_sig.py` with `--segment` and `--name`, then verify with `dumpsig` or `scripts/test_sig.py`
7. **Add `FLIRT_DESCRIPTIONS`** entries in `label_functions.py` so the labeled output shows human-readable names

---

## Technical Notes

- IDA FLIRT v5 sig files use **raw deflate** compression (no zlib header) — the `ApplySigHeadless.py` script handles this with `zlib.decompress(data, -15)`
- Ghidra represents DOS MZ addresses as `seg:off` strings (e.g., `1000:0000`); the script's `_addr_to_int()` helper handles this format
- **Two-pass pipeline required**: Python `.py` scripts need `pyghidraRun -H`; Java `.java` scripts use regular `analyzeHeadless`
- CRC16 uses the X.25 variant with reversed bit order and polynomial 0x1021 — implementation in both `ApplySigHeadless.py` and `gen_sig.py`

### BP7 Disk Images (`dev/BP7.0/`)

The BP7 retail distribution was investigated and found to ship `.TPU`/`.TPL` files only —
Borland's proprietary **TPUQ** binary format. The FLAIR tools `plb` (OMF parser) and `pcf`
(COFF parser) both return "invalid input file" on these. BP7 does **not** distribute the
assembly-source `.OBJ` files for its RTL.

### IDA Free TP-related sigs (checked, not relevant for DOS)

The following additional TP sig files exist in IDA Free 9.3 but target **Windows** only:
- `tpowl.sig` — OWL for Turbo Pascal for Windows 6.0/7.0 (18 KB)
- `tpwin.sig` — Turbo Pascal for Windows 6.0/7.0 (7 KB)
- `tpsig2.sig` / `tpsig2n.sig` — TP startup stubs (0 KB, effectively empty)
- `otp60.sig` — Objective Toolkit Pro 6.0 for C++ Windows (408 KB, unrelated)