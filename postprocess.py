#!/usr/bin/env python3
"""postprocess.py — Apply text-based cleanup to decompiled.c output files.

This script applies the same transformations that Decompile.java Phase 5
applies (or should apply), allowing us to update pre-generated test output
files without re-running the Ghidra pipeline.

Transformations applied:
  1. Type cleanup: undefined1→byte, undefined2→word, undefined4→dword, undefined8→qword
  2. Calling convention cleanup: __cdecl16near, __cdecl16far, __stdcall16far → removed
  3. CONCAT11 cleanup: CONCAT11(extraout_AH..., value) → value
  4. Variable declaration cleanup: remove unused unaff_DS and extraout_AH declarations
  5. Library code elimination: replace library function bodies with summary

Usage:
  python3 postprocess.py tests/output/HELLO/decompiled.c
  python3 postprocess.py tests/output/*/decompiled.c
"""
import re
import sys
import os


# ── Library function detection ──

LIBRARY_PREFIXES = ('bp_', 'ddp_', 'crt_', 'dos_', 'comio_', 'ovr_')

FLIRT_PATTERNS = [
    re.compile(r'^@\w+\$'),       # @Name$qXXX (Borland mangled FLIRT names)
    re.compile(r'^__[A-Z]'),      # __Name (system functions)
]

# Maps @Name$... FLIRT names to friendly display names.
# The key format uses @ prefix and $ separator as Ghidra outputs them.
FLIRT_AT_NAMES = {
    '@Write$qm4Text4Char4Word': 'bp_write_char',
    '@Write$qm4Textm6String4Word': 'bp_write_str',
    '@Write$qm4Text7Longint4Word': 'bp_write_longint',
    '@Write$qm4Text7Boolean4Word': 'bp_write_bool',
    '@Write$qm4Text4Real4Wordt3': 'bp_write_real',
    '@WriteLn$qm4Text': 'bp_writeln',
    '@ReadLn$qm4Text': 'bp_readln',
    '@Delete$qm6String7Integert2': 'bp_delete',
    '@Randomize$qv': 'bp_randomize',
    '@Random$q4Word': 'bp_random',
    '@ParamCount$qv': 'bp_paramcount',
    '@Val__Longint$qm6Stringm7Integer': 'bp_val_longint',
    '@Val__Real$qm6Stringm7Integer': 'bp_val_real',
    '@FillChar$qm3Any4Word4Byte': 'bp_fillchar',
    '@UpCase$q4Char': 'bp_upcase',
    '@Eof$qm4File': 'bp_eof',
    '@Rename$qm4Filem6String': 'bp_rename',
    '@LStrClr': 'bp_lstrclr',
    '@__StackCheck$q4Word': 'bp_stackcheck',
    '@AssignCrt$qm4Text': 'crt_assigncrt',
    '@SetIntVec$q4Byte7Pointer': 'dos_setintvec',
    '@SetTime$q4Wordt1t1t1': 'dos_settime',
    '@FSplit$q7PathStrm6DirStrm7NameStrm6ExtStr': 'dos_fsplit',
    '@Intr$q4Bytem9Registers': 'dos_intr',
    '@GetEnv$q6String': 'dos_getenv',
    '@EnvStr$q7Integer': 'dos_envstr',
    '@DiskSize$q4Byte': 'dos_disksize',
    '@FindNext$qm9SearchRec': 'dos_findnext',
}

# Regex for generic @Name$q... decoding
_FLIRT_AT_RE = re.compile(r'^@(\w+?)(\$.*)?$')


def decode_flirt_name(name):
    """Decode a FLIRT mangled name to a friendlier form.

    Returns the friendly name if known, or a generic decode, or the
    original name if not a FLIRT name.
    """
    # Check explicit table first
    friendly = FLIRT_AT_NAMES.get(name)
    if friendly:
        return friendly
    # Generic decode for @Name$q... pattern
    m = _FLIRT_AT_RE.match(name)
    if m:
        return 'bp_' + m.group(1).lower()
    return name


def is_library_function(name):
    """Check if a function name is a known library function."""
    if any(name.startswith(p) for p in LIBRARY_PREFIXES):
        return True
    for pat in FLIRT_PATTERNS:
        if pat.match(name):
            return True
    return False


# ── Type cleanup ──

def cleanup_types(text):
    """Replace Ghidra undefined types with standard BP7 type names."""
    text = re.sub(r'\bundefined1\b', 'byte', text)
    text = re.sub(r'\bundefined2\b', 'word', text)
    text = re.sub(r'\bundefined4\b', 'dword', text)
    text = re.sub(r'\bundefined8\b', 'qword', text)
    return text


# ── Calling convention cleanup ──

def cleanup_calling_conventions(text):
    """Remove 16-bit calling convention noise."""
    text = text.replace('__cdecl16near ', '')
    text = text.replace('__cdecl16far ', '')
    text = text.replace('__stdcall16far ', '')
    return text


# ── CONCAT11 cleanup ──

def cleanup_concat11(text):
    """Replace CONCAT11(extraout_AH..., value) → value.

    Only handles the case where the first argument is extraout_AH (or
    extraout_AH_NN). More complex CONCAT11 patterns (arithmetic, nested
    expressions) are left untouched — they represent genuine 16-bit operations.
    """
    # Use a function to handle balanced parentheses in the value argument
    def replace_concat11(match):
        # Find the value argument after the comma
        start = match.end()
        pos = match.start()
        # Find the full CONCAT11(...) by tracking parenthesis depth
        full_text = text[pos:]
        # Skip "CONCAT11("
        i = len('CONCAT11(')
        depth = 1
        while i < len(full_text) and depth > 0:
            if full_text[i] == '(':
                depth += 1
            elif full_text[i] == ')':
                depth -= 1
            i += 1
        if depth != 0:
            return match.group(0)  # Unbalanced — leave unchanged

        # full_text[:i] is "CONCAT11(...)"
        inner = full_text[len('CONCAT11('):i - 1]
        # Split on first comma to separate first arg from value
        # But commas inside nested parens don't count
        comma_pos = None
        parens = 0
        for j, ch in enumerate(inner):
            if ch == '(':
                parens += 1
            elif ch == ')':
                parens -= 1
            elif ch == ',' and parens == 0:
                comma_pos = j
                break

        if comma_pos is None:
            return match.group(0)

        value = inner[comma_pos + 1:].strip()
        return value

    # Find all CONCAT11(extraout_AH..., ...) patterns and replace them
    # We need to do this iteratively since regex can't handle balanced parens
    result = []
    i = 0
    pattern = re.compile(r'CONCAT11\(extraout_AH\w*,')
    while i < len(text):
        m = pattern.search(text, i)
        if not m:
            result.append(text[i:])
            break

        result.append(text[i:m.start()])

        # Track balanced parens from CONCAT11(
        # Find the opening paren
        paren_start = m.start() + len('CONCAT11')
        depth = 0
        j = paren_start
        while j < len(text):
            if text[j] == '(':
                depth += 1
            elif text[j] == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1

        if depth != 0:
            # Unbalanced — leave unchanged
            result.append(text[m.start():m.end()])
            i = m.end()
            continue

        # Extract the full CONCAT11(...) span
        full = text[m.start():j + 1]
        inner = full[len('CONCAT11('):-1]

        # Find the first top-level comma
        comma_pos = None
        parens = 0
        for k, ch in enumerate(inner):
            if ch == '(':
                parens += 1
            elif ch == ')':
                parens -= 1
            elif ch == ',' and parens == 0:
                comma_pos = k
                break

        if comma_pos is not None:
            value = inner[comma_pos + 1:].strip()
            result.append(value)
        else:
            result.append(full)  # Shouldn't happen

        i = j + 1

    return ''.join(result)


# ── Variable declaration cleanup ──

def cleanup_declarations(func_body):
    """Remove unused variable declarations for unaff_DS and extraout_AH.

    After CONCAT11 cleanup, some extraout_AH variables become unused.
    Also remove unaff_DS declarations (DS register is implicit in BP7).

    Only removes a declaration if the variable name doesn't appear
    anywhere else in the function body.
    """
    lines = func_body.split('\n')
    result = []

    for line in lines:
        stripped = line.strip()

        # Check for unaff_DS declarations
        match_ds = re.match(r'^\s+\w+\s+(unaff_DS)\s*;$', line)
        if match_ds:
            var_name = match_ds.group(1)
            # Check if var_name is used elsewhere in the function body
            # (excluding this declaration line itself)
            other_lines = '\n'.join(l for l in lines if l != line)
            if re.search(r'\b' + re.escape(var_name) + r'\b', other_lines):
                result.append(line)  # Keep — still used
            # else: remove declaration (skip appending)
            continue

        # Check for extraout_AH declarations
        match_ah = re.match(r'^\s+\w+\s+(extraout_AH\w*)\s*;$', line)
        if match_ah:
            var_name = match_ah.group(1)
            # Check if var_name is used elsewhere in the function body
            other_lines = '\n'.join(l for l in lines if l != line)
            if re.search(r'\b' + re.escape(var_name) + r'\b', other_lines):
                result.append(line)  # Keep — still used
            # else: remove declaration (skip appending)
            continue

        result.append(line)

    return '\n'.join(result)


# ── Library code elimination ──

# Regex to split output into function blocks.
# Each block starts with "\n// ==================" and includes the header + body.
FUNC_BLOCK_RE = re.compile(
    r'(\n// ={10,}\n// Function: (\S+) @ ([0-9a-f]+:[0-9a-f]+)\n// ={10,}\n)'
)


def eliminate_library_bodies(text):
    """Replace library function bodies with a marker comment.

    Library functions get their C code body replaced with:
      // [LIBRARY] <description if available>

    Application functions keep their full body.

    Returns: (modified_text, list_of_library_funcs)
    """
    # Split text into segments: [preamble, header1, name1, addr1, body1, header2, ...]
    parts = FUNC_BLOCK_RE.split(text)

    # parts layout: [pre, header, name, addr, body, header, name, addr, body, ...]
    #   parts[0] = text before first function
    #   parts[1] = header (// ===...=== block)
    #   parts[2] = function name
    #   parts[3] = function address
    #   parts[4] = body text (up to next header)
    #   ... repeats

    library_funcs = []
    result_parts = [parts[0]]

    i = 1
    while i < len(parts):
        header = parts[i]
        func_name = parts[i + 1]
        func_addr = parts[i + 2]
        body = parts[i + 3] if i + 3 < len(parts) else ''

        if is_library_function(func_name):
            # Extract description from the body if available
            # Look for /* description */ comment on the signature line
            desc_match = re.search(r'/\*\s*(.+?)\s*\*/', body.split('\n')[0] if body else '')
            desc = ''
            if desc_match:
                desc = ' — ' + desc_match.group(1)

            # Replace body with library marker
            result_parts.append(header)
            result_parts.append(f'// [LIBRARY]{desc}\n\n')
            library_funcs.append((func_name, func_addr))
        else:
            result_parts.append(header)
            result_parts.append(body)

        i += 4

    return ''.join(result_parts), library_funcs


def add_library_summary(text, library_funcs):
    """Add a summary section listing all library functions at the end."""
    if not library_funcs:
        return text

    # Remove any existing library summary (idempotency)
    text = re.sub(
        r'\n// === Library Functions ===\n.*?// ===+\n',
        '\n',
        text,
        flags=re.DOTALL
    )

    summary = '\n// === Library Functions ===\n'
    summary += f'// {len(library_funcs)} library functions identified (bodies omitted)\n'
    summary += '//\n'
    for name, addr in library_funcs:
        friendly = decode_flirt_name(name)
        if friendly != name:
            summary += f'//   {friendly} ({name}) @ {addr}\n'
        else:
            summary += f'//   {name} @ {addr}\n'
    summary += '// ===========================\n'

    return text.rstrip() + '\n' + summary


# ── Main processing pipeline ──

def process_function_blocks(text):
    """Apply per-function-block transformations (declaration cleanup)."""
    # Split into function blocks and process each
    parts = FUNC_BLOCK_RE.split(text)

    result_parts = [parts[0]]
    i = 1
    while i < len(parts):
        header = parts[i]
        func_name = parts[i + 1]
        body = parts[i + 3] if i + 3 < len(parts) else ''

        if not is_library_function(func_name) and body.strip():
            body = cleanup_declarations(body)

        result_parts.append(header)
        # parts[i+2] is the address, but it's part of the header capture
        # We need to reconstruct properly — the header includes name and addr
        result_parts.append(body)

        i += 4

    return ''.join(result_parts)


def postprocess(text):
    """Apply all post-processing transformations to decompiled output."""
    # Step 1: Type cleanup (matches Decompile.java Phase 5)
    text = cleanup_types(text)

    # Step 2: Calling convention cleanup (matches Decompile.java Phase 5)
    text = cleanup_calling_conventions(text)

    # Step 3: CONCAT11 cleanup (new)
    text = cleanup_concat11(text)

    # Step 4: Per-function declaration cleanup (new)
    text = process_function_blocks(text)

    # Step 5: Library code elimination (new)
    text, library_funcs = eliminate_library_bodies(text)

    # Step 6: Add library summary section (new)
    text = add_library_summary(text, library_funcs)

    return text


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 postprocess.py <decompiled.c> [...]")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        if not os.path.isfile(filepath):
            print(f"  SKIP: {filepath} (not found)")
            continue

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            original = f.read()

        result = postprocess(original)

        if result != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(result)
            # Count changes
            orig_lines = len(original.split('\n'))
            new_lines = len(result.split('\n'))
            print(f"  OK: {filepath} ({orig_lines} → {new_lines} lines)")
        else:
            print(f"  UNCHANGED: {filepath}")


if __name__ == '__main__':
    main()
