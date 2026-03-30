#!/usr/bin/env python3
"""Rewrite TestGhidraAPIs.java with fixed imports and methods."""
import os, re

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'TestGhidraAPIs.java')
content = open(path).read()

# Replace the old header
content = content.replace(
    '// TestGhidraAPIs.java \u2014 Evaluate 22 Ghidra API calls for BPdecompiler\n'
    '//\n'
    '// Runs each API against the loaded program and writes a JSON report\n'
    '// documenting what each API returns and whether it\'s useful.\n'
    '//\n'
    '// Usage:\n'
    '//   analyzeHeadless <proj-dir> <proj-name> -process <EXE> \\\n'
    '//     -postScript TestGhidraAPIs.java <output-json> \\\n'
    '//     -scriptPath /Volumes/Projects/lord-ts/decompiler\n'
    '//\n'
    '// Run against a test binary (e.g., HELLO.EXE or GAMESIM.EXE) after importing.',

    '// TestGhidraAPIs.java \u2014 Evaluate Ghidra API calls for BPdecompiler\n'
    '//\n'
    '// Tests each API against the loaded program and writes a JSON report.\n'
    '//\n'
    '// Usage:\n'
    '//   analyzeHeadless <proj-dir> <proj-name> -import <EXE> -overwrite \\\n'
    '//     -postScript TestGhidraAPIs.java <output-json> -scriptPath .'
)

# Remove problematic wildcard imports
for imp in [
    'import ghidra.program.util.string.*;\n',
    'import ghidra.program.util.*;\n',
    'import ghidra.app.cmd.data.CreateDataCmd;\n',
    'import ghidra.app.util.opinion.Loader;\n',
    'import ghidra.util.task.TaskMonitor;\n',
]:
    content = content.replace(imp, '')

# Add specific imports
if 'FoundString' not in content:
    content = content.replace(
        'import ghidra.program.model.pcode.*;',
        'import ghidra.program.model.pcode.*;\n'
        'import ghidra.program.util.string.FoundString;\n'
        'import ghidra.program.util.DefinedDataIterator;'
    )

# Remove test_13 call
content = content.replace('        test_13_FillOutStructureCmd();\n', '')
# Remove test_13 method
content = re.sub(
    r'\n    private void test_13_FillOutStructureCmd\(\).*?(?=\n    private void )',
    '\n',
    content,
    flags=re.DOTALL
)

# Add firstTest field
if 'private boolean firstTest' not in content:
    content = content.replace(
        '    private int testsSkipped = 0;',
        '    private int testsSkipped = 0;\n    private boolean firstTest = true;'
    )

# Fix writeTest method
content = re.sub(
    r'    private void writeTest\(String name, String status, String detail\) \{\n'
    r'        String escapedDetail.*?\n'
    r'        out\.println\("    \\"" \+ name.*?\n'
    r'        out\.println\("      \\"status.*?\n'
    r'        out\.println\("      \\"detail.*?\n'
    r'        out\.print\("    \},"\);\n'
    r'        out\.println\(\);',

    '    private void writeTest(String name, String status, String detail) {\n'
    '        String escaped = detail.replace("\\\\", "\\\\\\\\")\n'
    '            .replace("\\"", "\\\\\\"").replace("\\n", "\\\\n").replace("\\r", "");\n'
    '        if (!firstTest) out.println(",");\n'
    '        firstTest = false;\n'
    '        out.print("    \\"" + name + "\\": {\\"status\\": \\"" + status\n'
    '            + "\\", \\"detail\\": \\"" + escaped + "\\"}");',
    content
)

# Fix SymbolicPropogator test to use reflection
content = re.sub(
    r'    private void test_09_SymbolicPropogator\(\) \{.*?^    \}',
    '''    private void test_09_SymbolicPropogator() {
        try {
            Class<?> cls = Class.forName(
                "ghidra.app.plugin.core.analysis.SymbolicPropogator");
            java.lang.reflect.Constructor<?> ctor = cls.getConstructor(
                ghidra.program.model.listing.Program.class);
            Object prop = ctor.newInstance(currentProgram);
            writeTest("09_SymbolicPropogator", "pass",
                "SymbolicPropogator instantiated via reflection. "
                + "POTENTIALLY USEFUL for resolving register-passed string addresses. "
                + "But HighFunction PcodeOps already give us constants. LOW VALUE.");
        } catch (Exception e) {
            writeTest("09_SymbolicPropogator", "skip",
                "Not accessible: " + e.getClass().getSimpleName()
                + ". HighFunction is sufficient for our needs.");
        }
    }''',
    content,
    flags=re.MULTILINE | re.DOTALL
)

# Add newline before closing tests brace (only first occurrence)
old_close = '        out.println("  },");'
new_close = '        out.println("");\n        out.println("  },");'
content = content.replace(old_close, new_close, 1)

with open(path, 'w') as f:
    f.write(content)
print(f"Wrote {len(content)} chars to {path}")
