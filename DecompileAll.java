// DecompileAll.java — Ghidra headless decompiler script
//
// Decompiles all functions in the current program and writes C pseudocode to a file.
//
// Usage:
//   analyzeHeadless <proj-dir> <proj-name> -process <EXE> \
//     -postScript DecompileAll.java [output-file] \
//     -scriptPath scripts
//
// Arguments:
//   output-file  Path to write decompiled output (default: decompiled.c in cwd)
//
// Output goes to the specified path (or <cwd>/decompiled.c if no arg given).
// Run from the game's dev/<gamename>/ directory so the default output lands there.
//
// IMPORTANT: Use regular analyzeHeadless (not pyghidraRun) for Java scripts.
// Java scripts fail in PyGhidra mode.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0)
            ? args[0]
            : System.getProperty("user.dir") + "/decompiled.c";

        File outFile = new File(outPath);
        outFile.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(outFile));

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        int count = 0;

        while (it.hasNext()) {
            Function func = it.next();
            DecompileResults res = decomp.decompileFunction(func, 60, monitor);
            if (res.decompileCompleted()) {
                pw.println("\n// ==========================================");
                pw.println("// Function: " + func.getName()
                    + " @ " + func.getEntryPoint());
                pw.println("// ==========================================\n");
                pw.println(res.getDecompiledFunction().getC());
            }
            count++;
        }

        pw.close();
        decomp.dispose();
        println("Decompiled " + count + " functions to " + outFile.getAbsolutePath());
    }
}
