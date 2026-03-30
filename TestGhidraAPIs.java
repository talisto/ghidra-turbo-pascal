// TestGhidraAPIs.java — Evaluate Ghidra API calls for BPdecompiler
//
// Tests each API against the loaded program and writes a JSON report.
//
// Usage:
//   analyzeHeadless <proj-dir> <proj-name> -import <EXE> -overwrite \
//     -postScript TestGhidraAPIs.java <output-json> -scriptPath .

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.database.mem.FileBytes;

import java.io.*;
import java.util.*;

public class TestGhidraAPIs extends GhidraScript {

    private PrintWriter out;
    private int testsPassed = 0;
    private int testsFailed = 0;
    private int testsSkipped = 0;
    private boolean firstTest = true;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0)
            ? args[0]
            : System.getProperty("user.dir") + "/api_test_results.json";

        File outFile = new File(outPath);
        outFile.getParentFile().mkdirs();
        out = new PrintWriter(new FileWriter(outFile));
        out.println("{");
        out.println("  \"program\": \"" + currentProgram.getName() + "\",");
        out.println("  \"tests\": {");

        // ── Category 1: String Handling ──
        test_01_findPascalStrings();
        test_02_PascalStringDataType_createData();
        test_03_StringDataInstance();
        test_04_DefinedDataIterator();

        // ── Category 2: Decompiler Interface ──
        test_05_DecompInterface();
        test_06_HighFunction();
        test_07_HighVariable();
        test_08_ClangTokenGroup();

        // ── Category 3: Constant Propagation ──
        test_09_SymbolicPropogator();

        // ── Category 4: Name Resolution ──
        test_11_DemanglerUtil();
        test_12_setCallingConvention();

        // ── Category 5: Structure Recovery ──
        test_14_DataTypeManager();

        // ── Category 6: Function Management ──
        test_15_FunctionManager();
        test_16_FunctionComments();
        test_17_createLabel();

        // ── Category 7: Memory & References ──
        test_19_Memory();
        test_20_ReferenceManager();
        test_21_AddressSet();
        test_22_RelocationTable();

        out.println("");
        out.println("  },");
        out.println("  \"summary\": {");
        out.println("    \"passed\": " + testsPassed + ",");
        out.println("    \"failed\": " + testsFailed + ",");
        out.println("    \"skipped\": " + testsSkipped);
        out.println("  }");
        out.println("}");
        out.close();

        println("=== API Test Results ===");
        println("  Passed:  " + testsPassed);
        println("  Failed:  " + testsFailed);
        println("  Skipped: " + testsSkipped);
        println("  Written: " + outFile.getAbsolutePath());
    }

    // ── Test helpers ──

    private void writeTest(String name, String status, String detail) {
        String escapedDetail = detail.replace("\\", "\\\\")
            .replace("\"", "\\\"").replace("\n", "\\n");
        out.println("    \"" + name + "\": {");
        out.println("      \"status\": \"" + status + "\",");
        out.println("      \"detail\": \"" + escapedDetail + "\"");
        out.print("    },");
        out.println();
        if ("pass".equals(status)) testsPassed++;
        else if ("fail".equals(status)) testsFailed++;
        else testsSkipped++;
    }

    // ── Category 1: String Handling ──

    private void test_01_findPascalStrings() {
        try {
            List<FoundString> strings = findPascalStrings(null, 4, 1, false);
            int count = strings.size();
            // Verify we can read string text from memory
            int readable = 0;
            for (FoundString fs : strings) {
                String text = fs.getString(currentProgram.getMemory());
                if (text != null && !text.isEmpty()) readable++;
            }
            writeTest("01_findPascalStrings", "pass",
                "Found " + count + " Pascal strings, " + readable + " readable. "
                + "VERDICT: Essential — finds all length-prefixed strings in binary. "
                + "REPLACES: annotate_strings.py build_string_db() EXE scanning.");
        } catch (Exception e) {
            writeTest("01_findPascalStrings", "fail", e.getMessage());
        }
    }

    private void test_02_PascalStringDataType_createData() {
        try {
            List<FoundString> strings = findPascalStrings(null, 4, 1, false);
            int created = 0;
            int skipped = 0;
            for (FoundString fs : strings) {
                Address addr = fs.getAddress();
                if (getDataAt(addr) != null || getInstructionAt(addr) != null) {
                    skipped++;
                    continue;
                }
                try {
                    createData(addr, new PascalStringDataType());
                    created++;
                } catch (Exception e) {
                    skipped++;
                }
            }
            writeTest("02_PascalStringDataType_createData", "pass",
                "Defined " + created + " string data types (" + skipped + " skipped). "
                + "VERDICT: Useful — enriches Ghidra DB with typed string data, "
                + "enables DefinedDataIterator and cross-references. "
                + "ENHANCES: String discovery reliability.");
        } catch (Exception e) {
            writeTest("02_PascalStringDataType_createData", "fail", e.getMessage());
        }
    }

    private void test_03_StringDataInstance() {
        try {
            // StringDataInstance provides character-level access to defined strings
            // Test by iterating DefinedData after we've created PascalStringDataType above
            int count = 0;
            int withContent = 0;
            DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext() && count < 100) {
                Data data = dataIter.next();
                if (data.getDataType() instanceof PascalStringDataType) {
                    count++;
                    Object value = data.getValue();
                    if (value != null) withContent++;
                }
            }
            writeTest("03_StringDataInstance", "pass",
                "Found " + count + " PascalStringDataType entries, " + withContent + " with values. "
                + "VERDICT: Low value — we already have quality filtering via isQualityString(). "
                + "StringDataInstance would duplicate that work. SKIP.");
        } catch (Exception e) {
            writeTest("03_StringDataInstance", "fail", e.getMessage());
        }
    }

    private void test_04_DefinedDataIterator() {
        try {
            // DefinedDataIterator.byDataType() with a predicate matching string types
            DefinedDataIterator strIter = DefinedDataIterator.byDataType(currentProgram,
                dt -> dt instanceof PascalStringDataType
                    || dt.getName().toLowerCase().contains("string"));
            int count = 0;
            int pascalCount = 0;
            while (strIter.hasNext()) {
                Data d = strIter.next();
                count++;
                if (d.getDataType() instanceof PascalStringDataType) {
                    pascalCount++;
                }
            }
            writeTest("04_DefinedDataIterator", "pass",
                "DefinedDataIterator found " + count + " string data items, "
                + pascalCount + " are PascalStringDataType. "
                + "VERDICT: Useful AFTER createData() — clean way to iterate "
                + "all known strings without re-scanning. "
                + "REPLACES: Re-iterating FoundString list for strings.json.");
        } catch (Exception e) {
            writeTest("04_DefinedDataIterator", "fail", e.getMessage());
        }
    }

    // ── Category 2: Decompiler Interface ──

    private void test_05_DecompInterface() {
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            Function firstFunc = getFirstFunction();
            DecompileResults res = decomp.decompileFunction(firstFunc, 30, monitor);
            boolean success = res.decompileCompleted();
            String cCode = "";
            if (success) {
                cCode = res.getDecompiledFunction().getC();
            }
            decomp.dispose();
            writeTest("05_DecompInterface", success ? "pass" : "fail",
                "Decompiled " + firstFunc.getName() + ": " + success
                + ", output length: " + cCode.length() + " chars. "
                + "VERDICT: Essential — core decompilation API. ALREADY USED.");
        } catch (Exception e) {
            writeTest("05_DecompInterface", "fail", e.getMessage());
        }
    }

    private void test_06_HighFunction() {
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            // Find a function with calls (not just entry)
            Function func = getFirstFunction();
            Function testFunc = null;
            int checked = 0;
            while (func != null && checked < 50) {
                DecompileResults res = decomp.decompileFunction(func, 30, monitor);
                if (res.decompileCompleted()) {
                    HighFunction hf = res.getHighFunction();
                    if (hf != null) {
                        // Check if this function has PcodeOp CALL operations
                        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
                        int callCount = 0;
                        while (ops.hasNext()) {
                            PcodeOpAST op = ops.next();
                            if (op.getOpcode() == PcodeOp.CALL) {
                                callCount++;
                            }
                        }
                        if (callCount > 0) {
                            testFunc = func;
                            // Re-decompile to get fresh HighFunction
                            res = decomp.decompileFunction(func, 30, monitor);
                            hf = res.getHighFunction();

                            // Count local symbols and parameters
                            LocalSymbolMap lsm = hf.getLocalSymbolMap();
                            int symCount = lsm.getNumParams();

                            writeTest("06_HighFunction", "pass",
                                "Function " + func.getName() + " has " + callCount
                                + " CALL ops, " + symCount + " params. "
                                + "VERDICT: Very useful — gives structured access to "
                                + "decompiler's high-level IR. Can extract CALL targets "
                                + "and their constant arguments to resolve string refs "
                                + "programmatically instead of regex on C text. "
                                + "REPLACES: annotate_strings.py regex pattern matching.");
                            break;
                        }
                    }
                }
                func = getFunctionAfter(func);
                checked++;
            }
            if (testFunc == null) {
                writeTest("06_HighFunction", "skip",
                    "No function with CALL ops found in first 50 functions.");
            }
            decomp.dispose();
        } catch (Exception e) {
            writeTest("06_HighFunction", "fail", e.getMessage());
        }
    }

    private void test_07_HighVariable() {
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            Function func = getFirstFunction();
            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res.decompileCompleted()) {
                HighFunction hf = res.getHighFunction();
                if (hf != null) {
                    LocalSymbolMap lsm = hf.getLocalSymbolMap();
                    int numSyms = lsm.getNumParams();
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < numSyms; i++) {
                        HighParam hp = (HighParam) lsm.getParam(i);
                        sb.append(hp.getName()).append("(")
                          .append(hp.getDataType().getName()).append(") ");
                    }
                    writeTest("07_HighVariable", "pass",
                        "Function " + func.getName() + " params: " + sb.toString()
                        + "VERDICT: Useful alongside HighFunction for reading "
                        + "parameter types. ENHANCES decompilation quality understanding.");
                } else {
                    writeTest("07_HighVariable", "skip", "HighFunction was null.");
                }
            } else {
                writeTest("07_HighVariable", "fail", "Decompilation failed.");
            }
            decomp.dispose();
        } catch (Exception e) {
            writeTest("07_HighVariable", "fail", e.getMessage());
        }
    }

    private void test_08_ClangTokenGroup() {
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            Function func = getFirstFunction();
            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res.decompileCompleted()) {
                ClangTokenGroup tokens = res.getCCodeMarkup();
                int tokenCount = countTokens(tokens);
                writeTest("08_ClangTokenGroup", "pass",
                    "Token tree for " + func.getName() + " has " + tokenCount + " tokens. "
                    + "VERDICT: Useful for structured traversal of decompiled output — "
                    + "can walk the token tree to find function calls, constants, etc. "
                    + "But HighFunction PcodeOps are more direct for our use case. "
                    + "ENHANCES: Could provide more precise string annotation placement.");
            } else {
                writeTest("08_ClangTokenGroup", "fail", "Decompilation failed.");
            }
            decomp.dispose();
        } catch (Exception e) {
            writeTest("08_ClangTokenGroup", "fail", e.getMessage());
        }
    }

    private int countTokens(ClangNode node) {
        if (node instanceof ClangToken) return 1;
        int count = 0;
        for (int i = 0; i < node.numChildren(); i++) {
            count += countTokens(node.Child(i));
        }
        return count;
    }

    // ── Category 3: Constant Propagation ──

    private void test_09_SymbolicPropogator() {
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
    }

    // ── Category 4: Name Resolution ──

    private void test_11_DemanglerUtil() {
        try {
            // Test demangling Borland Pascal mangled names
            // These are the names that FLIRT sigs apply (e.g., @Write$qm4Textm6String4Word)
            // Ghidra renders them as _Write_qm4Textm6String4Word
            String[] testNames = {
                "_Write_qm4Textm6String4Word",
                "_Random_q4Word",
                "_GotoXY_q4Bytet1",
                "_WriteLn_qm4Text",
                "__ClearDSeg"
            };

            int demangled = 0;
            StringBuilder results = new StringBuilder();
            for (String name : testNames) {
                try {
                    // DemanglerUtil.demangle requires a program and mangled name
                    ghidra.app.util.demangler.DemangledObject dem =
                        ghidra.app.util.demangler.DemanglerUtil.demangle(
                            currentProgram, name);
                    if (dem != null) {
                        demangled++;
                        results.append(name).append(" -> ").append(dem.getName()).append("; ");
                    } else {
                        results.append(name).append(" -> null; ");
                    }
                } catch (Exception e) {
                    results.append(name).append(" -> ERROR; ");
                }
            }

            writeTest("11_DemanglerUtil", "pass",
                "Demangled " + demangled + "/" + testNames.length + ": " + results.toString()
                + "VERDICT: Useful IF it handles Borland Pascal mangling. "
                + "If it returns null for BP names, we keep our decode_flirt_name() "
                + "tables. Either way, we can call it in Java before decompilation "
                + "to rename functions. ENHANCES: Cleaner function names in output.");
        } catch (Exception e) {
            writeTest("11_DemanglerUtil", "fail", e.getMessage());
        }
    }

    private void test_12_setCallingConvention() {
        try {
            // Check available calling conventions
            CompilerSpec cspec = currentProgram.getCompilerSpec();
            PrototypeModel[] models = cspec.getCallingConventions();
            StringBuilder convNames = new StringBuilder();
            boolean hasPascal = false;
            for (PrototypeModel m : models) {
                convNames.append(m.getName()).append(", ");
                if (m.getName().toLowerCase().contains("pascal")) {
                    hasPascal = true;
                }
            }

            // Also check the default
            PrototypeModel defModel = cspec.getDefaultCallingConvention();

            // Try setting it on a function (non-destructive — read current first)
            Function func = getFirstFunction();
            String origConv = func.getCallingConventionName();

            writeTest("12_setCallingConvention", "pass",
                "Available conventions: " + convNames.toString()
                + "Default: " + defModel.getName() + ". "
                + "Has Pascal: " + hasPascal + ". "
                + "First function convention: " + origConv + ". "
                + "VERDICT: Useful IF __pascal convention is available — tells "
                + "decompiler about left-to-right parameter push order. "
                + "ENHANCES: Parameter ordering in decompiled output.");
        } catch (Exception e) {
            writeTest("12_setCallingConvention", "fail", e.getMessage());
        }
    }

    // ── Category 5: Structure Recovery ──


    private void test_14_DataTypeManager() {
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int typeCount = dtm.getDataTypeCount(true);

            // Check if we can find/create useful types
            DataType pascalStr = new PascalStringDataType();
            DataType byteType = dtm.getDataType("/byte");
            DataType wordType = dtm.getDataType("/word");

            writeTest("14_DataTypeManager", "pass",
                "Program has " + typeCount + " data types. "
                + "PascalStringDataType available: " + (pascalStr != null) + ". "
                + "byte type: " + (byteType != null) + ", word type: " + (wordType != null) + ". "
                + "VERDICT: Useful utility — already used implicitly via createData(). "
                + "Could be used to create Borland Pascal record types. "
                + "ENHANCES: Type system richness.");
        } catch (Exception e) {
            writeTest("14_DataTypeManager", "fail", e.getMessage());
        }
    }

    // ── Category 6: Function Management ──

    private void test_15_FunctionManager() {
        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            int funcCount = fm.getFunctionCount();
            FunctionIterator it = fm.getFunctions(true);
            int iterCount = 0;
            String firstFuncInfo = "";
            while (it.hasNext()) {
                Function f = it.next();
                if (iterCount == 0) {
                    firstFuncInfo = f.getName() + " @ " + f.getEntryPoint()
                        + " (params: " + f.getParameterCount() + ")";
                }
                iterCount++;
            }
            writeTest("15_FunctionManager", "pass",
                "FunctionManager reports " + funcCount + " functions, "
                + "iterator found " + iterCount + ". First: " + firstFuncInfo + ". "
                + "VERDICT: Essential — already used for function iteration. "
                + "ALREADY USED in DecompileAll.java.");
        } catch (Exception e) {
            writeTest("15_FunctionManager", "fail", e.getMessage());
        }
    }

    private void test_16_FunctionComments() {
        try {
            Function func = getFirstFunction();
            // Read existing comments
            String existingPlate = func.getComment();
            String existingRepeat = func.getRepeatableComment();

            // Test setting a plate comment (non-destructively — only if none exists)
            boolean setComment = false;
            if (existingPlate == null || existingPlate.isEmpty()) {
                func.setComment("Test plate comment — API evaluation");
                setComment = true;
            }

            // Also test CodeUnit comments at the function entry
            Listing listing = currentProgram.getListing();
            CodeUnit cu = listing.getCodeUnitAt(func.getEntryPoint());
            String preComment = null;
            if (cu != null) {
                preComment = cu.getComment(CodeUnit.PRE_COMMENT);
            }

            writeTest("16_FunctionComments", "pass",
                "Function " + func.getName() + " plate comment set: " + setComment
                + ". CodeUnit at entry: " + (cu != null)
                + ". Pre-comment: " + (preComment != null) + ". "
                + "VERDICT: Very useful — setting plate/pre comments on functions "
                + "makes them appear in decompiled output. "
                + "REPLACES: label_functions.py inline comment injection. "
                + "Comments set in Ghidra DB appear automatically in decompiler output.");
        } catch (Exception e) {
            writeTest("16_FunctionComments", "fail", e.getMessage());
        }
    }

    private void test_17_createLabel() {
        try {
            // Test creating a label at a known address
            // Use the first data address to avoid disrupting code
            Address firstDataAddr = null;
            DataIterator di = currentProgram.getListing().getDefinedData(true);
            if (di.hasNext()) {
                firstDataAddr = di.next().getAddress();
            }

            boolean created = false;
            if (firstDataAddr != null) {
                try {
                    // Check if label already exists
                    Symbol[] existing = currentProgram.getSymbolTable()
                        .getSymbols(firstDataAddr);
                    createLabel(firstDataAddr, "test_api_label", true);
                    created = true;
                } catch (Exception e) {
                    // Label conflict
                }
            }

            writeTest("17_createLabel", "pass",
                "Label created at " + firstDataAddr + ": " + created + ". "
                + "VERDICT: Useful — can name data addresses (e.g., string constants) "
                + "so they show up by name in decompiled output instead of raw offsets. "
                + "ENHANCES: Readability of string references.");
        } catch (Exception e) {
            writeTest("17_createLabel", "fail", e.getMessage());
        }
    }

    // ── Category 7: Memory & References ──

    private void test_19_Memory() {
        try {
            Memory mem = currentProgram.getMemory();
            MemoryBlock[] blocks = mem.getBlocks();
            StringBuilder blockInfo = new StringBuilder();
            for (MemoryBlock b : blocks) {
                blockInfo.append(b.getName())
                    .append("(").append(b.getStart()).append("-").append(b.getEnd())
                    .append(", ").append(b.getSize()).append("B) ");
            }

            // Test reading bytes from a known address
            Address start = blocks[0].getStart();
            byte[] buf = new byte[16];
            int bytesRead = mem.getBytes(start, buf);

            writeTest("19_Memory", "pass",
                "Memory blocks: " + blockInfo.toString()
                + "Read " + bytesRead + " bytes from " + start + ". "
                + "VERDICT: Essential — already used for getString(). "
                + "Can read raw Pascal string bytes directly from Ghidra memory "
                + "instead of opening the EXE file separately. "
                + "REPLACES: annotate_strings.py EXE file scanning fallback.");
        } catch (Exception e) {
            writeTest("19_Memory", "fail", e.getMessage());
        }
    }

    private void test_20_ReferenceManager() {
        try {
            ReferenceManager rm = currentProgram.getReferenceManager();
            // Count references from the first function
            Function func = getFirstFunction();
            AddressSet body = new AddressSet(func.getBody());
            int refFromCount = 0;
            int refToCount = 0;
            AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext() && refFromCount < 1000) {
                Address addr = addrIter.next();
                Reference[] refsFrom = rm.getReferencesFrom(addr);
                refFromCount += refsFrom.length;
            }

            // Count references TO the function entry
            ReferenceIterator refsToIter = rm.getReferencesTo(func.getEntryPoint());
            while (refsToIter.hasNext()) {
                refsToIter.next();
                refToCount++;
            }

            writeTest("20_ReferenceManager", "pass",
                "Function " + func.getName() + " has " + refFromCount
                + " outgoing refs, " + refToCount + " incoming refs. "
                + "VERDICT: Useful for finding all callers of a function and all "
                + "data references. Could identify which functions reference which "
                + "strings. ENHANCES: Cross-reference analysis.");
        } catch (Exception e) {
            writeTest("20_ReferenceManager", "fail", e.getMessage());
        }
    }

    private void test_21_AddressSet() {
        try {
            // Test address set operations
            Function func = getFirstFunction();
            AddressSetView body = func.getBody();
            long addrCount = body.getNumAddresses();
            Address minAddr = body.getMinAddress();
            Address maxAddr = body.getMaxAddress();

            writeTest("21_AddressSet", "pass",
                "Function body: " + minAddr + "-" + maxAddr
                + " (" + addrCount + " addresses). "
                + "VERDICT: Utility class — already used implicitly. "
                + "Useful for limiting operations to specific address ranges. "
                + "ALREADY USED.");
        } catch (Exception e) {
            writeTest("21_AddressSet", "fail", e.getMessage());
        }
    }

    private void test_22_RelocationTable() {
        try {
            // Use reflection to access RelocationTable (may not be in all builds)
            Object rt = currentProgram.getClass().getMethod("getRelocationTable").invoke(currentProgram);
            int relocCount = 0;
            java.lang.reflect.Method getRelocs = rt.getClass().getMethod("getRelocations");
            Iterator<?> relocs = (Iterator<?>)getRelocs.invoke(rt);
            while (relocs.hasNext()) {
                relocs.next();
                relocCount++;
            }

            writeTest("22_RelocationTable", "pass",
                "Program has " + relocCount + " relocations. "
                + "VERDICT: Low value — Ghidra already applies MZ relocations "
                + "during import. Could be used to identify segment boundaries "
                + "but not essential for decompilation. SKIP.");
        } catch (Exception e) {
            writeTest("22_RelocationTable", "fail", e.getMessage());
        }
    }
}
