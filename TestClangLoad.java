import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;

public class TestClangLoad extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("TestClangLoad: classes loaded OK");
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ghidra.program.model.listing.Function func = getFirstFunction();
        if (func != null) {
            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res.decompileCompleted()) {
                HighFunction hf = res.getHighFunction();
                ClangTokenGroup markup = res.getCCodeMarkup();
                println("HighFunction: " + (hf != null));
                println("Markup: " + (markup != null));
                if (hf != null) {
                    LocalSymbolMap lsm = hf.getLocalSymbolMap();
                    println("Params: " + lsm.getNumParams());
                }
                if (markup != null) {
                    println("Children: " + markup.numChildren());
                }
            }
        }
        decomp.dispose();
    }
}
