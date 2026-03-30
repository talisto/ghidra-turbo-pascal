// MinimalTest.java — Minimal Ghidra API test
import ghidra.app.script.GhidraScript;
import java.io.*;

public class MinimalTest extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("MinimalTest running on: " + currentProgram.getName());
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
