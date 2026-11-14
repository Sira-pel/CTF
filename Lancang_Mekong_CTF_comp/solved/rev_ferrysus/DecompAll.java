// Decompile all functions to /tmp/ferry_decomp
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class DecompAll extends GhidraScript {
    public void run() throws Exception {
        String outdir = System.getenv("DECOMP_OUT");
        if (outdir == null) outdir = "/tmp/ferry_decomp";
        File d = new File(outdir);
        d.mkdirs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        int n = 0;
        for (Function f : fm.getFunctions(true)) {
            DecompileResults res = di.decompileFunction(f, 60, monitor);
            String c;
            if (res != null && res.decompileCompleted()) {
                c = res.getDecompiledFunction().getC();
            } else {
                c = "// fail " + (res == null ? "null" : res.getErrorMessage());
            }
            String name = f.getEntryPoint().toString() + "_" + f.getName();
            name = name.replaceAll("[/:]", "_") + ".c";
            PrintWriter pw = new PrintWriter(new File(d, name));
            pw.println("// " + f.getName() + " @ " + f.getEntryPoint());
            pw.println(c);
            pw.close();
            n++;
        }
        println("DECOMPILED " + n + " to " + outdir);
    }
}
