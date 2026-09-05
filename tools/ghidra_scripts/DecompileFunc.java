// DecompileFunc.java - Ghidra headless post-script: decompile one function
// and emit JSON {function, address, decompiled} on stdout.
// Env: GHIDRA_DECOMP_FUNC = function name OR address (hex/dec) OR "entry".
//@category WinRE
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.PrintWriter;
import java.util.Iterator;

public class DecompileFunc extends GhidraScript {
    @Override
    public void run() throws Exception {
        String want = getScriptArgs().length > 0 ? getScriptArgs()[0] : "entry";
        String env = System.getenv("GHIDRA_DECOMP_FUNC");
        if (env != null && !env.isBlank()) { want = env; }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        Function f = null;
        if (want.equalsIgnoreCase("entry")) {
            Address ep = currentProgram.getImageBase();
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            if (it.hasNext()) { f = it.next(); }
        } else if (want.startsWith("FUN_") || want.matches("(?i)0x[0-9a-f]+")) {
            String hex = want.startsWith("FUN_") ? want.substring(4) : want.replace("0x", "");
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseLong(hex, 16));
            f = currentProgram.getFunctionManager().getFunctionAt(a);
            if (f == null) { f = currentProgram.getFunctionManager().getFunctionContaining(a); }
        } else {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function cand = it.next();
                if (cand.getName().equalsIgnoreCase(want)) { f = cand; break; }
            }
        }

        StringBuilder json = new StringBuilder("{");
        if (f == null) {
            json.append("\"error\": \"function not found: ").append(want.replace("\"", "'")).append("\"");
        } else {
            DecompileResults res = di.decompileFunction(f, 120, new ConsoleTaskMonitor());
            String code = res != null && res.decompileCompleted()
                    ? res.getDecompiledFunction().getC() : "// decompile failed";
            json.append("\"function\": \"").append(f.getName().replace("\"", "'"))
                .append("\", \"address\": \"").append(f.getEntryPoint().toString())
                .append("\", \"decompiled\": \"")
                .append(code.replace("\\", "\\\\").replace("\"", "\\\"")
                        .replace("\n", "\\n").replace("\r", "")
                        .replace("\t", "  "))
                .append("\"");
        }
        json.append("}");
        PrintWriter out = new PrintWriter(System.out, true);
        out.println(json.toString());
        di.dispose();
    }
}
