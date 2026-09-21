// Ghidra headless post-script: emit bounded inventory and decompiler evidence.
//@category AAR
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class AarGhidraInventory extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder();
        b.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int)c));
                    }
                    else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }

    private static String sha256(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder b = new StringBuilder();
        for (byte x : digest) b.append(String.format("%02x", x & 0xff));
        return b.toString();
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AAR inventory requires a current program");
        }
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: AarGhidraInventory.java <output-json>");
        }

        int functionCount = 0;
        int internalFunctionCount = 0;
        List<String> decomp = new ArrayList<>();

        DecompInterface iface = new DecompInterface();
        iface.toggleCCode(true);
        iface.toggleSyntaxTree(true);
        if (!iface.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open program");
        }

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            functionCount++;
            if (f.isExternal()) continue;
            internalFunctionCount++;

            String name = f.getName();
            if (!name.startsWith("aar_")) continue;

            DecompileResults result = iface.decompileFunction(f, 30, monitor);
            boolean ok = result != null && result.decompileCompleted() &&
                result.getDecompiledFunction() != null;
            String c = ok ? result.getDecompiledFunction().getC() : "";

            StringBuilder row = new StringBuilder();
            row.append("{");
            row.append("\"name\":").append(esc(name)).append(",");
            row.append("\"entry\":").append(esc(f.getEntryPoint().toString())).append(",");
            row.append("\"body_address_count\":").append(f.getBody().getNumAddresses()).append(",");
            row.append("\"decompile_completed\":").append(ok);
            if (ok) {
                row.append(",\"decompiled_c_sha256\":").append(esc(sha256(c)));
                row.append(",\"decompiled_c_length\":").append(c.length());
            }
            row.append("}");
            decomp.add(row.toString());
        }
        iface.dispose();

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema\": \"aar-ghidra-inventory/v0\",\n");
        out.append("  \"program\": {");
        out.append("\"name\":").append(esc(currentProgram.getName())).append(",");
        out.append("\"language_id\":").append(esc(currentProgram.getLanguageID().toString())).append(",");
        out.append("\"compiler_spec_id\":").append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append(",");
        out.append("\"executable_format\":").append(esc(currentProgram.getExecutableFormat()));
        out.append("},\n");
        out.append("  \"function_count\": ").append(functionCount).append(",\n");
        out.append("  \"internal_function_count\": ").append(internalFunctionCount).append(",\n");
        out.append("  \"target_decompilations\": [");
        for (int i = 0; i < decomp.size(); i++) {
            if (i > 0) out.append(",");
            out.append("\n    ").append(decomp.get(i));
        }
        if (!decomp.isEmpty()) out.append("\n  ");
        out.append("]\n");
        out.append("}\n");

        Path path = Path.of(args[0]).toAbsolutePath();
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
        println("AAR inventory wrote " + path);
    }
}
