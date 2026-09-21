// Ghidra headless post-script: emit deterministic, bounded function evidence.
// @category AAR

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ExportFunctionEvidence extends GhidraScript {
    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private static String sha256(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (byte b : digest) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("expected: <output-json> <max-functions>");
        }
        String output = args[0];
        int maxFunctions = Integer.parseInt(args[1]);
        if (maxFunctions < 1 || maxFunctions > 10000) {
            throw new IllegalArgumentException("max-functions must be 1..10000");
        }

        List<Function> functions = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            functions.add(it.next());
        }
        functions.sort(Comparator.comparing(f -> f.getEntryPoint()));

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        try (PrintWriter out = new PrintWriter(output, StandardCharsets.UTF_8)) {
            out.println("{");
            out.println("  \"schema\": \"aar-ghidra-function-evidence/v0\",");
            out.println("  \"program\": {");
            out.println("    \"name\": \"" + esc(currentProgram.getName()) + "\",");
            out.println("    \"executable_format\": \"" + esc(currentProgram.getExecutableFormat()) + "\",");
            out.println("    \"language_id\": \"" + esc(currentProgram.getLanguage().getLanguageID().getIdAsString()) + "\",");
            out.println("    \"compiler_spec_id\": \"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()) + "\",");
            out.println("    \"image_base\": \"" + esc(currentProgram.getImageBase().toString()) + "\"");
            out.println("  },");
            out.println("  \"function_count\": " + functions.size() + ",");
            out.println("  \"functions\": [");

            int limit = Math.min(maxFunctions, functions.size());
            for (int i = 0; i < limit; i++) {
                Function f = functions.get(i);
                DecompileResults result = decompiler.decompileFunction(f, 30, monitor);
                boolean completed = result != null && result.decompileCompleted();
                String c = "";
                if (completed && result.getDecompiledFunction() != null) {
                    c = result.getDecompiledFunction().getC();
                }
                out.println("    {");
                out.println("      \"entry\": \"" + esc(f.getEntryPoint().toString()) + "\",");
                out.println("      \"name\": \"" + esc(f.getName()) + "\",");
                out.println("      \"body_address_count\": " + f.getBody().getNumAddresses() + ",");
                out.println("      \"external\": " + f.isExternal() + ",");
                out.println("      \"decompile_completed\": " + completed + ",");
                out.println("      \"decompiled_c_sha256\": \"" + sha256(c) + "\"");
                out.print("    }");
                if (i + 1 < limit) {
                    out.print(",");
                }
                out.println();
            }
            out.println("  ]");
            out.println("}");
        }
        decompiler.dispose();
    }
}
