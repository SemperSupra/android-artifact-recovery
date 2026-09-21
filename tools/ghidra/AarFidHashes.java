// Ghidra headless post-script: emit Function ID hashes as normalized evidence.
//@category AAR
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class AarFidHashes extends GhidraScript {

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
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        b.append('"');
        return b.toString();
    }

    private static String hex(long value) {
        return String.format("%016x", value);
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AAR FID evidence requires a current program");
        }
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: AarFidHashes.java <output-json>");
        }

        FidService service = new FidService();
        List<String> rows = new ArrayList<>();
        int eligible = 0;
        int tooSmall = 0;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (f.isExternal()) continue;

            FidHashQuad hash = service.hashFunction(f);
            if (hash == null) {
                tooSmall++;
                continue;
            }
            eligible++;

            StringBuilder row = new StringBuilder();
            row.append("{");
            row.append("\"name\":").append(esc(f.getName())).append(",");
            row.append("\"entry\":").append(esc(f.getEntryPoint().toString())).append(",");
            row.append("\"code_unit_size\":").append(hash.getCodeUnitSize()).append(",");
            row.append("\"specific_additional_size\":").append(hash.getSpecificHashAdditionalSize()).append(",");
            row.append("\"full_hash\":").append(esc(hex(hash.getFullHash()))).append(",");
            row.append("\"specific_hash\":").append(esc(hex(hash.getSpecificHash())));
            row.append("}");
            rows.add(row.toString());
        }

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema\": \"aar-ghidra-fid-hashes/v0\",\n");
        out.append("  \"program\": {");
        out.append("\"name\":").append(esc(currentProgram.getName())).append(",");
        out.append("\"language_id\":").append(esc(currentProgram.getLanguageID().toString())).append(",");
        out.append("\"compiler_spec_id\":").append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
        out.append("},\n");
        out.append("  \"eligible_function_count\": ").append(eligible).append(",\n");
        out.append("  \"too_small_function_count\": ").append(tooSmall).append(",\n");
        out.append("  \"functions\": [");
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) out.append(",");
            out.append("\n    ").append(rows.get(i));
        }
        if (!rows.isEmpty()) out.append("\n  ");
        out.append("]\n");
        out.append("}\n");

        Path path = Path.of(args[0]).toAbsolutePath();
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
        println("AAR FID hashes wrote " + path);
    }
}
