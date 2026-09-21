// Ghidra headless post-script: query a supplied FID database using current program hashes.
//@category AAR
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class AarQueryFidReference extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }

    private static String hex(long value) {
        return String.format("%016x", value);
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("current program required");
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "usage: AarQueryFidReference.java <db-file> <family> <output-json>"
            );
        }

        File dbFile = new File(args[0]).getAbsoluteFile();
        String family = args[1];
        Path output = Path.of(args[2]).toAbsolutePath();

        if (!dbFile.isFile()) throw new IllegalStateException("FID database missing: " + dbFile);

        FidFileManager manager = FidFileManager.getInstance();
        FidFile attached = manager.addUserFidFile(dbFile);
        if (attached == null) throw new IllegalStateException("could not attach FID database");

        FidService service = new FidService();
        List<String> rows = new ArrayList<>();

        try (FidQueryService query = service.openFidQueryService(currentProgram.getLanguage(), false)) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function f = it.next();
                if (f.isExternal()) continue;

                FidHashQuad hash = service.hashFunction(f);
                if (hash == null) continue;

                List<FunctionRecord> candidates = query.findFunctionsByFullHash(hash.getFullHash());
                for (FunctionRecord ref : candidates) {
                    LibraryRecord lib = query.getLibraryForFunction(ref);
                    if (lib == null || !family.equals(lib.getLibraryFamilyName())) continue;

                    boolean specificMatch = ref.getSpecificHash() == hash.getSpecificHash();

                    StringBuilder row = new StringBuilder();
                    row.append("{");
                    row.append("\"query_function\":").append(esc(f.getName())).append(",");
                    row.append("\"query_entry\":").append(esc(f.getEntryPoint().toString())).append(",");
                    row.append("\"reference_function\":").append(esc(ref.getName())).append(",");
                    row.append("\"reference_family\":").append(esc(lib.getLibraryFamilyName())).append(",");
                    row.append("\"reference_version\":").append(esc(lib.getLibraryVersion())).append(",");
                    row.append("\"reference_variant\":").append(esc(lib.getLibraryVariant())).append(",");
                    row.append("\"full_hash\":").append(esc(hex(hash.getFullHash()))).append(",");
                    row.append("\"specific_hash\":").append(esc(hex(hash.getSpecificHash()))).append(",");
                    row.append("\"specific_match\":").append(specificMatch);
                    row.append("}");
                    rows.add(row.toString());
                }
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema\": \"aar-ghidra-fid-query/v0\",\n");
        out.append("  \"program\": ").append(esc(currentProgram.getName())).append(",\n");
        out.append("  \"family\": ").append(esc(family)).append(",\n");
        out.append("  \"matches\": [");
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) out.append(",");
            out.append("\n    ").append(rows.get(i));
        }
        if (!rows.isEmpty()) out.append("\n  ");
        out.append("]\n");
        out.append("}\n");

        if (output.getParent() != null) Files.createDirectories(output.getParent());
        Files.writeString(output, out.toString(), StandardCharsets.UTF_8);
        println("AAR FID query wrote " + output);
    }
}
