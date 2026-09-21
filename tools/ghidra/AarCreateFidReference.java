// Ghidra headless post-script: create a small FID reference database from current program.
//@category AAR
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class AarCreateFidReference extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("current program required");
        String[] args = getScriptArgs();
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "usage: AarCreateFidReference.java <db-file> <family> <version> <variant> <output-json>"
            );
        }

        File dbFile = new File(args[0]).getAbsoluteFile();
        String family = args[1];
        String version = args[2];
        String variant = args[3];
        Path output = Path.of(args[4]).toAbsolutePath();

        if (dbFile.exists()) {
            throw new IllegalStateException("FID database already exists: " + dbFile);
        }

        FidFileManager manager = FidFileManager.getInstance();
        manager.createNewFidDatabase(dbFile);
        FidFile fidFile = manager.addUserFidFile(dbFile);
        if (fidFile == null) throw new IllegalStateException("could not attach new FID database");

        FidService service = new FidService();
        DomainFile domain = currentProgram.getDomainFile();
        if (domain == null) throw new IllegalStateException("current program has no domain file");

        FidPopulateResult result;
        try (FidDB db = fidFile.getFidDB(true)) {
            result = service.createNewLibraryFromPrograms(
                db,
                family,
                version,
                variant,
                List.of(domain),
                null,
                currentProgram.getLanguageID(),
                null,
                null,
                monitor
            );
            db.saveDatabase("AAR FID reference", monitor);
        }

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"schema\": \"aar-ghidra-fid-reference/v0\",\n");
        out.append("  \"family\": ").append(esc(family)).append(",\n");
        out.append("  \"version\": ").append(esc(version)).append(",\n");
        out.append("  \"variant\": ").append(esc(variant)).append(",\n");
        out.append("  \"database\": ").append(esc(dbFile.getAbsolutePath())).append(",\n");
        out.append("  \"language_id\": ").append(esc(currentProgram.getLanguageID().toString())).append(",\n");
        out.append("  \"total_attempted\": ").append(result.getTotalAttempted()).append(",\n");
        out.append("  \"total_added\": ").append(result.getTotalAdded()).append(",\n");
        out.append("  \"total_excluded\": ").append(result.getTotalExcluded()).append("\n");
        out.append("}\n");

        if (output.getParent() != null) Files.createDirectories(output.getParent());
        Files.writeString(output, out.toString(), StandardCharsets.UTF_8);
        println("AAR FID reference database created: " + dbFile);
    }
}
