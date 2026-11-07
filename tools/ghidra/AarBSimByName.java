// Ghidra headless post-script: compare an explicit bounded set of same-named functions with BSim.
//@category AAR
import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.VectorCompare;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AarBSimByName extends GhidraScript {
    private static final int MAX_NAMES = 128;

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

    private static Map<String, List<Function>> functionsByName(Program program) {
        Map<String, List<Function>> out = new HashMap<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal()) continue;
            out.computeIfAbsent(f.getName(), k -> new ArrayList<>()).add(f);
        }
        return out;
    }

    private static LSHVector vectorFor(
            DecompInterface decompiler,
            Function function,
            WeightedLSHCosineVectorFactory factory) throws Exception {
        SignatureResult sig = decompiler.generateSignatures(function, false, 30, null);
        if (sig == null || sig.features == null) {
            throw new IllegalStateException("No BSim signature features for " + function.getName());
        }
        return factory.buildVector(sig.features);
    }

    private static DecompInterface openDecompiler(
            Program program,
            WeightedLSHCosineVectorFactory factory) {
        DecompInterface d = new DecompInterface();
        d.setOptions(new DecompileOptions());
        d.toggleSyntaxTree(false);
        d.setSignatureSettings(factory.getSettings());
        if (!d.openProgram(program)) {
            String msg = d.getLastMessage();
            d.dispose();
            throw new IllegalStateException(
                "Decompiler could not open " + program.getName() + ": " + msg
            );
        }
        return d;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AAR BSim by-name comparison requires current program");
        }

        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "usage: AarBSimByName.java <reference-project-path> <names-file> <output-json>"
            );
        }

        DomainFile refFile = state.getProject().getProjectData().getFile(args[0]);
        if (refFile == null) {
            throw new IllegalStateException("Reference DomainFile not found: " + args[0]);
        }

        Path namesPath = Path.of(args[1]).toAbsolutePath();
        if (!Files.isRegularFile(namesPath)) {
            throw new IllegalStateException("names file missing: " + namesPath);
        }

        Set<String> wanted = new LinkedHashSet<>();
        for (String raw : Files.readAllLines(namesPath, StandardCharsets.UTF_8)) {
            String name = raw.trim();
            if (name.isEmpty() || name.startsWith("#")) continue;
            wanted.add(name);
        }
        if (wanted.isEmpty()) throw new IllegalStateException("names file is empty");
        if (wanted.size() > MAX_NAMES) {
            throw new IllegalStateException(
                "bounded comparison accepts at most " + MAX_NAMES + " names, got " + wanted.size()
            );
        }

        Program reference = null;
        DecompInterface queryDecompiler = null;
        DecompInterface referenceDecompiler = null;
        try {
            reference = (Program) refFile.getDomainObject(this, false, false, monitor);
            Map<String, List<Function>> refFuncs = functionsByName(reference);
            Map<String, List<Function>> curFuncs = functionsByName(currentProgram);

            WeightedLSHCosineVectorFactory factory = new WeightedLSHCosineVectorFactory();
            ResourceFile weights = GenSignatures.getWeightsFile(
                currentProgram.getLanguageID(), reference.getLanguageID()
            );
            if (weights == null) {
                throw new IllegalStateException(
                    "No BSim weights for " + currentProgram.getLanguageID() +
                    " vs " + reference.getLanguageID()
                );
            }
            try (InputStream input = weights.getInputStream()) {
                XmlPullParser parser = new NonThreadedXmlPullParserImpl(
                    input, "AAR BSim weights", SpecXmlUtils.getXmlHandler(), false
                );
                factory.readWeights(parser);
            }

            queryDecompiler = openDecompiler(currentProgram, factory);
            referenceDecompiler = openDecompiler(reference, factory);

            List<String> rows = new ArrayList<>();
            List<String> skips = new ArrayList<>();

            for (String name : wanted) {
                monitor.checkCancelled();
                List<Function> q = curFuncs.getOrDefault(name, List.of());
                List<Function> r = refFuncs.getOrDefault(name, List.of());
                if (q.size() != 1 || r.size() != 1) {
                    String reason =
                        q.size() == 0 ? "query-missing" :
                        r.size() == 0 ? "reference-missing" :
                        q.size() > 1 ? "query-ambiguous" : "reference-ambiguous";
                    skips.add(
                        "{\"function\":" + esc(name) +
                        ",\"reason\":" + esc(reason) +
                        ",\"query_count\":" + q.size() +
                        ",\"reference_count\":" + r.size() + "}"
                    );
                    continue;
                }

                Function query = q.get(0);
                Function known = r.get(0);
                LSHVector qv = vectorFor(queryDecompiler, query, factory);
                LSHVector rv = vectorFor(referenceDecompiler, known, factory);
                VectorCompare compare = new VectorCompare();
                double similarity = rv.compare(qv, compare);
                double significance = factory.calculateSignificance(compare);

                rows.add(
                    "{\"function\":" + esc(name) +
                    ",\"query_entry\":" + esc(query.getEntryPoint().toString()) +
                    ",\"reference_entry\":" + esc(known.getEntryPoint().toString()) +
                    ",\"similarity\":" + Double.toString(similarity) +
                    ",\"significance\":" + Double.toString(significance) +
                    ",\"query_self_significance\":" +
                        Double.toString(factory.getSelfSignificance(qv)) +
                    ",\"reference_self_significance\":" +
                        Double.toString(factory.getSelfSignificance(rv)) + "}"
                );
            }

            StringBuilder out = new StringBuilder();
            out.append("{\n");
            out.append("  \"schema\": \"aar-ghidra-bsim-by-name/v0\",\n");
            out.append("  \"query_program\": ").append(esc(currentProgram.getName())).append(",\n");
            out.append("  \"reference_program\": ").append(esc(reference.getName())).append(",\n");
            out.append("  \"requested_name_count\": ").append(wanted.size()).append(",\n");
            out.append("  \"policy\": {");
            out.append("\"identity_from_name\":false,");
            out.append("\"identity_from_bsim_alone\":false,");
            out.append("\"production_similarity_threshold\":\"UNQUALIFIED\",");
            out.append("\"max_names\":").append(MAX_NAMES).append("},\n");

            out.append("  \"matches\": [");
            for (int i = 0; i < rows.size(); i++) {
                if (i > 0) out.append(",");
                out.append("\n    ").append(rows.get(i));
            }
            if (!rows.isEmpty()) out.append("\n  ");
            out.append("],\n");

            out.append("  \"skipped\": [");
            for (int i = 0; i < skips.size(); i++) {
                if (i > 0) out.append(",");
                out.append("\n    ").append(skips.get(i));
            }
            if (!skips.isEmpty()) out.append("\n  ");
            out.append("]\n");
            out.append("}\n");

            Path output = Path.of(args[2]).toAbsolutePath();
            if (output.getParent() != null) Files.createDirectories(output.getParent());
            Files.writeString(output, out.toString(), StandardCharsets.UTF_8);
            println(
                "AAR BSim by-name wrote " + output +
                " matches=" + rows.size() + " skipped=" + skips.size()
            );
        }
        finally {
            if (queryDecompiler != null) {
                queryDecompiler.closeProgram();
                queryDecompiler.dispose();
            }
            if (referenceDecompiler != null) {
                referenceDecompiler.closeProgram();
                referenceDecompiler.dispose();
            }
            if (reference != null) reference.release(this);
        }
    }
}
