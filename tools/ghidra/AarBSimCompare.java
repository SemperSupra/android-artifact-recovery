// Ghidra headless post-script: compare named functions to a source-known reference with BSim.
//@category AAR
import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.VectorCompare;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.framework.model.DomainFile;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AarBSimCompare extends GhidraScript {

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

    private static LSHVectorFactory vectorFactory() throws Exception {
        LSHVectorFactory factory = new WeightedLSHCosineVectorFactory();
        ResourceFile weights = GenSignatures.getWeightsFile(null, null);
        if (weights == null) {
            throw new IllegalStateException("No default BSim weights resource available");
        }
        try (InputStream input = weights.getInputStream()) {
            XmlPullParser parser = new NonThreadedXmlPullParserImpl(
                input, "AAR BSim weights", SpecXmlUtils.getXmlHandler(), false
            );
            factory.readWeights(parser);
        }
        return factory;
    }

    private static LSHVector vectorFor(Program program, Function function, LSHVectorFactory factory)
            throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleSyntaxTree(false);
            decompiler.setSignatureSettings(factory.getSettings());
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException(
                    "Decompiler could not open " + program.getName() + ": " + decompiler.getLastMessage()
                );
            }
            SignatureResult sig = decompiler.generateSignatures(function, false, 30, null);
            if (sig == null || sig.features == null) {
                throw new IllegalStateException("No BSim signature features for " + function.getName());
            }
            return factory.buildVector(sig.features);
        }
        finally {
            decompiler.closeProgram();
            decompiler.dispose();
        }
    }

    private static Map<String, Function> targetFunctions(Program program) {
        Map<String, Function> out = new HashMap<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (!f.isExternal() && f.getName().startsWith("aar_")) {
                out.put(f.getName(), f);
            }
        }
        return out;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AAR BSim comparison requires current program");
        }
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "usage: AarBSimCompare.java <reference-project-path> <output-json>"
            );
        }

        DomainFile refFile = state.getProject().getProjectData().getFile(args[0]);
        if (refFile == null) {
            throw new IllegalStateException("Reference DomainFile not found: " + args[0]);
        }

        Program reference = null;
        try {
            reference = (Program) refFile.getDomainObject(this, false, false, monitor);
            Map<String, Function> refFuncs = targetFunctions(reference);
            Map<String, Function> curFuncs = targetFunctions(currentProgram);

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

            List<String> rows = new ArrayList<>();
            for (String name : new String[] {"aar_known_mix", "aar_known_checksum"}) {
                Function query = curFuncs.get(name);
                Function known = refFuncs.get(name);
                if (query == null || known == null) {
                    throw new IllegalStateException(
                        "Missing target function " + name +
                        " query=" + (query != null) + " reference=" + (known != null)
                    );
                }

                LSHVector qv = vectorFor(currentProgram, query, factory);
                LSHVector rv = vectorFor(reference, known, factory);
                VectorCompare compare = new VectorCompare();
                double similarity = rv.compare(qv, compare);
                double significance = factory.calculateSignificance(compare);
                double querySelf = factory.getSelfSignificance(qv);
                double referenceSelf = factory.getSelfSignificance(rv);

                StringBuilder row = new StringBuilder();
                row.append("{");
                row.append("\"function\":").append(esc(name)).append(",");
                row.append("\"query_entry\":").append(esc(query.getEntryPoint().toString())).append(",");
                row.append("\"reference_entry\":").append(esc(known.getEntryPoint().toString())).append(",");
                row.append("\"similarity\":").append(Double.toString(similarity)).append(",");
                row.append("\"significance\":").append(Double.toString(significance)).append(",");
                row.append("\"query_self_significance\":").append(Double.toString(querySelf)).append(",");
                row.append("\"reference_self_significance\":").append(Double.toString(referenceSelf));
                row.append("}");
                rows.add(row.toString());
            }

            StringBuilder out = new StringBuilder();
            out.append("{\n");
            out.append("  \"schema\": \"aar-ghidra-bsim-pairwise/v0\",\n");
            out.append("  \"query_program\": ").append(esc(currentProgram.getName())).append(",\n");
            out.append("  \"reference_program\": ").append(esc(reference.getName())).append(",\n");
            out.append("  \"query_language_id\": ").append(esc(currentProgram.getLanguageID().toString())).append(",\n");
            out.append("  \"reference_language_id\": ").append(esc(reference.getLanguageID().toString())).append(",\n");
            out.append("  \"matches\": [");
            for (int i = 0; i < rows.size(); i++) {
                if (i > 0) out.append(",");
                out.append("\n    ").append(rows.get(i));
            }
            if (!rows.isEmpty()) out.append("\n  ");
            out.append("]\n");
            out.append("}\n");

            Path output = Path.of(args[1]).toAbsolutePath();
            if (output.getParent() != null) Files.createDirectories(output.getParent());
            Files.writeString(output, out.toString(), StandardCharsets.UTF_8);
            println("AAR BSim comparison wrote " + output);
        }
        finally {
            if (reference != null) reference.release(this);
        }
    }
}
