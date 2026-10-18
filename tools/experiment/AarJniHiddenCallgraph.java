// AAR A-3 read-only Ghidra JNI function-boundary/callgraph witness.
//@category AAR
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AarJniHiddenCallgraph extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("no program");
        String[] args = getScriptArgs();
        if (args.length != 1 || !("x86_64".equals(args[0]) || "aarch64".equals(args[0])))
            throw new IllegalArgumentException("ABI label required");
        final String jni = "Java_org_sempersupra_aar_golden_NativeBridge_nativeDispatch";
        Function exported = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (jni.equals(f.getName())) {
                if (exported != null) throw new IllegalStateException("duplicate JNI exports");
                exported = f;
            }
        }
        if (exported == null || exported.isExternal())
            throw new IllegalStateException("JNI entry was not recovered");
        println("AAR_A3_ABI=" + args[0]);
        println("AAR_A3_JNI_ENTRY=" + Long.toHexString(exported.getEntryPoint().getOffset()));
        List<Function> targets = new ArrayList<Function>();
        for (Function callee : exported.getCalledFunctions(monitor)) {
            if (callee.isExternal()) continue;
            if (callee.equals(exported)) continue;
            // The stripped program must not retain known-private symbol names.
            if (callee.getName().contains("aar_fold") || callee.getName().contains("aar_affine"))
                throw new IllegalStateException("source symbol leak");
            targets.add(callee);
        }
        Collections.sort(targets, (a,b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
        if (targets.size() > 16) throw new IllegalStateException("unbounded JNI callgraph");
        DecompInterface dec = new DecompInterface();
        dec.toggleCCode(true);
        if (!dec.openProgram(currentProgram)) throw new IllegalStateException("decompiler unavailable");
        for (Function callee : targets) {
            monitor.checkCancelled();
            DecompileResults result = dec.decompileFunction(callee, 30, monitor);
            boolean decompiled = result != null && result.decompileCompleted()
                && result.getDecompiledFunction() != null;
            println("AAR_A3_CALLEE=" + Long.toHexString(callee.getEntryPoint().getOffset())
                + "|" + callee.getBody().getNumAddresses() + "|" + decompiled);
        }
        dec.dispose();
        println("AAR_A3_INTERNAL_CALLS=" + targets.size());
    }
}
