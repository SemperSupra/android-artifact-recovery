// AAR A-4: read-only, source-blind pseudocode projection of stripped JNI callees.
//@category AAR
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AarJniSemanticEvidence extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("program missing");
        String[] args=getScriptArgs();
        if (args.length!=1 || !("x86_64".equals(args[0]) || "aarch64".equals(args[0])))
            throw new IllegalArgumentException("ABI required");
        final String export="Java_org_sempersupra_aar_golden_NativeBridge_nativeDispatch";
        Function root=null;
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f=it.next();
            if (export.equals(f.getName())) {
                if (root!=null)throw new IllegalStateException("duplicate export");
                root=f;
            }
        }
        if (root==null || root.isExternal())throw new IllegalStateException("JNI root absent");
        List<Function> children=new ArrayList<Function>();
        for (Function f:root.getCalledFunctions(monitor)) {
            if (!f.isExternal() && !f.equals(root))children.add(f);
        }
        Collections.sort(children,(a,b)->a.getEntryPoint().compareTo(b.getEntryPoint()));
        if (children.size()!=2)throw new IllegalStateException("exactly two source-blind native helpers required");
        DecompInterface d=new DecompInterface();
        d.toggleCCode(true);
        if (!d.openProgram(currentProgram))throw new IllegalStateException("decompiler failed");
        println("AAR_A4_ABI="+args[0]);
        println("AAR_A4_BASE="+Long.toHexString(currentProgram.getImageBase().getOffset()));
        for(Function f:children) {
            monitor.checkCancelled();
            if(f.getName().contains("aar_fold")||f.getName().contains("aar_affine"))
                throw new IllegalStateException("reference helper symbol leaked");
            DecompileResults result=d.decompileFunction(f,30,monitor);
            if(result==null || !result.decompileCompleted() || result.getDecompiledFunction()==null)
                throw new IllegalStateException("callee not decompiled");
            String c=result.getDecompiledFunction().getC();
            if (c.length()>4096 || c.length()<12)throw new IllegalStateException("pseudocode size invalid");
            if(c.contains("aar_fold")||c.contains("aar_affine"))
                throw new IllegalStateException("reference helper label leaked");
            println("AAR_A4_IR="+Long.toHexString(f.getEntryPoint().getOffset())+"|"+
                Base64.getEncoder().encodeToString(c.getBytes(StandardCharsets.UTF_8)));
        }
        d.dispose();
        println("AAR_A4_COUNT="+children.size());
    }
}
