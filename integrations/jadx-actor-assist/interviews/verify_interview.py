#!/usr/bin/env python3
"""Independent public synthetic Java oracle; model text is never compiled."""
import hashlib,json,re
from pathlib import Path
import subprocess,sys
ROLES=("DETERMINISTIC_CANDIDATE","REASONING_CANDIDATE")
TASK="java-overload-dex-recovery-synthetic-v0"
def canonical_signature_kind(source):
    """Bounded syntactic representations of the same JVM parameter signature.

    This policy is fixed before re-running models; it never infers missing
    names or accepts a different overload by semantic keyword proximity.
    """
    if not isinstance(source,str) or len(source)>160:
        return "UNPARSEABLE"
    pattern=(r"\s*(?:(?:public|private|protected)\s+)?"
             r"(?:static\s+)?(?:String\s+|java\.lang\.String\s+)?"
             r"(?:OverloadOracle\.)?a\s*\(\s*"
             r"(?:java\.lang\.)?(Object|String)"
             r"(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\)\s*")
    m=re.fullmatch(pattern,source)
    return m.group(1).upper() if m else "UNPARSEABLE"

def verdict(raw,source,expected):
    if raw.get("schema")!="aar-jadx-local-actor-interview/v0" or raw.get("task")!=TASK:
        raise ValueError("actor/task contract mismatch")
    if raw.get("external_disclosure") is not False or raw.get("source_scope")!="PUBLIC_SYNTHETIC":
        raise ValueError("source/egress boundary violated")
    if raw.get("code_sha256")!=hashlib.sha256(source.encode()).hexdigest():
        raise ValueError("source SHA mismatch")
    if raw.get("role") not in ROLES:
        raise ValueError("unknown actor role")
    result={"role":raw["role"],"status":raw["status"],"scored":False,
        "pass":False,"correct_output":False,"correct_signature":False,
        "canonical_overload_kind":"UNPARSEABLE",
        "uncertainty_calibrated":False,"valid_citations":False,
        "requested_model":raw.get("requested_model"),
        "observed_model":raw.get("observed_model"),
        "code_sha256":raw.get("code_sha256"),"prompt_sha256":raw.get("prompt_sha256"),
        "elapsed_ms":raw.get("elapsed_ms"),"failure_class":raw.get("failure_class")}
    if raw["status"]!="OBSERVED_UNVERIFIED":
        return result
    body=raw.get("candidate")
    if not isinstance(body,str) or len(body)>30000:
        return result
    body=body.strip()
    triple=chr(96)*3
    if body.startswith(triple+"json") and body.endswith(triple):
        body=body[len(triple+"json"):-len(triple)].strip()
    try:
        val=json.loads(body)
    except (ValueError,TypeError):
        result["status"]="INVALID_JSON"
        return result
    required={"runtime_output","selected_signature","original_source_names","evidence"}
    if not isinstance(val,dict) or set(val)!=required or any(
        not isinstance(val[k],str) for k in required-{"evidence"}):
        result["status"]="INVALID_SCHEMA"
        return result
    ev=val["evidence"]
    valid=(isinstance(ev,list) and 2<=len(ev)<=8 and
           all(isinstance(e,str) for e in ev) and len(set(ev))==len(ev) and
           all(e in {f"L{i+1}" for i in range(len(source.splitlines()))} for e in ev))
    result["scored"]=True
    result["correct_output"]=val["runtime_output"]==expected
    result["canonical_overload_kind"]=canonical_signature_kind(val["selected_signature"])
    result["correct_signature"]=result["canonical_overload_kind"]=="OBJECT"
    result["uncertainty_calibrated"]=val["original_source_names"]=="UNKNOWN"
    result["valid_citations"]=bool(valid)
    result["pass"]=all(result[k] for k in (
        "correct_output","correct_signature","uncertainty_calibrated","valid_citations"))
    result["status"]="MATCH_FOUR_FIELDS" if result["pass"] else "OBSERVED_MISMATCH"
    return result
def evaluate(source_file,raw_dir,output):
    if output.exists():
        raise ValueError("refuse overwriting experiment")
    source=source_file.read_text(encoding="utf8")
    subprocess.run(["javac","-encoding","UTF-8","-d",str(raw_dir),str(source_file)],
                   check=True,timeout=25,capture_output=True)
    signatures=subprocess.run(["javap","-classpath",str(raw_dir),"-p","-s",
                               "OverloadOracle"],check=True,capture_output=True,
                              text=True,timeout=10).stdout
    if ("descriptor: (Ljava/lang/Object;)Ljava/lang/String;" not in signatures or
        "descriptor: (Ljava/lang/String;)Ljava/lang/String;" not in signatures):
        raise ValueError("expected independent JVM overload descriptors unavailable")
    ref=subprocess.run(["java","-cp",str(raw_dir),"OverloadOracle"],
                       check=True,timeout=10,capture_output=True,text=True).stdout.strip()
    if ref!="OBJECT":
        raise ValueError("compiled Java oracle drift")
    observations=[]
    for role in ROLES:
        raw=json.loads((raw_dir/(role+".json")).read_text(encoding="utf8"))
        observations.append(verdict(raw,source,ref))
    receipt={"schema":"aar-jadx-local-interview-score/v1","task":TASK,
        "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
        "scoring_policy":"JVM_OVERLOAD_CANONICALIZATION_V1",
        "oracle":"INDEPENDENT_JAVAC_JAVA_AUTHOR_OWNED",
        "oracle_output_sha256":hashlib.sha256(ref.encode()).hexdigest(),
        "results":observations,"model_generalization":"UNKNOWN",
        "original_R8_recovery":"NOT_TESTED","independent_holdout":"NOT_TESTED",
        "external_inference":"NOT_USED"}
    output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return receipt
if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: verify_interview.py fixture raw-dir receipt")
    r=evaluate(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
    for i in r["results"]:
        print(json.dumps({"role":i["role"],"status":i["status"],
                          "passed":i["pass"],"scored":i["scored"]},sort_keys=True))
    print("LOCAL_JADX_ACTOR_INTERVIEW=OBSERVED;GENERALIZATION=UNKNOWN")
