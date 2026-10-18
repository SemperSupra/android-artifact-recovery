#!/usr/bin/env python3
"""Independent public synthetic Java oracle; model text is never compiled."""
import hashlib,json
from pathlib import Path
import subprocess,sys
ROLES=("DETERMINISTIC_CANDIDATE","REASONING_CANDIDATE")
TASK="java-overload-dex-recovery-synthetic-v0"
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
    result["correct_signature"]=val["selected_signature"]=="a(Object)"
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
    ref=subprocess.run(["java","-cp",str(raw_dir),"OverloadOracle"],
                       check=True,timeout=10,capture_output=True,text=True).stdout.strip()
    if ref!="OBJECT":
        raise ValueError("compiled Java oracle drift")
    observations=[]
    for role in ROLES:
        raw=json.loads((raw_dir/(role+".json")).read_text(encoding="utf8"))
        observations.append(verdict(raw,source,ref))
    receipt={"schema":"aar-jadx-local-interview-score/v0","task":TASK,
        "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
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
