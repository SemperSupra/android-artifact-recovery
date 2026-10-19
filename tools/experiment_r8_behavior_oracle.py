#!/usr/bin/env python3
"""Independent ten-vector oracle for unmodified raw JADX Java after R8.

Source-known original classes are used only by the evaluator. We do not
provide R8 mappings or source truth to the earlier blind JADX stage.
Do not infer original R8 DEX behavior from recompilation of decompiled Java.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

LABELS=("release","rename-only","shrink-only","shrink-optimize","full-r8")
RENAMED=("rename-only","full-r8")
TARGET=Path("org/sempersupra/aar/golden/kotlin")

def categorize_javac(stderr: bytes) -> dict:
    """Public-safe diagnostic taxonomy: no source strings, paths, or symbols."""
    value=stderr.decode("utf-8","replace")
    markers={
        "missing_symbol":"cannot find symbol",
        "missing_package":"does not exist",
        "type_incompatibility":"incompatible types",
        "wrong_overload":"cannot be applied to given types",
        "duplicate_definition":"is already defined",
        "invalid_generated_java":"illegal start of expression",
        "invalid_statement":"not a statement",
        "visibility":"has private access",
        "unhandled_exception":"unreported exception",
        "ambiguous_method":"reference to",
    }
    results={key:value.count(pattern) for key,pattern in markers.items()}
    results={key:n for key,n in results.items() if n}
    if b"error:" in stderr and not results:
        results["unclassified_javac_diagnostic"]=1
    return results

def call(argv: list[str],seconds: int=90) -> tuple[dict,bytes]:
    started=time.monotonic()
    try:
        proc=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,timeout=seconds,check=False)
        return ({"exit_code":proc.returncode,
                 "duration_ms":round((time.monotonic()-started)*1000,2),
                 "stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),
                 "stderr_sha256":hashlib.sha256(proc.stderr).hexdigest(),
                 "compiler_error_lines":sum(b"error:" in ln for ln in proc.stderr.splitlines()),
                 "javac_diagnostic_categories":categorize_javac(proc.stderr)},
                proc.stdout)
    except subprocess.TimeoutExpired:
        return ({"exit_code":None,"timeout":True,"duration_ms":seconds*1000},b"")

def lines(raw: bytes) -> list[str]:
    try:
        xs=raw.decode("utf-8").strip().splitlines()
    except UnicodeDecodeError as err:
        raise ValueError("invalid UTF8 behavioral oracle output") from err
    if len(xs)!=10 or any(not x.startswith(f"case={i}|") for i,x in enumerate(xs)):
        raise ValueError("source-known ten-vector harness output malformed")
    return xs

def classify(expected: list[str], raw: bytes) -> dict:
    try:
        observed=lines(raw)
    except ValueError:
        return {"state":"OUTPUT_INVALID","matched":0,"mismatched":0,"unknown":10}
    matches=sum(a==b for a,b in zip(expected,observed))
    return {"state":"MATCH_10_VECTORS" if matches==10 else "MISMATCH_OBSERVED",
            "matched":matches,"mismatched":10-matches,"unknown":0}

def evaluate(original: Path,stdlib: Path,annotations: Path|None,
             harness: Path,recovered: Path,output: Path) -> dict:
    if output.exists():
        raise ValueError("refusing to overwrite sealed scoring output")
    if not original.is_dir() or not stdlib.is_file() or not harness.is_file():
        raise ValueError("missing original source-known reference classpath")
    if annotations is not None and not annotations.is_file():
        raise ValueError("invalid annotations reference")
    if any(not (recovered/l/"sources").is_dir() for l in LABELS):
        raise ValueError("all five sealed raw JADX source trees required")
    output.mkdir(parents=True)
    deps=[str(stdlib)]+([str(annotations)] if annotations else [])
    cp=":".join([str(original),*deps])
    oh=output/"independent-original-harness"
    oh.mkdir()
    original_compile,_=call(["javac","-encoding","UTF-8","-cp",cp,
                             "-d",str(oh),str(harness)])
    if original_compile["exit_code"]!=0:
        raise ValueError("original ten-vector harness did not compile")
    original_run, raw=call(["java","-cp",str(oh)+":"+cp,
                           "GoldenFingerprintMatrixHarness"])
    if original_run["exit_code"]!=0:
        raise ValueError("original oracle execution failed")
    expected=lines(raw)
    methods={}
    for label in LABELS:
        if label in RENAMED:
            methods[label]={"state":"NOT_EVALUATED_RENAMED_NO_ADAPTER",
                            "matched":0,"mismatched":0,"unknown":10}
            continue
        sources=sorted((recovered/label/"sources"/TARGET).rglob("*.java"))
        value={"raw_sources":len(sources),"matched":0,
               "mismatched":0,"unknown":10,"state":"TARGET_MISSING"}
        if sources:
            root=output/label
            root.mkdir()
            classes=root/"classes"
            classes.mkdir()
            built,_=call(["javac","-encoding","UTF-8","-cp",":".join(deps),
                          "-d",str(classes),*map(str,sources)])
            value["java_compile"]=built
            value["state"]="RAW_JAVA_COMPILE_FAILED"
            if built["exit_code"]==0:
                harness_dir=root/"harness"
                harness_dir.mkdir()
                compiled,_=call(["javac","-encoding","UTF-8",
                                 "-cp",":".join([str(classes),*deps]),
                                 "-d",str(harness_dir),str(harness)])
                value["harness_compile"]=compiled
                value["state"]="RECOVERED_API_INCOMPATIBLE"
                if compiled["exit_code"]==0:
                    executed,raw=call(["java","-cp",
                                       ":".join([str(harness_dir),str(classes),*deps]),
                                       "GoldenFingerprintMatrixHarness"])
                    value["java_execute"]=executed
                    value["state"]="RECOVERED_JAVA_EXECUTION_FAILED"
                    if executed["exit_code"]==0:
                        value.update(classify(expected,raw))
        methods[label]=value
        print(json.dumps({"variant":label,"result":value["state"],
                          "matched":value["matched"],"unknown":value["unknown"],
                          "javac_categories":value.get("java_compile",{}).get("javac_diagnostic_categories",{})},
                         sort_keys=True),flush=True)
    doc={"schema":"aar-r8-raw-java-oracle/v0",
         "source_known_oracle_vectors":10,"original_compile":original_compile,
         "original_execution":original_run,"methods":methods,
         "original_r8_dex_behavior":"NOT_TESTED",
         "mapping_passed_to_recoverer":False,"mapping_passed_to_evaluator":False,
         "generalized_recovery_qualified":False,
         "interpretation":"Raw unmodified recovered Java, ten source-known cases only."}
    (output/"result.json").write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",
                                      encoding="utf-8")
    return doc

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("original_classes","kotlin_stdlib","harness","recovered_root","out"):
        p.add_argument("--"+name.replace("_","-"),type=Path,required=True)
    p.add_argument("--annotations",default="")
    a=p.parse_args()
    try:
        result=evaluate(a.original_classes,a.kotlin_stdlib,
                        Path(a.annotations) if a.annotations else None,
                        a.harness,a.recovered_root,a.out)
        print(json.dumps({"state":"R8_RAW_JAVA_ORACLE_SCORED","variants":len(result["methods"]),
                          "generalized_recovery":False},sort_keys=True))
        return 0
    except (OSError,ValueError) as error:
        print(json.dumps({"state":"BLOCKED","reason":str(error)}),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
