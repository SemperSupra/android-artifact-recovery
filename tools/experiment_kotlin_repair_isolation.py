#!/usr/bin/env python3
"""Bounded Kotlin reconstruction-repair isolation on an independent vector matrix.

All source and APKs are synthetic public goldens. Keep raw Java, minimal
diagnostic intervention, and historical repair-assisted output separate.
This is a comparative experiment, not a generic Kotlin deobfuscator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import time

from qualify_method_comparison import compare
from repair_jadx_kotlin_java import dedupe_simple_getters, repair

PACKAGE = "org/sempersupra/aar/golden/kotlin"
CLASS = "GoldenFingerprintMatrixHarness"


def checksum(file: pathlib.Path) -> str:
    return hashlib.sha256(file.read_bytes()).hexdigest()


def invoke(argv: list[str], timeout: int = 120) -> dict:
    start = time.monotonic()
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=False, timeout=timeout)
        return {"exit_code": p.returncode,
                "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
                "stdout": p.stdout.decode("utf-8", "replace")[-24000:],
                "stderr": p.stderr.decode("utf-8", "replace")[-24000:]}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "elapsed_ms": timeout * 1000,
                "stdout": "", "stderr": "TIMEOUT"}


def main() -> int:
    p = argparse.ArgumentParser()
    for arg in ("apk", "original_classes", "kotlin_stdlib", "matrix_harness", "jadx", "out"):
        p.add_argument("--" + arg.replace("_", "-"), required=True)
    p.add_argument("--annotations", default="")
    a = p.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    origcp = ":".join(filter(None, (a.original_classes, a.kotlin_stdlib, a.annotations)))
    candcp = ":".join(filter(None, (a.kotlin_stdlib, a.annotations)))

    oracle_classes = out / "oracle-harness"
    oracle_classes.mkdir()
    compile_oracle = invoke(["javac", "-encoding", "UTF-8", "-cp", origcp,
                             "-d", str(oracle_classes), a.matrix_harness])
    if compile_oracle["exit_code"] != 0:
        raise SystemExit("original harness compile failure: " + compile_oracle["stderr"])
    original = invoke(["java", "-cp", str(oracle_classes) + ":" + origcp, CLASS])
    if original["exit_code"] != 0:
        raise SystemExit("original source-known harness failure: " + original["stderr"])
    expected = original["stdout"].strip().splitlines()
    if len(expected) != 10 or any(not v.startswith("case=" + str(i) + "|")
                                   for i, v in enumerate(expected)):
        raise SystemExit("incorrect/unstable original 10-case oracle")
    apk = pathlib.Path(a.apk)
    apk_hash = checksum(apk)
    oracle = {"schema": "aar-method-oracle/v0", "artifact_sha256": apk_hash,
              "questions": {f"case-{i}": {"expected": v, "consequential": True}
                            for i, v in enumerate(expected)}}

    raw = out / "raw"
    raw.mkdir()
    # Match the qualified AAR static-recovery producer exactly: output form is an
    # experimental input, not an interchangeable JADX implementation detail.
    jadx_args = ["--no-res", "--no-imports", "--show-bad-code"]
    decomp = invoke([a.jadx, *jadx_args, "-d", str(raw), a.apk], timeout=180)
    original_package = raw / "sources" / PACKAGE
    original_java = original_package / "GoldenRecordFingerprint.java"
    if not original_java.is_file():
        raise SystemExit("partial/raw JADX must produce source-known target, status=" +
                         str(decomp["exit_code"]))
    raw_text = original_java.read_text(encoding="utf-8")
    experiments = {}
    obs = {}
    for method in ("raw", "dedupe-only", "existing-bounded-repair"):
        root = raw if method == "raw" else out / method
        change = {"kind": "NONE", "source_sha256": checksum(original_java)}
        intervention_error = None
        if method != "raw":
            shutil.copytree(original_package, root / "sources" / PACKAGE)
            dest = root / "sources" / PACKAGE / original_java.name
            try:
                if method == "dedupe-only":
                    patched, rule = dedupe_simple_getters(raw_text)
                    rules = [{"id": rule.rule_id, "count": rule.count}]
                else:
                    patched, repaired = repair(raw_text)
                    rules = [{"id": q.rule_id, "count": q.count} for q in repaired]
                dest.write_text(patched, encoding="utf-8")
                change = {"kind": method, "state": "APPLIED",
                          "input_sha256": checksum(original_java),
                          "output_sha256": checksum(dest), "rules": rules}
            except ValueError as exc:
                intervention_error = str(exc)
                change = {"kind": method, "state": "UNSUPPORTED_PATTERN",
                          "input_sha256": checksum(original_java),
                          "error": intervention_error, "rules": []}
        java_sources = sorted((root / "sources" / PACKAGE).rglob("*.java"))
        classes = root / "classes"
        classes.mkdir()
        compiled = (
            {"exit_code": None, "elapsed_ms": 0, "stdout": "",
             "stderr": "INTERVENTION_UNSUPPORTED: " + intervention_error}
            if intervention_error else
            invoke(["javac", "-encoding", "UTF-8", "-cp", candcp, "-d",
                    str(classes), *map(str, java_sources)])
        )
        execute = {"exit_code": None, "stderr": "NOT_RUN", "stdout": ""}
        harness_compiled = {"exit_code": None, "stderr": "NOT_RUN"}
        if compiled["exit_code"] == 0:
            harness = root / "harness"
            harness.mkdir()
            harness_compiled = invoke(["javac", "-encoding", "UTF-8", "-cp",
                                      str(classes) + ":" + candcp,
                                      "-d", str(harness), a.matrix_harness])
            if harness_compiled["exit_code"] == 0:
                execute = invoke(["java", "-cp",
                                  str(harness) + ":" + str(classes) + ":" + candcp,
                                  CLASS])
        actual = execute["stdout"].strip().splitlines() if execute["exit_code"] == 0 else []
        present = {f"case-{i}": {"state": "OBSERVED", "value": row}
                   for i, row in enumerate(actual[:len(expected)])}
        obs[method] = {"schema": "aar-method-observations/v0",
                       "artifact_sha256": apk_hash,
                       "method_id": "kotlin-" + method,
                       "elapsed_ms": decomp["elapsed_ms"] + compiled["elapsed_ms"],
                       "observations": present}
        experiments[method] = {
            "intervention": change,
            "compile": compiled,
            "harness_compile": harness_compiled,
            "execution": execute,
            "extra_lines": actual[len(expected):],
            "matched_vectors": sum(actual[i] == expected[i] for i in
                                   range(min(len(expected), len(actual)))),
            "observed_vectors": len(actual),
        }
        print(json.dumps({"method": method, "compiled": compiled["exit_code"] == 0,
                          "observed": len(actual),
                          "matched": experiments[method]["matched_vectors"],
                          "compile_error_count": compiled["stderr"].count("error:")},
                         sort_keys=True), flush=True)

    comparisons = {
        k: compare(oracle, obs["raw"], obs[k])
        for k in ("dedupe-only", "existing-bounded-repair")
    }
    doc = {"schema": "aar-kotlin-repair-isolation/v0",
           "artifact_sha256": apk_hash,
           "original_source_known_vectors": expected,
           "original_harness": original, "jadx": decomp, "jadx_flags": jadx_args,
           "methods": experiments, "comparisons": comparisons,
           "interpretation": "Diagnostic intervention, not generalized Kotlin repair. "
                             "Source/oracle values are source-known public goldens; "
                             "no target original-source equivalence claim."}
    (out / "repair-isolation.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
