#!/usr/bin/env python3
"""Public source-known Kotlin/JADX option interview, not a recovery promotion.

AAR's original Kotlin behavior is the executable oracle. Every raw output is
compiled and exercised unmodified. Failed compiles remain UNKNOWN rather than
being patched, reclassified as behavior matches, or removed from the report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import time

from qualify_method_comparison import compare

TARGET = "org/sempersupra/aar/golden/kotlin"
CASES = {
    "auto": [],
    "no-inline-methods": ["--no-inline-methods"],
    "no-inline-kotlin-lambda": ["--no-inline-kotlin-lambda"],
    "no-replace-consts": ["--no-replace-consts"],
    "simple": ["--decompilation-mode", "simple"],
    "fallback": ["--decompilation-mode", "fallback"],
}


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def execute(argv: list[str], timeout: int = 90) -> dict:
    began = time.monotonic()
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, check=False, timeout=timeout)
        return {
            "returncode": p.returncode,
            "elapsed_ms": round((time.monotonic() - began) * 1000, 3),
            "stdout": p.stdout.decode("utf-8", "replace")[-8000:],
            "stderr": p.stderr.decode("utf-8", "replace")[-8000:],
        }
    except subprocess.TimeoutExpired:
        return {"returncode": None, "elapsed_ms": timeout * 1000,
                "stdout": "", "stderr": "TIMEOUT"}


def main() -> int:
    parser = argparse.ArgumentParser()
    for arg in ("apk", "original_classes", "kotlin_stdlib", "harness", "jadx", "out"):
        parser.add_argument("--" + arg.replace("_", "-"), required=True)
    parser.add_argument("--annotations", default="")
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    apk = pathlib.Path(args.apk)
    original_classpath = str(pathlib.Path(args.original_classes)) + ":" + args.kotlin_stdlib
    recovery_classpath = args.kotlin_stdlib
    if args.annotations:
        original_classpath += ":" + args.annotations
        recovery_classpath += ":" + args.annotations

    original_harness = out / "original-harness"
    original_harness.mkdir(exist_ok=True)
    built = execute(["javac", "-cp", original_classpath, "-d",
                     str(original_harness), args.harness])
    if built["returncode"] != 0:
        raise SystemExit("source-known harness compile failed: " + built["stderr"])
    original = execute(["java", "-cp", str(original_harness) + ":" +
                        original_classpath, "GoldenFingerprintHarness"])
    if original["returncode"] != 0:
        raise SystemExit("source-known oracle failed: " + original["stderr"])
    expected = original["stdout"].strip()
    apk_hash = sha256(apk)
    oracle = {"schema": "aar-method-oracle/v0", "artifact_sha256": apk_hash,
              "questions": {"declared-vector":
                            {"expected": expected, "consequential": True}}}

    results = {}
    observations = {}
    for method, opts in CASES.items():
        base = out / method
        sources = base / "sources"
        base.mkdir(exist_ok=True)
        recovery = execute([args.jadx, *opts, "-d", str(base), str(apk)], timeout=140)
        generated = sorted((sources / TARGET).rglob("*.java"))
        compiler = {"returncode": None, "stderr": "SKIPPED"}
        observed = {"returncode": None, "stderr": "SKIPPED"}
        value = {"state": "UNKNOWN"}
        if generated:
            classes = base / "classes"
            classes.mkdir(exist_ok=True)
            compiler = execute(["javac", "-cp", recovery_classpath, "-d", str(classes),
                                *map(str, generated)], timeout=60)
            if compiler["returncode"] == 0:
                harness_classes = base / "harness"
                harness_classes.mkdir(exist_ok=True)
                harness_compiler = execute(["javac", "-cp", str(classes) + ":" +
                                            recovery_classpath, "-d", str(harness_classes),
                                            args.harness])
                if harness_compiler["returncode"] == 0:
                    observed = execute(["java", "-cp", str(harness_classes) + ":" +
                                        str(classes) + ":" + recovery_classpath,
                                        "GoldenFingerprintHarness"])
                    if observed["returncode"] == 0:
                        value = {"state": "OBSERVED", "value": observed["stdout"].strip()}
                else:
                    observed = {"returncode": None,
                                "stderr": "harness compile failed: " +
                                harness_compiler["stderr"]}
        observations[method] = {"schema": "aar-method-observations/v0",
                                "artifact_sha256": apk_hash,
                                "method_id": "jadx-" + method,
                                "elapsed_ms": recovery["elapsed_ms"],
                                "observations": {"declared-vector": value}}
        results[method] = {
            "options": opts, "recovery": recovery, "source_count": len(generated),
            "compile": compiler, "execute": observed,
            "observation": value, "matched": value.get("value") == expected
            if value["state"] == "OBSERVED" else None,
        }
        print(json.dumps({"mode": method, "jadx_returncode": recovery["returncode"],
                          "java_files": len(generated),
                          "javac_returncode": compiler["returncode"],
                          "semantic": "MATCH" if results[method]["matched"] else
                                      "MISMATCH" if results[method]["matched"] is False else
                                      "UNKNOWN"}, sort_keys=True), flush=True)

    comparison = {}
    for method in CASES:
        if method != "auto":
            comparison[method] = compare(oracle, observations["auto"],
                                         observations[method])
    output = {"schema": "aar-kotlin-jadx-variant-interview/v0",
              "artifact_sha256": apk_hash,
              "source_known_expected": expected, "original_execution": original,
              "original_harness_build": built, "tools": {
                  "jadx_launcher_sha256": sha256(pathlib.Path(args.jadx)),
                  "kotlin_stdlib_sha256": sha256(pathlib.Path(args.kotlin_stdlib)),
              },
              "cases": results, "compared_to_auto": comparison,
              "interpretation": "Only one declared behavioral vector tested. "
                                "Raw recovery is never automatically repaired. "
                                "Qualified improvement requires held-out validation."}
    (out / "interview.json").write_text(json.dumps(output, sort_keys=True, indent=2) + "\n",
                                         encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
