#!/usr/bin/env python3
"""Source-known D8 debug/release x JADX auto/restructure calibration.

Public synthetic Java only. A candidate signal is NOT a qualified methodology
improvement; compiler mode variants are scored separately by exact DEX identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import statistics
import subprocess
import time

from qualify_method_comparison import compare


CLASS_NAME = "org.sempersupra.aar.golden.methodology.BranchAndFold"


def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def execute(args: list[str], *, timeout: int = 150) -> dict:
    started = time.monotonic()
    cp = subprocess.run(args, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False, timeout=timeout)
    return {
        "exit_code": cp.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "stdout": cp.stdout.decode("utf-8", "replace")[-4000:],
        "stderr": cp.stderr.decode("utf-8", "replace")[-4000:],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("source", "java", "javac", "jar", "d8", "jadx", "out"):
        p.add_argument("--" + name, required=True)
    args = p.parse_args()
    src = pathlib.Path(args.source).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    classes = out / "original-classes"
    classes.mkdir(exist_ok=True)
    built = execute([args.javac, "-g", "-d", str(classes), str(src)])
    if built["exit_code"] != 0:
        raise SystemExit("source-known fixture compilation failed: " + built["stderr"])
    original = execute([args.java, "-cp", str(classes), CLASS_NAME])
    if original["exit_code"] != 0:
        raise SystemExit("source-known oracle failed: " + original["stderr"])
    expected = original["stdout"].strip()
    jar_path = out / "source-known.jar"
    jar_build = execute([args.jar, "--create", "--file", str(jar_path),
                         "-C", str(classes), "."])
    if jar_build["exit_code"] != 0:
        raise SystemExit("jar creation failed: " + jar_build["stderr"])

    report = {
        "schema": "aar-d8-jadx-calibration/v0",
        "source_sha256": digest(src),
        "tool_entrypoints": {
            "d8_sha256": digest(pathlib.Path(args.d8)),
            "jadx_sha256": digest(pathlib.Path(args.jadx)),
        },
        "source_known_output": expected,
        "variants": {},
        "interpretation": "Calibration only. No method superiority or original-source recovery claim.",
    }

    for compiler_mode in ("debug", "release"):
        var = out / compiler_mode
        var.mkdir(exist_ok=True)
        d8_output = execute([args.d8, "--" + compiler_mode, "--min-api", "26",
                             "--output", str(var), str(jar_path)])
        if d8_output["exit_code"] != 0:
            raise SystemExit("D8 " + compiler_mode + " failed: " + d8_output["stderr"])
        dex = var / "classes.dex"
        if not dex.is_file():
            raise SystemExit("D8 produced no classes.dex")
        dex_sha = digest(dex)
        oracle = {
            "schema": "aar-method-oracle/v0", "artifact_sha256": dex_sha,
            "questions": {"behavior": {"expected": expected, "consequential": True}},
        }
        # Alternating ABBA trials guard against a fixed first-run penalty.
        # These short trials are calibration, not qualified cost evidence.
        order = ("auto", "restructure", "restructure", "auto")
        repetitions = {"auto": [], "restructure": []}
        for trial, jadx_mode in enumerate(order):
            target = var / (jadx_mode + "-trial-" + str(trial))
            target.mkdir()
            decompiled = execute([args.jadx, "--decompilation-mode", jadx_mode,
                                  "-d", str(target), str(dex)], timeout=180)
            source_files = sorted((target / "sources").rglob("*.java"))
            observation = {"state": "UNKNOWN"}
            compile_record = {"exit_code": None, "reason": "not attempted"}
            candidate = {"exit_code": None, "reason": "not attempted"}
            if decompiled["exit_code"] == 0 and source_files:
                recompiled = target / "recompiled"
                recompiled.mkdir()
                compile_record = execute([args.javac, "-d", str(recompiled),
                                          *map(str, source_files)], timeout=90)
                if compile_record["exit_code"] == 0:
                    candidate = execute([args.java, "-cp", str(recompiled), CLASS_NAME])
                    if candidate["exit_code"] == 0:
                        observation = {"state": "OBSERVED", "value": candidate["stdout"].strip()}
            repetitions[jadx_mode].append({
                "trial": trial, "decompilation": decompiled,
                "recovered_sources": len(source_files),
                "compile": compile_record,
                "run": candidate, "observation": observation,
            })
        methods = []
        details = {}
        for jadx_mode in ("auto", "restructure"):
            trials = repetitions[jadx_mode]
            values = [t["observation"] for t in trials]
            consistent = len(values) == 2 and all(
                v["state"] == "OBSERVED" and v["value"] == values[0].get("value")
                for v in values
            )
            observed = values[0] if consistent else {"state": "UNKNOWN"}
            elapsed = round(statistics.median(
                t["decompilation"]["elapsed_ms"] for t in trials), 3)
            methods.append({
                "schema": "aar-method-observations/v0",
                "artifact_sha256": dex_sha,
                "method_id": "jadx-" + jadx_mode,
                "elapsed_ms": elapsed,
                "observations": {"behavior": observed},
            })
            details[jadx_mode] = {
                "trials": trials,
                "consistent_observations": consistent,
                "semantic_state": observed["state"],
                "median_elapsed_ms_reported": elapsed,
            }
        comparison = compare(oracle, *methods)
        report["variants"][compiler_mode] = {
            "dex_sha256": dex_sha,
            "d8": d8_output,
            "methods": methods,
            "details": details,
            "comparison": comparison,
        }
        print(json.dumps({
            "compiler_mode": compiler_mode,
            "dex_sha256": dex_sha,
            "auto": comparison["baseline"]["per_question"]["behavior"],
            "restructure": comparison["candidate"]["per_question"]["behavior"],
            "signal": comparison["signal"],
            "qualified_improvement": comparison["qualified_improvement"],
            "median_ms": {
                "auto": comparison["baseline"]["elapsed_ms_reported"],
                "restructure": comparison["candidate"]["elapsed_ms_reported"],
            },
            "crossover_order": list(order),
        }, sort_keys=True))
    (out / "calibration.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
