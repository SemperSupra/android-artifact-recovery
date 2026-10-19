#!/usr/bin/env python3
"""Source-informed probes of bundled JADX v1.5.6 Kotlin metadata passes.

Official upstream pinned source commit:
28ff15e4ae69950aebea110a13e5ab895d234dfc
KotlinMetadataOptions Git blob:
ab2cb8a1e89357d29a212bd50503e787db735581
KotlinMetadataDecompilePass Git blob:
c9c520625870e12c8ee35a6dc8d059dbbed190ec
No R8 mapping or external plugins provided to JADX.
"""
import argparse
import hashlib
import json
from pathlib import Path
from experiment_r8_behavior_oracle import call

MODES = {
    "baseline": (),
    "getters-off": ("-Pkotlin-metadata.getters=no",),
    "tostring-off": ("-Pkotlin-metadata.to-string=no",),
    "both-off": ("-Pkotlin-metadata.getters=no", "-Pkotlin-metadata.to-string=no"),
}
LABELS = ("shrink-only", "shrink-optimize")
TARGET = Path("org/sempersupra/aar/golden/kotlin")

def run(apks, jadx, stdlib, out):
    if out.exists():
        raise ValueError("output exists: experiments cannot overwrite evidence")
    if set(apks) != set(LABELS) or any(not p.is_file() for p in apks.values()):
        raise ValueError("two existing R8 fixture APKs required")
    if not (jadx.is_file() and stdlib.is_file()):
        raise ValueError("JADX and Kotlin standard library required")
    out.mkdir(parents=True)
    results = {}
    for label in LABELS:
        results[label] = {}
        for mode, options in MODES.items():
            dest = out / label / mode
            dest.mkdir(parents=True)
            d, _ = call([str(jadx), *options, "--no-res", "--no-imports",
                         "--show-bad-code", "-d", str(dest), str(apks[label])])
            files = sorted((dest / "sources" / TARGET).rglob("*.java"))
            hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
            record = {
                "jadx_exit": d["exit_code"], "target_files": len(files),
                "target_file_hashes": hashes, "options": list(options),
                "javac": "NOT_RUN", "behavior": "UNKNOWN",
                "generalization": "UNKNOWN",
            }
            if files:
                classes = dest / "classes"
                classes.mkdir()
                c, _ = call(["javac", "-encoding", "UTF-8", "-cp", str(stdlib),
                             "-d", str(classes), *[str(p) for p in files]])
                record["javac"] = "PASS" if c["exit_code"] == 0 else "FAIL"
                record["categories"] = c.get("javac_diagnostic_categories", {})
                record["compiler_error_lines"] = c.get("compiler_error_lines")
            results[label][mode] = record
            print(json.dumps({"r8":label, "plugin_options":mode, "jadx_exit":record["jadx_exit"],
                              "javac":record["javac"], "diagnostics":record.get("categories", {})},
                             sort_keys=True), flush=True)
    deltas = {
        label: {key: {
            "target_code_changed": result["target_file_hashes"] != results[label]["baseline"]["target_file_hashes"],
            "compiler_categories_changed": result.get("categories", {}) != results[label]["baseline"].get("categories", {}),
        } for key, result in modes.items() if key != "baseline"}
        for label, modes in results.items()
    }
    observation = {
        "schema":"aar-jadx-source-pinned-kotlin-plugin-probe/v0",
        "upstream_source_commit":"28ff15e4ae69950aebea110a13e5ab895d234dfc",
        "R8_mapping_given_to_jadx":False, "third_party_plugins_installed":False,
        "source_equivalence":"UNKNOWN", "behavior":"NOT_TESTED",
        "results":results, "contrasts":deltas, "plugin_adoption":"HOLD",
    }
    (out / "probe.json").write_text(json.dumps(observation, indent=2, sort_keys=True)+"\n")
    return observation

def main():
    p = argparse.ArgumentParser()
    for name in ("shrink_only_apk","shrink_optimize_apk","jadx","kotlin_stdlib","out"):
        p.add_argument("--"+name.replace("_","-"),type=Path,required=True)
    a = p.parse_args()
    run({"shrink-only":a.shrink_only_apk,"shrink-optimize":a.shrink_optimize_apk},
        a.jadx, a.kotlin_stdlib, a.out)
if __name__ == "__main__":
    main()
