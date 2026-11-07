#!/usr/bin/env python3
"""Static, bounded, per-DEX JADX rep: source-owned tool orchestration only.

Runs pinned JADX on isolated DEX bytecode, never executes recovered app code.
The original APK/DEX and JADX .java outputs remain only on an ephemeral runner.
Public receipt contains allowlisted counts, verdicts, digests, no raw logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import zipfile

from tools.qualify_android_abi import qualify_native_abi  # import-only contract parity
from tools.qualify_dex_header_inventory import census, MAX_DEX_BYTES
from tools.qualify_jadx_log import qualify_jadx_log

MAX_SECONDS_PER_DEX = 120
JAVA_HEAP = "4g"


def _extract_bounded(zf: zipfile.ZipFile, name: str, target: Path) -> str:
    size = zf.getinfo(name).file_size
    if size < 112 or size > MAX_DEX_BYTES:
        raise ValueError("root DEX source size outside approved envelope")
    digest = hashlib.sha256()
    written = 0
    with zf.open(name) as src, target.open("wb") as dst:
        while True:
            data = src.read(1024 * 1024)
            if not data:
                break
            written += len(data)
            if written > MAX_DEX_BYTES:
                raise ValueError("inflated DEX exceeds approved envelope")
            digest.update(data)
            dst.write(data)
    if written != size:
        raise ValueError("DEX actual size inconsistent with archive header")
    return digest.hexdigest()


def _run_one(jadx: Path, dex: Path, output: Path, logfile: Path,
             seconds: int) -> tuple[int, str, bool]:
    env = dict(os.environ)
    env["JAVA_OPTS"] = "-Xmx" + JAVA_HEAP + " -XX:+UseG1GC"
    output.mkdir(parents=True, exist_ok=True)
    with logfile.open("wb") as stream:
        try:
            proc = subprocess.Popen(
                [str(jadx), "--threads-count", "1", "--no-res", "--no-imports",
                 "--show-bad-code", "-d", str(output), str(dex)],
                stdout=stream, stderr=subprocess.STDOUT, env=env,
                start_new_session=True,
            )
        except OSError:
            return 127, "TOOL_LAUNCH_FAILED", False
        try:
            rc = proc.wait(timeout=seconds)
            verdict = "EXITED"
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            rc, verdict = 124, "TIMEOUT_KILLED"
    # The raw log is ephemeral. Any class names, code, paths, URLs or
    # decompiler errors are never copied into public derived receipts.
    with logfile.open("rb") as f:
        logbytes = f.read(1_000_001)
    truncated = len(logbytes) > 1_000_000
    text = logbytes[:1_000_000].decode("utf-8", "replace")
    return rc, verdict, truncated, text


def run(apk: Path, jadx: Path, out_root: Path, receipt: Path,
        seconds: int = MAX_SECONDS_PER_DEX) -> dict:
    if not (1 <= seconds <= 300):
        raise ValueError("invalid timeout")
    if not jadx.is_file():
        raise ValueError("pinned JADX tool file not present")
    descriptor = census(apk)  # header bounds, contiguity and counts
    out_root.mkdir(parents=True, exist_ok=True)
    results = []
    observed_relative_paths: set[str] = set()
    overlap_count = 0
    with tempfile.TemporaryDirectory(prefix="aar-dex-shards-") as tmp:
        temp = Path(tmp)
        with zipfile.ZipFile(apk) as zf:
            for i, info in enumerate(descriptor["dex_headers"], 1):
                name = info["root_dex_name"]
                source = temp / name
                dex_sha = _extract_bounded(zf, name, source)
                target = out_root / ("shard-" + str(i).zfill(2))
                log = temp / ("jadx-" + str(i) + ".log")
                rc, process_status, truncated, logtext = _run_one(
                    jadx, source, target, log, seconds)
                # Keep caller-observed output independent of JADX progress %
                quality = qualify_jadx_log(logtext + "\njadx_returncode=" + str(rc) + "\n")
                java = sorted((target / "sources").rglob("*.java")) if (target / "sources").is_dir() else []
                for path in java:
                    relative = path.relative_to(target / "sources").as_posix()
                    if relative in observed_relative_paths:
                        overlap_count += 1
                    observed_relative_paths.add(relative)
                results.append({
                    "root_dex_name":name,
                    "dex_sha256":dex_sha,
                    "class_defs_header_count":info["class_defs"],
                    "method_ids_header_count":info["method_ids"],
                    "java_files_observed":len(java),
                    "exit_code":rc,
                    "process_status":process_status,
                    "jadx_status":quality["status"],
                    "reported_error_count":quality["reported_error_count"],
                    "heap_out_of_memory_observed":("OutOfMemoryError" in logtext),
                    "raw_log_truncated":truncated,
                })
                log.unlink(missing_ok=True)
                source.unlink(missing_ok=True)
    fail_count = sum(r["exit_code"] != 0 for r in results)
    result = {
        "schema":"aar-jadx-sharded-static-diagnostic/v1",
        "status":("JADX_SHARDED_EXIT_ZERO_COVERAGE_UNVERIFIED"
                  if fail_count == 0 else "JADX_SHARDED_PARTIAL_EVIDENCE"),
        "original_donor_executed":False,
        "root_dex_count":len(results),
        "total_dex_class_defs":descriptor["aggregate"]["class_defs"],
        "total_dex_method_ids":descriptor["aggregate"]["method_ids"],
        "total_java_files_observed":sum(r["java_files_observed"] for r in results),
        "java_relative_path_overlap_count":overlap_count,
        "failed_shard_count":fail_count,
        "heap_oom_shards":sum(r["heap_out_of_memory_observed"] for r in results),
        "timed_out_shards":sum(r["process_status"]=="TIMEOUT_KILLED" for r in results),
        "max_heap":JAVA_HEAP,
        "timeout_per_shard_seconds":seconds,
        "shards":results,
        "coverage_verified":False,
        "claim_boundary":"Isolated JADX tool invocation against bytecode; DEX class cardinality and Java source-file count are not equivalent. No original app code executed; all output Java/logs remain ephemeral.",
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return result


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",required=True,type=Path)
    p.add_argument("--jadx",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--receipt",required=True,type=Path)
    p.add_argument("--seconds",type=int,default=MAX_SECONDS_PER_DEX)
    a=p.parse_args()
    r=run(a.apk,a.jadx,a.output,a.receipt,a.seconds)
    print(json.dumps({"schema":r["schema"],"status":r["status"],
                      "root_dex_count":r["root_dex_count"],
                      "total_java_files_observed":r["total_java_files_observed"],
                      "failed_shard_count":r["failed_shard_count"],
                      "heap_oom_shards":r["heap_oom_shards"]},sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
