#!/usr/bin/env python3
"""Run bounded Ghidra headless analysis and normalize execution evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-home", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--script-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--max-functions", type=int, default=64)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    ghidra_home = pathlib.Path(args.ghidra_home).resolve()
    binary = pathlib.Path(args.binary).resolve()
    script_dir = pathlib.Path(args.script_dir).resolve()
    out = pathlib.Path(args.out).resolve()
    log = pathlib.Path(args.log).resolve()

    analyze = ghidra_home / "support" / "analyzeHeadless"
    script = script_dir / "ExportFunctionEvidence.java"
    if not analyze.is_file():
        raise SystemExit(f"analyzeHeadless not found: {analyze}")
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    if not script.is_file():
        raise SystemExit(f"Ghidra post-script not found: {script}")
    if args.max_functions < 1 or args.max_functions > 10000:
        raise SystemExit("max-functions must be 1..10000")

    out.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="aar-ghidra-") as td:
        project_root = pathlib.Path(td) / "project"
        project_root.mkdir()
        command = [
            str(analyze),
            str(project_root),
            "AARHeadless",
            "-import",
            str(binary),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script.name,
            str(out),
            str(args.max_functions),
            "-deleteProject",
        ]
        started = time.monotonic()
        try:
            cp = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=args.timeout,
                check=False,
            )
            timed_out = False
            returncode = cp.returncode
            output = cp.stdout
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            returncode = 124
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")

    elapsed_ms = round((time.monotonic() - started) * 1000, 3)
    log.write_text(output, encoding="utf-8")

    if returncode != 0:
        raise SystemExit(f"Ghidra headless returned {returncode}; see {log}")
    if timed_out:
        raise SystemExit(f"Ghidra headless timed out; see {log}")
    if not out.is_file():
        raise SystemExit(f"Ghidra evidence output was not created; see {log}")

    evidence = json.loads(out.read_text(encoding="utf-8"))
    evidence["artifact"] = {
        "sha256": sha256_file(binary),
        "size_bytes": binary.stat().st_size,
    }
    evidence["execution"] = {
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "max_functions": args.max_functions,
    }
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "PASS",
        "artifact_sha256": evidence["artifact"]["sha256"],
        "function_count": evidence["function_count"],
        "emitted_functions": len(evidence["functions"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
