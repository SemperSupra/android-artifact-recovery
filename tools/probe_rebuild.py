#!/usr/bin/env python3
"""Probe whether a recovered Gradle project can be rebuilt without repair.

The probe records the attempt as evidence. A failed rebuild is a valid measured
result and is not converted into a successful semantic claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import time


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--project", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()

    project = pathlib.Path(args.project).resolve()
    if not project.is_dir():
        raise SystemExit(f"project directory not found: {project}")

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("no rebuild command supplied")

    started = time.monotonic()
    timed_out = False
    try:
        cp = subprocess.run(
            command,
            cwd=project,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
            check=False,
        )
        returncode = cp.returncode
        stdout = cp.stdout.decode("utf-8", "replace")
        stderr = cp.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = (exc.stdout or b"")
        stderr = (exc.stderr or b"")
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")

    elapsed_ms = round((time.monotonic() - started) * 1000, 3)

    apks = []
    for apk in sorted(project.rglob("*.apk")):
        if apk.is_file():
            apks.append(
                {
                    "path": apk.relative_to(project).as_posix(),
                    "size_bytes": apk.stat().st_size,
                    "sha256": sha256_file(apk),
                }
            )

    report = {
        "schema": "aar-rebuild-feasibility/v0",
        "project": str(project),
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "status": "REBUILDABLE-AS-EXPORTED" if returncode == 0 and apks else "NOT-REBUILDABLE-AS-EXPORTED",
        "outputs": {"apks": apks},
        "stdout": stdout,
        "stderr": stderr,
        "repair_applied": False,
    }

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("status", "returncode", "timed_out", "elapsed_ms")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
