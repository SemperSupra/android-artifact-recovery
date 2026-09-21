#!/usr/bin/env python3
"""Passive Android environment spelunker.

Runs a bounded allowlist of read-only ADB observations and emits structured JSON.
It does not install packages, change settings, start activities, or mutate the guest.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Sequence

SCHEMA = "aar-environment-spelunk/v0"


@dataclass(frozen=True)
class Probe:
    id: str
    argv: tuple[str, ...]
    family: str
    level: int = 2


PROBES: tuple[Probe, ...] = (
    Probe("device.state", ("get-state",), "device"),
    Probe("device.serial", ("get-serialno",), "device"),
    Probe("build.properties", ("shell", "getprop"), "framework"),
    Probe("kernel.uname", ("shell", "uname", "-a"), "kernel"),
    Probe("identity.id", ("shell", "id"), "kernel"),
    Probe("cpu.info", ("shell", "cat", "/proc/cpuinfo"), "hardware"),
    Probe("memory.info", ("shell", "cat", "/proc/meminfo"), "hardware"),
    Probe("mounts", ("shell", "cat", "/proc/mounts"), "storage"),
    Probe("features", ("shell", "pm", "list", "features"), "framework"),
    Probe("runtime.process", ("shell", "getprop", "dalvik.vm.isa.arm64.variant"), "runtime"),
    Probe("security.selinux", ("shell", "getenforce"), "security"),
    Probe("cgroups", ("shell", "cat", "/proc/self/cgroup"), "kernel"),
)


def run(argv: Sequence[str], timeout: float) -> tuple[int, str, str, float]:
    start = time.monotonic()
    try:
        cp = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        elapsed_ms = round((time.monotonic() - start) * 1000, 3)
        return cp.returncode, cp.stdout, cp.stderr, elapsed_ms
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = round((time.monotonic() - start) * 1000, 3)
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, out, err + "\nTIMEOUT", elapsed_ms


def classify(returncode: int, stdout: str, stderr: str) -> tuple[str, int]:
    text = (stdout + "\n" + stderr).lower()
    if returncode == 0:
        return ("PRESENT", 2 if stdout.strip() else 1)
    if returncode == 124:
        return ("INACCESSIBLE", 1)
    if "permission denied" in text or "not permitted" in text:
        return ("INACCESSIBLE", 1)
    if "not found" in text or "unknown command" in text or "no such file" in text:
        return ("ABSENT", 0)
    if "offline" in text or "no devices" in text or "device not found" in text:
        return ("INACCESSIBLE", 0)
    return ("UNKNOWN", 0)


def clean_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    p.add_argument("--serial", default="")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--output", default="-")
    args = p.parse_args()

    adb = shutil.which(args.adb) if not pathlib.Path(args.adb).is_file() else args.adb
    if not adb:
        print(f"ADB executable not found: {args.adb}", file=sys.stderr)
        return 2

    prefix = [str(adb)]
    if args.serial:
        prefix += ["-s", args.serial]

    adb_rc, adb_out, adb_err, adb_ms = run([str(adb), "version"], args.timeout)
    if adb_rc != 0:
        print(f"adb version failed: {clean_text(adb_err)}", file=sys.stderr)
        return 3

    observations: list[dict[str, object]] = []
    for probe in PROBES:
        rc, out, err, elapsed_ms = run(prefix + list(probe.argv), args.timeout)
        classification, capability_level = classify(rc, out, err)
        observations.append(
            {
                "id": probe.id,
                "family": probe.family,
                "classification": classification,
                "capability_level": capability_level,
                "returncode": rc,
                "elapsed_ms": elapsed_ms,
                "argv": list(probe.argv),
                "stdout": clean_text(out),
                "stderr": clean_text(err),
            }
        )

    result = {
        "schema": SCHEMA,
        "mode": "passive",
        "mutation_authorized": False,
        "adb": {
            "version_returncode": adb_rc,
            "version": clean_text(adb_out),
            "stderr": clean_text(adb_err),
            "elapsed_ms": adb_ms,
        },
        "target": {"serial": args.serial or None},
        "observations": observations,
        "summary": {
            key: sum(1 for item in observations if item["classification"] == key)
            for key in ("PRESENT", "ABSENT", "UNEXPECTED", "INACCESSIBLE", "UNKNOWN")
        },
    }

    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(encoded)
    else:
        path = pathlib.Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
