#!/usr/bin/env python3
"""Fingerprint/compare exact offline OCI recovery-tool capabilities.

This contract is not an APK semantic oracle and does not give actor/model admission.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys

CONTRACT = pathlib.Path(__file__).resolve().parents[1] / "parity-contract.json"
SCHEMA = "aar-tool-image-observation/v0"


def sha(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as reader:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def contract(path: pathlib.Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != "aar-tool-parity-contract/v0":
        raise ValueError("unsupported capability contract")
    return doc


def observe(profile: str, cfg: dict) -> dict:
    if sys.platform != cfg["platform"]:
        raise ValueError("this OCI tool profile requires Linux")
    required = cfg["profiles"][profile]["requires"]
    tools: dict = {}
    for key in required:
        spec = cfg["tools"][key]
        if "glob" in spec:
            matches = sorted(glob.glob(spec["glob"], recursive=True))
            if not matches or any(not pathlib.Path(x).is_file() for x in matches):
                raise ValueError(f"{key}: missing or invalid tool library set")
            members = [{"path": x, "sha256": sha(pathlib.Path(x))} for x in matches]
            entry = {
                "path": spec["glob"],
                "files": members,
                "sha256": hashlib.sha256(canonical({"files": members}).encode()).hexdigest(),
            }
            path = None
        else:
            path = pathlib.Path(spec["path"])
            if not path.is_file():
                raise ValueError(f"{key}: missing executable or artifact: {path}")
            entry = {"sha256": sha(path), "path": str(path)}
        if "sha256" in spec and entry["sha256"] != spec["sha256"]:
            raise ValueError(f"{key}: installed artifact digest differs from contract")
        if "argv" in spec:
            try:
                cp = subprocess.run([str(path), *spec["argv"]],
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=30, check=False, text=True)
            except (OSError, subprocess.TimeoutExpired) as e:
                raise ValueError(f"{key}: probe could not execute: {type(e).__name__}") from e
            if cp.returncode != 0:
                raise ValueError(f"{key}: --version failed with {cp.returncode}")
            entry["version"] = (cp.stdout + cp.stderr).strip().splitlines()[:3]
        tools[key] = entry
    facts = {
        "schema": SCHEMA,
        "profile": profile,
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
        "contract_sha256": hashlib.sha256(canonical(cfg).encode()).hexdigest(),
        "tools": tools,
        "claims": {
            "capabilities": "MECHANICAL_TOOL_PRESENCE_AND_BYTE_IDENTITY_ONLY",
            "apk_source_recovery": "UNKNOWN",
            "behavioral_equivalence": "UNKNOWN",
            "sovereign_model_parity": "UNKNOWN",
        },
    }
    facts["fingerprint_sha256"] = hashlib.sha256(canonical(facts).encode()).hexdigest()
    return facts


def compare(expected: dict, actual: dict) -> dict:
    for d in (expected, actual):
        if d.get("schema") != SCHEMA or not isinstance(d.get("tools"), dict):
            raise ValueError("unsupported observation format")
        claimed = d.get("fingerprint_sha256")
        without = {k: v for k, v in d.items() if k != "fingerprint_sha256"}
        if hashlib.sha256(canonical(without).encode()).hexdigest() != claimed:
            raise ValueError("tampered or malformed capability fingerprint")
    dimensions = ("profile", "platform", "architecture", "contract_sha256", "tools", "claims")
    drift = [k for k in dimensions if expected.get(k) != actual.get(k)]
    return {"schema": "aar-tool-image-comparison/v0",
            "state": "PASS_IDENTICAL_OBSERVED_CAPABILITIES" if not drift else "FAIL_CAPABILITY_DRIFT",
            "drift": drift,
            "expected_fingerprint": expected["fingerprint_sha256"],
            "actual_fingerprint": actual["fingerprint_sha256"],
            "limitations": "No source/behavior/model equivalence implied by tool parity"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["probe", "compare"])
    p.add_argument("--profile", choices=["python-core", "java-static"], default="python-core")
    p.add_argument("--contract", type=pathlib.Path, default=CONTRACT)
    p.add_argument("--expected", type=pathlib.Path)
    p.add_argument("--actual", type=pathlib.Path)
    p.add_argument("--output", type=pathlib.Path)
    args = p.parse_args(argv)
    try:
        if args.action == "probe":
            result = observe(args.profile, contract(args.contract))
        else:
            if args.expected is None or args.actual is None:
                raise ValueError("comparison requires --expected and --actual")
            result = compare(json.loads(args.expected.read_text(encoding="utf-8")),
                             json.loads(args.actual.read_text(encoding="utf-8")))
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if result.get("state") != "FAIL_CAPABILITY_DRIFT" else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"state": "BLOCKED", "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
