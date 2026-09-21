#!/usr/bin/env python3
"""Recover bounded static representations from an APK.

This tool treats the APK bytes as ground truth and writes derived representations
into an output directory. Tool-specific output remains derived evidence, not the
canonical artifact model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
import zipfile

DEX_RE = re.compile(r"^classes(?:\d+)?\.dex$")
SO_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(argv: list[str], stdout_path: pathlib.Path | None = None) -> dict[str, object]:
    started = time.monotonic()
    cp = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)

    if stdout_path is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_bytes(cp.stdout)

    return {
        "argv": argv,
        "returncode": cp.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout": "" if stdout_path else cp.stdout.decode("utf-8", "replace"),
        "stderr": cp.stderr.decode("utf-8", "replace"),
        "stdout_file": str(stdout_path) if stdout_path else None,
    }


def tool_version(path: str, args: list[str]) -> dict[str, object]:
    try:
        return run([path, *args])
    except FileNotFoundError:
        return {
            "argv": [path, *args],
            "returncode": 127,
            "elapsed_ms": 0,
            "stdout": "",
            "stderr": "tool not found",
            "stdout_file": None,
        }


def extract_selected(apk: pathlib.Path, out: pathlib.Path) -> tuple[list[pathlib.Path], list[dict[str, object]]]:
    dex_files: list[pathlib.Path] = []
    native_files: list[dict[str, object]] = []

    with zipfile.ZipFile(apk) as z:
        for info in z.infolist():
            name = info.filename
            base = pathlib.PurePosixPath(name).name
            if DEX_RE.match(base) and "/" not in name.rstrip("/"):
                target = out / "inputs" / "dex" / base
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(info))
                dex_files.append(target)
                continue

            match = SO_RE.match(name)
            if match:
                abi, soname = match.groups()
                target = out / "inputs" / "native" / abi / soname
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(info))
                native_files.append(
                    {
                        "archive_path": name,
                        "abi": abi,
                        "soname": soname,
                        "path": str(target),
                        "sha256": sha256_file(target),
                        "size_bytes": target.stat().st_size,
                    }
                )

    return sorted(dex_files), sorted(native_files, key=lambda x: (str(x["abi"]), str(x["soname"])))


def hash_tree(root: pathlib.Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return records


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("--out", required=True)
    p.add_argument("--jadx", required=True)
    p.add_argument("--dexdump", required=True)
    p.add_argument("--llvm-readelf")
    p.add_argument("--llvm-objdump")
    args = p.parse_args()

    apk = pathlib.Path(args.apk).resolve()
    out = pathlib.Path(args.out).resolve()
    if not apk.is_file():
        raise SystemExit(f"APK not found: {apk}")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    manifest: dict[str, object] = {
        "schema": "aar-static-recovery/v0",
        "artifact": {
            "path": str(apk),
            "size_bytes": apk.stat().st_size,
            "sha256": sha256_file(apk),
        },
        "representations": [],
        "tools": {
            "jadx": tool_version(args.jadx, ["--version"]),
            "dexdump": tool_version(args.dexdump, ["--help"]),
        },
    }

    dex_files, native_files = extract_selected(apk, out)
    manifest["discovery"] = {
        "dex": [
            {
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in dex_files
        ],
        "native": native_files,
    }

    if not dex_files:
        raise SystemExit("No root classes*.dex files found")

    failures: list[str] = []

    for dex in dex_files:
        dest = out / "lowlevel" / "dexdump" / f"{dex.name}.txt"
        result = run([args.dexdump, "-d", str(dex)], dest)
        manifest["representations"].append(
            {
                "kind": "dex-low-level",
                "producer": "dexdump",
                "input": str(dex),
                "output": str(dest),
                "result": result,
            }
        )
        if result["returncode"] != 0:
            failures.append(f"dexdump:{dex.name}")

    jadx_out = out / "highlevel" / "jadx"
    jadx_result = run(
        [
            args.jadx,
            "--no-res",
            "--no-imports",
            "--show-bad-code",
            "-d",
            str(jadx_out),
            str(apk),
        ]
    )
    manifest["representations"].append(
        {
            "kind": "dex-high-level",
            "producer": "jadx",
            "input": str(apk),
            "output": str(jadx_out),
            "result": jadx_result,
        }
    )
    if jadx_result["returncode"] != 0:
        failures.append("jadx")

    if native_files:
        if not args.llvm_readelf or not args.llvm_objdump:
            manifest["native_recovery"] = {
                "status": "UNKNOWN",
                "reason": "native code discovered but LLVM recovery tools were not supplied",
            }
        else:
            manifest["tools"]["llvm-readelf"] = tool_version(args.llvm_readelf, ["--version"])
            manifest["tools"]["llvm-objdump"] = tool_version(args.llvm_objdump, ["--version"])
            native_results: list[dict[str, object]] = []
            for item in native_files:
                native = pathlib.Path(str(item["path"]))
                abi = str(item["abi"])
                stem = native.name
                readelf_out = out / "lowlevel" / "native" / abi / f"{stem}.readelf.txt"
                disasm_out = out / "lowlevel" / "native" / abi / f"{stem}.objdump.txt"
                readelf = run(
                    [args.llvm_readelf, "-h", "-S", "-s", str(native)],
                    readelf_out,
                )
                objdump = run(
                    [args.llvm_objdump, "-d", "--demangle", str(native)],
                    disasm_out,
                )
                native_results.append(
                    {
                        "abi": abi,
                        "input": str(native),
                        "readelf": {"output": str(readelf_out), "result": readelf},
                        "objdump": {"output": str(disasm_out), "result": objdump},
                    }
                )
                if readelf["returncode"] != 0:
                    failures.append(f"readelf:{abi}:{stem}")
                if objdump["returncode"] != 0:
                    failures.append(f"objdump:{abi}:{stem}")
            manifest["native_recovery"] = {
                "status": "PRESENT",
                "representations": native_results,
            }

    manifest["outputs"] = hash_tree(out)
    manifest["failures"] = failures
    manifest["status"] = "PASS" if not failures else "FAIL"

    manifest_path = out / "recovery-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
