#!/usr/bin/env python3
"""Public-safe NDK native reference inventory; metadata-only, no library upload.

Only authorizes exact Android NDK installation roots. Never runs arbitrary NDK
executables other than local llvm-ar (list mode) and llvm-nm (definition census).
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

TRIPLE = "aarch64-linux-android"
MAX_ARCHIVE_BYTES = 150_000_000

def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()

def candidates() -> list[Path]:
    result = []
    for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        if os.environ.get(name):
            result.append(Path(os.environ[name]))
    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(name):
            result.extend(sorted((Path(os.environ[name]) / "ndk").glob("*"), reverse=True))
    result.extend(sorted(Path("/usr/local/lib/android/sdk/ndk").glob("*"), reverse=True))
    return list(dict.fromkeys(result))

def inventory(root: Path) -> dict:
    root = root.resolve()
    prop = root / "source.properties"
    if not prop.is_file():
        raise ValueError("missing NDK source.properties")
    text = prop.read_text(encoding="utf-8")
    version = re.search(r"(?m)^Pkg\.Revision\s*=\s*([0-9.]+)\s*$", text)
    if not version:
        raise ValueError("missing exact NDK revision")
    prebuilts = list((root / "toolchains" / "llvm" / "prebuilt").glob("*/bin/llvm-ar"))
    if len(prebuilts) != 1:
        raise ValueError(f"expected exactly one NDK llvm-ar, got {len(prebuilts)}")
    ar = prebuilts[0]
    toolchain = ar.parent.parent
    libdir = toolchain / "sysroot" / "usr" / "lib" / TRIPLE
    clang_dir = toolchain / "lib" / "clang"
    patterns = [
        ("libc++_static.a", libdir / "libc++_static.a"),
        ("libunwind.a", libdir / "libunwind.a"),
        ("compiler-rt-builtins", clang_dir / "*" / "lib" / "linux" / "libclang_rt.builtins-aarch64-android.a"),
    ]
    archives = []
    for label, path in patterns:
        possibilities = list(clang_dir.glob("*/lib/linux/libclang_rt.builtins-aarch64-android.a")) if label == "compiler-rt-builtins" else [path]
        exact = [x for x in possibilities if x.is_file()]
        if len(exact) == 0:
            archives.append({"category": label, "status": "NOT_PRESENT"})
            continue
        if len(exact) != 1:
            raise ValueError("ambiguous NDK archive " + label)
        p = exact[0]
        if p.stat().st_size <= 0 or p.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("archive bounds exceeded")
        run = subprocess.run([str(ar), "t", str(p)], capture_output=True, text=True, timeout=45, check=True)
        names = [n for n in run.stdout.splitlines() if n.strip()]
        if not names:
            raise ValueError("NDK archive has zero members")
        archives.append({"category":label, "status":"MEMBERS_FOUND", "members":len(names),
                         "bytes":p.stat().st_size, "sha256":sha(p),
                         "path_relative_to_ndk":p.relative_to(root).as_posix()})
    return {"schema_version":1, "status":"NDK_INSTALLATION_INVENTORIED",
            "ndk_revision":version.group(1), "host_tag":toolchain.name,
            "abi":"arm64-v8a", "triple":TRIPLE, "archives":archives,
            "qualification":"INVENTORY_ONLY_NOT_FID_OR_JNI_MATCH",
            "binary_artifacts_uploaded":False}

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--ndk-root", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    locations = [args.ndk_root] if args.ndk_root else candidates()
    valid = [x for x in locations if x is not None and (x / "source.properties").is_file()]
    if not valid:
        print("NDK_ENVIRONMENT_UNAVAILABLE: no installed NDK root",file=sys.stderr)
        return 77
    try:
        result = inventory(valid[0])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print("NDK_INVENTORY_FAIL:" + str(exc),file=sys.stderr)
        return 1
    message = json.dumps(result,sort_keys=True)
    print(message)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
