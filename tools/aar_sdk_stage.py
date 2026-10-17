#!/usr/bin/env python3
"""Stage a host-installed Android SDK subset for local, non-published OCI build.

Does not download SDK, approve licenses, or grant rights to redistribute SDK.
Only Android build-tools 37.0.0 and Android platform 35 are selected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys

BUILD_TOOLS = "37.0.0"
PLATFORM = "android-35"
ROOT_FILES = {
    "build-tools/37.0.0/aapt2": "0f1c0e560f99db510a76ebc99ad5c3e68438f62e8e8617018a716ca4a589a699",
    "build-tools/37.0.0/dexdump": "860eac6a099ae2b3f0e39a1c7e43272f8bab48440c19a941e3fc87de099d7bd6",
    "build-tools/37.0.0/apksigner": "b47549e373b895ce6ca620d0c7887e674d9615ffa837a86ac601dcfd04adb0f0",
}
REQUIRED = ("build-tools/37.0.0/d8", "platforms/android-35/android.jar")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def stage(sdk: Path, output: Path) -> dict:
    sdk = sdk.expanduser().resolve(strict=True)
    if not sdk.is_dir():
        raise ValueError("SDK root must be a directory")
    arch = platform.machine().lower()
    if sys.platform != "linux" or arch not in ("x86_64", "amd64"):
        raise ValueError("SDK 37.0.0 native toolchain candidate requires Linux amd64")
    output = output.expanduser().absolute()
    if output.exists():
        raise ValueError("staging output already exists: refusing to overwrite evidence")
    if sdk == output or sdk in output.parents or output in sdk.parents:
        raise ValueError("staging location cannot overlap installed SDK")
    components = [f"build-tools/{BUILD_TOOLS}", f"platforms/{PLATFORM}"]
    for rel in components:
        root = sdk / rel
        if not root.is_dir() or root.is_symlink():
            raise ValueError("required SDK component missing or symlink: " + rel)
        # SDK symlink references may leave the source component. Do not silently follow them.
        for current in root.rglob("*"):
            if current.is_symlink():
                raise ValueError("SDK component contains symlink; stage policy requires regular files")
            if not (current.is_dir() or current.is_file()):
                raise ValueError("SDK component contains special file")
    for rel, expected in ROOT_FILES.items():
        p = sdk / rel
        if not p.is_file() or sha(p) != expected:
            raise ValueError("SDK tool hash mismatch or missing: " + rel)
    for rel in REQUIRED:
        if not (sdk / rel).is_file():
            raise ValueError("required SDK input absent: " + rel)
    try:
        for rel in components:
            dest = output / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(sdk / rel, dest, symlinks=False)
        metadata = {
            "schema": "aar-sdk-staging/v0",
            "source_kind": "preinstalled_sdk",
            "target": "linux/amd64",
            "android_build_tools": BUILD_TOOLS,
            "android_platform": PLATFORM,
            "tool_sha256": {k: sha(output / k) for k in ROOT_FILES},
            "android_jar_sha256": sha(output / "platforms/android-35/android.jar"),
            "d8_sha256": sha(output / "build-tools/37.0.0/d8"),
            "registry_publication_authorized": False,
            "license_reuse_or_redistribution": "UNREVIEWED",
            "claims": "PREINSTALLED_BYTES_STAGED_ONLY",
        }
        (output / "sdk-provenance.json").write_text(json.dumps(metadata, indent=2, sort_keys=True)+"\n")
        return metadata
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        print(json.dumps(stage(a.sdk_root, a.output), indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError) as err:
        print(json.dumps({"state": "BLOCKED", "reason": str(err)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
