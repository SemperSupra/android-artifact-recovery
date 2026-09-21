#!/usr/bin/env python3
"""Classify native DT_NEEDED edges without pretending platform identity is exact."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

# Deliberately conservative subset of Android/NDK libraries that are stable
# enough to classify as platform semantic boundaries. This is not an exhaustive
# Android native-library catalog.
ANDROID_PLATFORM_LIBS = {
    "libc.so": {
        "reference": "android-ndk:libc",
        "source_ref": "https://android.googlesource.com/platform/bionic/",
    },
    "libdl.so": {
        "reference": "android-ndk:libdl",
        "source_ref": "https://android.googlesource.com/platform/bionic/",
    },
    "libm.so": {
        "reference": "android-ndk:libm",
        "source_ref": "https://android.googlesource.com/platform/bionic/",
    },
    "liblog.so": {
        "reference": "android-ndk:liblog",
        "source_ref": "https://android.googlesource.com/platform/system/logging/",
    },
    "libandroid.so": {
        "reference": "android-ndk:libandroid",
        "source_ref": "https://android.googlesource.com/platform/frameworks/base/",
    },
    "libz.so": {
        "reference": "android-ndk:libz",
        "source_ref": "https://android.googlesource.com/platform/external/zlib/",
    },
}

RUNTIME_CANDIDATES = {
    "libc++_shared.so": {
        "reference": "android-ndk:libc++_shared",
        "source_ref": "https://android.googlesource.com/toolchain/llvm-project/libcxx/",
    },
}


def load(path: str) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--observations", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    doc = load(args.observations)
    if doc.get("schema") != "aar-component-observations/v0":
        raise SystemExit("unsupported component observations schema")

    bundled_sonames: dict[str, list[str]] = {}
    for obj in doc.get("objects", []):
        if obj.get("kind") != "elf":
            continue
        for soname in obj.get("metadata", {}).get("sonames", []) or []:
            bundled_sonames.setdefault(str(soname), []).append(str(obj.get("object_id")))

    edges = []
    summary = {
        "android_platform_boundary": 0,
        "bundled_dependency": 0,
        "ndk_runtime_candidate": 0,
        "unresolved_external": 0,
    }

    for obj in doc.get("objects", []):
        if obj.get("kind") != "elf":
            continue
        object_id = str(obj.get("object_id"))
        needed = obj.get("metadata", {}).get("needed", []) or []
        for dep in sorted({str(x) for x in needed}):
            if dep in bundled_sonames:
                state = "BUNDLED_DEPENDENCY"
                detail = {
                    "bundled_object_ids": sorted(bundled_sonames[dep]),
                }
                summary["bundled_dependency"] += 1
            elif dep in ANDROID_PLATFORM_LIBS:
                state = "ANDROID_PLATFORM_BOUNDARY"
                detail = ANDROID_PLATFORM_LIBS[dep]
                summary["android_platform_boundary"] += 1
            elif dep in RUNTIME_CANDIDATES:
                state = "NDK_RUNTIME_CANDIDATE"
                detail = RUNTIME_CANDIDATES[dep]
                summary["ndk_runtime_candidate"] += 1
            else:
                state = "UNRESOLVED_EXTERNAL"
                detail = {}
                summary["unresolved_external"] += 1

            edges.append({
                "from_object_id": object_id,
                "needed": dep,
                "state": state,
                **detail,
            })

    out_doc = {
        "schema": "aar-android-native-boundaries/v0",
        "artifact": doc.get("artifact", {}),
        "edges": edges,
        "summary": summary,
        "policy": {
            "platform_boundary_is_semantic_reference_not_exact_runtime_bytes": True,
            "bundled_dependency_requires_component_correspondence": True,
            "ndk_runtime_candidate_requires_artifact_evidence": True,
            "unresolved_external_remains_unknown": True,
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(out_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
