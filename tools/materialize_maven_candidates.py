#!/usr/bin/env python3
"""Materialize only explicitly requested Maven JAR/AAR candidates.

This is a candidate-acquisition primitive, not a dependency resolver, crawler,
or component/version truth source. Callers must supply exact coordinates and
repository bases. Transitive dependencies are never followed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import urllib.parse
import urllib.request
from typing import Any, Callable

ALLOWED_PACKAGING = {"jar", "aar"}
EXACT_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class RequestError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_request(doc: dict[str, Any]) -> dict[str, Any]:
    if doc.get("schema") != "aar-maven-candidate-request/v0":
        raise RequestError("unsupported request schema")
    candidates = doc.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise RequestError("candidates must be a non-empty list")

    seen: set[str] = set()
    for c in candidates:
        if not isinstance(c, dict):
            raise RequestError("candidate must be an object")
        cid = c.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise RequestError(f"invalid/duplicate candidate id: {cid!r}")
        seen.add(cid)
        for field in ("repository", "group_id", "artifact_id", "version"):
            if not isinstance(c.get(field), str) or not c[field]:
                raise RequestError(f"{cid}: missing {field}")
        if not c["repository"].startswith("https://"):
            raise RequestError(f"{cid}: repository must use https")
        version = c["version"]
        if not EXACT_VERSION_RE.fullmatch(version) or version.upper() in {"LATEST", "RELEASE"} or "+" in version:
            raise RequestError(f"{cid}: version must be explicit, not dynamic")
        packaging = c.get("packaging", "jar")
        if packaging not in ALLOWED_PACKAGING:
            raise RequestError(f"{cid}: unsupported packaging {packaging!r}")
        expected = c.get("expected_sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise RequestError(f"{cid}: expected_sha256 must be lowercase SHA-256")
    return doc


def artifact_url(candidate: dict[str, Any]) -> str:
    repo = candidate["repository"].rstrip("/") + "/"
    group_path = candidate["group_id"].replace(".", "/")
    artifact = candidate["artifact_id"]
    version = candidate["version"]
    packaging = candidate.get("packaging", "jar")
    classifier = candidate.get("classifier")
    stem = f"{artifact}-{version}"
    if classifier:
        stem += f"-{classifier}"
    filename = f"{stem}.{packaging}"
    rel = f"{group_path}/{artifact}/{version}/{filename}"
    return urllib.parse.urljoin(repo, rel)


def read_bounded(response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise RequestError("artifact exceeds max_bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def materialize(
    doc: dict[str, Any],
    out_dir: pathlib.Path,
    *,
    max_bytes: int,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    validate_request(doc)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for c in doc["candidates"]:
        url = artifact_url(c)
        with opener(url, timeout=60) as response:
            data = read_bounded(response, max_bytes)
        digest = sha256_bytes(data)
        expected = c.get("expected_sha256")
        if expected is not None and digest != expected:
            raise RequestError(f"{c['id']}: SHA-256 mismatch")

        suffix = c.get("packaging", "jar")
        path = out_dir / f"{c['id']}.{suffix}"
        path.write_bytes(data)
        results.append({
            "id": c["id"],
            "group_id": c["group_id"],
            "artifact_id": c["artifact_id"],
            "version": c["version"],
            "packaging": suffix,
            "classifier": c.get("classifier"),
            "url": url,
            "sha256": digest,
            "bytes": len(data),
            "digest_status": "verified_expected" if expected else "observed_unpinned",
            "path": str(path),
        })

    return {
        "schema": "aar-maven-candidate-materialization/v0",
        "policy": {
            "explicit_candidates_only": True,
            "transitive_resolution": False,
            "version_identity_claims": False,
            "component_identity_claims": False,
            "unpinned_digest_is_reference_truth": False,
        },
        "candidates": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--request", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--max-bytes", type=int, default=128 * 1024 * 1024)
    args = ap.parse_args()

    request = json.loads(pathlib.Path(args.request).read_text(encoding="utf-8"))
    manifest = materialize(request, pathlib.Path(args.out_dir), max_bytes=args.max_bytes)
    out = pathlib.Path(args.manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"candidates": len(manifest["candidates"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
