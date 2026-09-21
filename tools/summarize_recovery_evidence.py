#!/usr/bin/env python3
"""Synthesize bounded AAR recovery evidence without collapsing UNKNOWNs."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: str | None) -> tuple[pathlib.Path | None, dict[str, Any] | None]:
    if not path:
        return None, None
    p = pathlib.Path(path)
    return p, json.loads(p.read_text(encoding="utf-8"))


def evidence_ref(path: pathlib.Path, doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "schema": doc.get("schema"),
    }


def claim(
    claim_id: str,
    kind: str,
    state: str,
    confidence: str,
    scope: str,
    evidence: list[dict[str, Any]],
    detail: str,
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "kind": kind,
        "state": state,
        "confidence": confidence,
        "scope": scope,
        "detail": detail,
        "evidence": evidence,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-sha256", required=True)
    ap.add_argument("--static")
    ap.add_argument("--rebuild")
    ap.add_argument("--behavior")
    ap.add_argument("--environment")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    static_path, static = load(args.static)
    rebuild_path, rebuild = load(args.rebuild)
    behavior_path, behavior = load(args.behavior)
    environment_path, environment = load(args.environment)

    claims: list[dict[str, Any]] = []
    unknowns: list[dict[str, str]] = []
    requirements: list[dict[str, Any]] = []

    claims.append(
        claim(
            "artifact.identity",
            "fact",
            "VERIFIED",
            "high",
            "exact-artifact-bytes",
            [],
            f"Artifact identity is pinned by SHA-256 {args.artifact_sha256}.",
        )
    )

    if static is None:
        unknowns.append({"id": "static-recovery", "reason": "no static recovery evidence supplied"})
    else:
        ref = evidence_ref(static_path, static)
        observed_sha = static.get("artifact", {}).get("sha256")
        if observed_sha and observed_sha != args.artifact_sha256:
            raise SystemExit(
                f"static recovery artifact SHA mismatch: expected={args.artifact_sha256} observed={observed_sha}"
            )

        status = str(static.get("status", "UNKNOWN"))
        claims.append(
            claim(
                "static.representations",
                "recovered",
                status,
                "high" if status in {"PASS", "PARTIAL", "FAIL"} else "unknown",
                "representation-production-only",
                [ref],
                "Static producer status measures whether declared derived representations were emitted; it does not establish semantic correctness.",
            )
        )
        if status == "PARTIAL":
            unknowns.append({
                "id": "static-completeness",
                "reason": "at least one producer returned nonzero while still emitting usable output",
            })
        if status == "FAIL":
            unknowns.append({
                "id": "static-completeness",
                "reason": "at least one required representation had a hard failure",
            })

        tools = static.get("tools", {})
        for tool_name, tool_record in sorted(tools.items()):
            if not isinstance(tool_record, dict):
                continue
            rc = tool_record.get("returncode")
            version_text = tool_record.get("stdout") or tool_record.get("stderr") or ""
            first_line = str(version_text).strip().splitlines()[0] if str(version_text).strip() else None
            requirements.append({
                "id": f"tool:{tool_name}",
                "state": "OBSERVED" if rc == 0 else "UNKNOWN",
                "source": "static-recovery-evidence",
                "detail": first_line,
            })

    if rebuild is None:
        unknowns.append({"id": "rebuildability", "reason": "no rebuild feasibility evidence supplied"})
    else:
        ref = evidence_ref(rebuild_path, rebuild)
        state = str(rebuild.get("status", "UNKNOWN"))
        measured = state in {"REBUILDABLE-AS-EXPORTED", "NOT-REBUILDABLE-AS-EXPORTED"}
        claims.append(
            claim(
                "rebuild.feasibility",
                "fact",
                state,
                "high" if measured else "unknown",
                "exact-export-and-command-only",
                [ref],
                "Rebuildability is a measured property of the recorded recovered project and command; it is not semantic validation.",
            )
        )
        if not measured:
            unknowns.append({"id": "rebuildability", "reason": "rebuild evidence did not contain a terminal recognized verdict"})
        command = rebuild.get("command")
        if isinstance(command, list) and command:
            requirements.append({
                "id": f"command:{command[0]}",
                "state": "OBSERVED",
                "source": "rebuild-evidence",
                "detail": " ".join(str(x) for x in command),
            })

    if behavior is None:
        unknowns.append({"id": "behavioral-equivalence", "reason": "no behavior comparison evidence supplied"})
    else:
        ref = evidence_ref(behavior_path, behavior)
        state = str(behavior.get("status", "UNKNOWN"))
        confidence = "high" if state in {"BEHAVIOR-MATCH", "BEHAVIOR-MISMATCH"} else "unknown"
        claims.append(
            claim(
                "behavior.declared-vector",
                "recovered",
                state,
                confidence,
                "declared-observables-and-test-vector-only",
                [ref],
                "Behavioral comparison is authoritative only for the declared input vector and observables.",
            )
        )
        if state == "UNKNOWN":
            unknowns.append({
                "id": "behavioral-equivalence",
                "reason": str(behavior.get("reason") or "candidate did not produce comparable behavior"),
            })

    if environment is None:
        unknowns.append({"id": "execution-environment", "reason": "no environment spelunk evidence supplied"})
    else:
        ref = evidence_ref(environment_path, environment)
        summary = environment.get("summary", {})
        claims.append(
            claim(
                "environment.observation",
                "fact",
                "OBSERVED",
                "high",
                "single-observed-execution-environment",
                [ref],
                f"Passive environment observation summary: {json.dumps(summary, sort_keys=True)}",
            )
        )
        requirements.append({
            "id": "android-adb-target",
            "state": "OBSERVED",
            "source": "environment-spelunk",
            "detail": "passive ADB-observable Android target",
        })

    # Preserve first occurrence order while removing exact duplicate requirement IDs/details.
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in requirements:
        key = (str(item.get("id")), str(item.get("detail")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    out_doc = {
        "schema": "aar-evidence-summary/v0",
        "artifact": {"sha256": args.artifact_sha256},
        "claims": claims,
        "unknowns": unknowns,
        "execution_requirements": deduped,
        "confidence_semantics": {
            "high": "direct deterministic/observed evidence for the stated narrow scope",
            "unknown": "insufficient evidence for the stated claim",
            "note": "confidence is scope-qualified and is not a probability",
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(out_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "claims": len(claims),
        "unknowns": len(unknowns),
        "execution_requirements": len(deduped),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
