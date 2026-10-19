#!/usr/bin/env python3
"""Compare sealed recovery observations against an independent source-known oracle.

This is an evidence comparator, not a decompiler, scheduler, or source-equivalence
oracle. Method evidence must be sealed before evaluation for blind experiments.
Candidate promotion requires separate independent reproduction and review.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

ORACLE_SCHEMA = "aar-method-oracle/v0"
RUN_SCHEMA = "aar-method-observations/v0"
RESULT_SCHEMA = "aar-method-comparison/v0"


def _load(path: str) -> dict[str, Any]:
    doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("expected top-level JSON object")
    return doc


def _hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_oracle(doc: dict[str, Any]) -> None:
    if doc.get("schema") != ORACLE_SCHEMA or not _hash(doc.get("artifact_sha256")):
        raise ValueError("invalid oracle schema or artifact SHA-256")
    questions = doc.get("questions")
    if not isinstance(questions, dict) or not questions:
        raise ValueError("oracle requires nonempty questions")
    for key, item in questions.items():
        if not isinstance(key, str) or not key or not isinstance(item, dict):
            raise ValueError("invalid question")
        if "expected" not in item or type(item.get("consequential")) is not bool:
            raise ValueError("question requires expected and consequential boolean")


def _validate_run(doc: dict[str, Any], oracle: dict[str, Any]) -> None:
    if doc.get("schema") != RUN_SCHEMA or doc.get("artifact_sha256") != oracle["artifact_sha256"]:
        raise ValueError("run schema or artifact identity does not match oracle")
    if not isinstance(doc.get("method_id"), str) or not doc["method_id"].strip():
        raise ValueError("method_id required")
    time = doc.get("elapsed_ms")
    if type(time) not in (int, float) or not (0 <= time < 1e12):
        raise ValueError("invalid measured elapsed_ms")
    observations = doc.get("observations")
    if not isinstance(observations, dict):
        raise ValueError("observations must be a JSON object")
    if set(observations) - set(oracle["questions"]):
        raise ValueError("run includes undeclared question")
    for q, obj in observations.items():
        if not isinstance(obj, dict) or obj.get("state") not in ("OBSERVED", "UNKNOWN"):
            raise ValueError("observation needs OBSERVED or UNKNOWN")
        if obj["state"] == "OBSERVED" and "value" not in obj:
            raise ValueError("OBSERVED requires value")
        if obj["state"] == "UNKNOWN" and "value" in obj:
            raise ValueError("UNKNOWN may not smuggle a guess")


def _evaluate(oracle: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    states: dict[str, str] = {}
    for key, q in sorted(oracle["questions"].items()):
        observation = run["observations"].get(key, {"state": "UNKNOWN"})
        if observation["state"] == "UNKNOWN":
            states[key] = "UNKNOWN"
        elif observation["value"] == q["expected"]:
            states[key] = "MATCH"
        else:
            states[key] = "MISMATCH"
    consequential = [key for key, q in oracle["questions"].items() if q["consequential"]]
    return {
        "method_id": run["method_id"],
        "elapsed_ms_reported": run["elapsed_ms"],
        "per_question": states,
        "consequential_match": sum(states[k] == "MATCH" for k in consequential),
        "consequential_mismatch": sum(states[k] == "MISMATCH" for k in consequential),
        "consequential_unknown": sum(states[k] == "UNKNOWN" for k in consequential),
        "all_mismatch": sum(s == "MISMATCH" for s in states.values()),
    }


def compare(oracle: dict[str, Any], baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    _validate_oracle(oracle)
    _validate_run(baseline, oracle)
    _validate_run(candidate, oracle)
    if baseline["method_id"] == candidate["method_id"]:
        raise ValueError("two distinct method_id values required")
    a, b = _evaluate(oracle, baseline), _evaluate(oracle, candidate)
    signal = "NO_PROMOTION_EVIDENCE"
    if b["all_mismatch"] == 0 and b["consequential_mismatch"] == 0:
        if b["consequential_match"] > a["consequential_match"]:
            signal = "CANDIDATE_QUALITY_SIGNAL"
        elif (b["per_question"] == a["per_question"]
              and b["consequential_match"] > 0
              and b["elapsed_ms_reported"] < a["elapsed_ms_reported"]):
            signal = "CANDIDATE_COST_SIGNAL"
    return {
        "schema": RESULT_SCHEMA,
        "artifact_sha256": oracle["artifact_sha256"],
        "baseline": a,
        "candidate": b,
        "signal": signal,
        "qualified_improvement": False,
        "required_next_gate": "INDEPENDENT_REPRODUCTION_AND_HELD_OUT_VALIDATION",
        "limitations": [
            "Reported runtime is not independently measured by this comparator.",
            "Only declared questions are scored; no source equivalence is implied.",
            "Blind recovery evidence must be sealed before evaluator-only oracle exposure.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--oracle", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    result = compare(_load(args.oracle), _load(args.baseline), _load(args.candidate))
    target = pathlib.Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"signal": result["signal"], "qualified_improvement": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
