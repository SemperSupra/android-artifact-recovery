#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import pathlib

FIELDS = ("canonical_b64", "sha256", "record_count", "unique_key_count")

def read_observation(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key in FIELDS:
            values[key] = value
    return values

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--original", required=True)
    p.add_argument("--candidate")
    p.add_argument("--candidate-state", required=True,
                   choices=("executed", "compile-failed", "run-failed"))
    p.add_argument("--candidate-detail")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    original = read_observation(pathlib.Path(a.original))
    missing_original = [x for x in FIELDS if x not in original]
    if missing_original:
        raise SystemExit(f"original observation missing fields: {missing_original}")

    doc: dict[str, object] = {
        "schema": "aar-behavior-comparison/v0",
        "oracle": original,
        "candidate_state": a.candidate_state,
        "candidate_detail": a.candidate_detail,
        "comparison": {},
    }

    if a.candidate_state == "executed" and a.candidate:
        candidate = read_observation(pathlib.Path(a.candidate))
        missing_candidate = [x for x in FIELDS if x not in candidate]
        if missing_candidate:
            doc["status"] = "UNKNOWN"
            doc["reason"] = f"candidate observation missing fields: {missing_candidate}"
        else:
            comparison = {
                field: {
                    "original": original[field],
                    "candidate": candidate[field],
                    "equal": original[field] == candidate[field],
                }
                for field in FIELDS
            }
            doc["candidate"] = candidate
            doc["comparison"] = comparison
            doc["status"] = (
                "BEHAVIOR-MATCH"
                if all(x["equal"] for x in comparison.values())
                else "BEHAVIOR-MISMATCH"
            )
    else:
        doc["status"] = "UNKNOWN"
        doc["reason"] = "recovered high-level representation was not independently executable"

    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": doc["status"], "candidate_state": a.candidate_state}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
