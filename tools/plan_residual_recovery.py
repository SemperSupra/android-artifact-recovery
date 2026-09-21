#!/usr/bin/env python3
"""Create a logical residual-recovery plan from correspondence evidence.

The planner never edits or emits a rewritten APK. It only prioritizes observed
objects for reference, boundary, delta, or residual work.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


def load(path: str) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--correspondence", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    doc = load(args.correspondence)
    if doc.get("schema") != "aar-component-correspondence/v0":
        raise SystemExit("unsupported correspondence schema")

    plan = {
        "schema": "aar-residual-recovery-plan/v0",
        "artifact": doc["artifact"],
        "reference_only": [],
        "boundary_analysis": [],
        "delta_recovery": [],
        "residual_recovery": [],
        "unknowns": list(doc.get("unknowns", [])),
        "policy": {
            "physical_subtraction": False,
            "preserve_original_identity": True,
            "boundary_analysis_for_known_components": True,
        },
    }

    for obj in doc.get("objects", []):
        object_ref = {
            "object_id": obj["object_id"],
            "kind": obj["kind"],
            "sha256": obj["sha256"],
            "archive_path": obj.get("archive_path"),
        }
        claims = obj.get("claims", [])

        for claim in claims:
            if claim.get("boundary_analysis_required"):
                plan["boundary_analysis"].append({
                    **object_ref,
                    "component_id": claim["component_id"],
                    "identity_state": claim["identity_state"],
                })

        if obj.get("residual_state") == "KNOWN_REFERENCE":
            exact = [
                c for c in claims
                if c["identity_state"] in {"EXACT_BYTES", "REPRODUCIBLE_EQUIVALENT"}
                and c["coverage"]["kind"] == "WHOLE_OBJECT"
            ]
            plan["reference_only"].append({
                **object_ref,
                "claims": exact,
            })
        elif obj.get("residual_state") == "DELTA":
            plan["delta_recovery"].append({
                **object_ref,
                "claims": claims,
            })
        else:
            plan["residual_recovery"].append({
                **object_ref,
                "claims": claims,
                "reason": (
                    "correspondence insufficient to remove object from residual recovery"
                    if claims
                    else "no correspondence claim"
                ),
            })

    pathlib.Path(args.out).write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "reference_only": len(plan["reference_only"]),
        "boundary_analysis": len(plan["boundary_analysis"]),
        "delta_recovery": len(plan["delta_recovery"]),
        "residual_recovery": len(plan["residual_recovery"]),
        "unknowns": len(plan["unknowns"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
