#!/usr/bin/env python3
"""Conservative AAR component correspondence matcher.

The matcher deliberately promotes only an exact cryptographic binary match to
EXACT_BYTES. Metadata overlap is retained as FAMILY_MATCH evidence and does not
remove the object from residual recovery.

This is the cheap first stage of component attribution. Structural matchers such
as FID/BSim are separate evidence producers.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


METADATA_FAMILIES = {
    "sonames": "soname",
    "build_ids": "build-id",
    "namespaces": "namespace",
    "package_coordinates": "package-metadata",
    "version_strings": "version-string",
    "license_notices": "license-notice",
}


def load_json(path: str) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def as_strings(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(x) for x in value if isinstance(x, (str, int, float))}


def exact_claim(obj: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    obj_sha = str(obj.get("sha256", "")).lower()
    obj_kind = str(obj.get("kind", ""))
    for binary in ref.get("binaries", []) or []:
        if (
            str(binary.get("sha256", "")).lower() == obj_sha
            and str(binary.get("kind", "")) == obj_kind
        ):
            return {
                "component_id": ref["component_id"],
                "component_name": ref["name"],
                "version": ref.get("version"),
                "purl": ref.get("purl"),
                "source_ref": ref.get("source_ref"),
                "reference_provenance_class": ref["provenance_class"],
                "identity_state": "EXACT_BYTES",
                "coverage": {"kind": "WHOLE_OBJECT"},
                "modification_state": "UNMODIFIED",
                "evidence": [
                    {
                        "family": "exact-hash",
                        "producer": "aar-component-correspondence",
                        "detail": f"object SHA-256 exactly matches reference binary for {ref['component_id']}",
                        "reference_sha256": obj_sha,
                    }
                ],
                "disposition": "REFERENCE_ONLY",
                "boundary_analysis_required": True,
            }
    return None


def metadata_claim(obj: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    observed = obj.get("metadata", {}) or {}
    reference = ref.get("metadata", {}) or {}
    evidence: list[dict[str, Any]] = []

    for key, family in METADATA_FAMILIES.items():
        overlap = sorted(as_strings(observed.get(key)) & as_strings(reference.get(key)))
        for value in overlap:
            evidence.append(
                {
                    "family": family,
                    "producer": "aar-component-correspondence",
                    "detail": f"metadata overlap {key}={value}",
                }
            )

    if not evidence:
        return None

    return {
        "component_id": ref["component_id"],
        "component_name": ref["name"],
        "version": ref.get("version"),
        "purl": ref.get("purl"),
        "source_ref": ref.get("source_ref"),
        "reference_provenance_class": ref["provenance_class"],
        "identity_state": "FAMILY_MATCH",
        "coverage": {"kind": "WHOLE_OBJECT"},
        "modification_state": "UNKNOWN",
        "evidence": evidence,
        "disposition": "RESIDUAL_RECOVERY",
        "boundary_analysis_required": True,
    }


def choose_residual_state(claims: list[dict[str, Any]]) -> str:
    if any(
        c["identity_state"] in {"EXACT_BYTES", "REPRODUCIBLE_EQUIVALENT"}
        and c["coverage"]["kind"] == "WHOLE_OBJECT"
        and c["modification_state"] == "UNMODIFIED"
        for c in claims
    ):
        return "KNOWN_REFERENCE"
    if any(c["modification_state"] == "MODIFIED_DERIVATIVE" for c in claims):
        return "DELTA"
    if claims:
        return "RESIDUAL"
    return "UNKNOWN"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--observations", required=True)
    ap.add_argument("--references", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    observations = load_json(args.observations)
    references = load_json(args.references)

    if observations.get("schema") != "aar-component-observations/v0":
        raise SystemExit("unsupported observations schema")
    if references.get("schema") != "aar-reference-catalog/v0":
        raise SystemExit("unsupported reference catalog schema")

    artifact_sha = str(observations.get("artifact", {}).get("sha256", ""))
    if len(artifact_sha) != 64:
        raise SystemExit("observations missing artifact SHA-256")

    out_objects: list[dict[str, Any]] = []
    unknowns: list[dict[str, str]] = []

    for obj in observations.get("objects", []):
        claims: list[dict[str, Any]] = []

        for ref in references.get("references", []):
            exact = exact_claim(obj, ref)
            if exact is not None:
                claims.append(exact)
                continue

            metadata = metadata_claim(obj, ref)
            if metadata is not None:
                claims.append(metadata)

        # Exact bytes dominate weaker claims to the same component/version but
        # do not erase claims to other candidates.
        exact_keys = {
            (c["component_id"], c.get("version"))
            for c in claims
            if c["identity_state"] == "EXACT_BYTES"
        }
        claims = [
            c for c in claims
            if c["identity_state"] == "EXACT_BYTES"
            or (c["component_id"], c.get("version")) not in exact_keys
        ]

        out_obj = dict(obj)
        out_obj["claims"] = claims
        out_obj["residual_state"] = choose_residual_state(claims)
        out_objects.append(out_obj)

        if not claims:
            unknowns.append(
                {
                    "id": str(obj.get("object_id")),
                    "reason": "no correspondence evidence against supplied reference catalog",
                }
            )

    doc = {
        "schema": "aar-component-correspondence/v0",
        "artifact": {"sha256": artifact_sha},
        "objects": out_objects,
        "unknowns": unknowns,
        "reference_catalog": {
            "path": str(pathlib.Path(args.references)),
            "reference_count": len(references.get("references", [])),
        },
        "policy": {
            "exact_hash_promotes_to_exact_bytes": True,
            "metadata_never_promotes_above_family_match": True,
            "attribution_erases_evidence": False,
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "objects": len(out_objects),
        "known_reference": sum(x["residual_state"] == "KNOWN_REFERENCE" for x in out_objects),
        "residual": sum(x["residual_state"] == "RESIDUAL" for x in out_objects),
        "unknown": sum(x["residual_state"] == "UNKNOWN" for x in out_objects),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
