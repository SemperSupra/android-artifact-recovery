"""Compare repeated derived Android evidence ZIPs without consuming original APKs.

A same-SHA donor does not imply deterministic decompilation or complete runtime
coverage. This is a metadata-only, non-promoting, read-only diagnostic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from zipfile import ZipFile
from tools.summarize_android_surface import KEYWORDS, LIBRARY_MARKERS, PROTOCOL_MARKERS

_ALLOWED_JADX_STATUS = {
    "MISSING_JADX_EXIT_CODE",
    "JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE",
    "JADX_EXIT_ZERO_COVERAGE_UNVERIFIED",
    "JADX_SHARDED_PARTIAL_EVIDENCE",
    "JADX_SHARDED_EXIT_ZERO_COVERAGE_UNVERIFIED",
    "JADX_TARGETED_FALLBACK_PARTIAL_EVIDENCE",
    "JADX_TARGETED_FALLBACK_EXIT_ZERO_COVERAGE_UNVERIFIED",
}


def _safe_jadx_status(receipt: dict) -> str:
    quality = receipt.get("decompiler_qualification")
    value = quality.get("status") if isinstance(quality, dict) else None
    return value if isinstance(value, str) and value in _ALLOWED_JADX_STATUS else "UNREVIEWED_JADX_STATUS"


# Metric dictionary keys must be literal, reviewed scanner vocabulary.
# Do not emit arbitrary keys from externally supplied evidence ZIPs.
_ALLOWED_METRICS = {
    "feature_markers": frozenset(KEYWORDS),
    "library_markers": frozenset(LIBRARY_MARKERS),
    "protocol_markers": frozenset(PROTOCOL_MARKERS),
}

def _validate_metric_names(surface: dict) -> None:
    for field, allowed in _ALLOWED_METRICS.items():
        metrics = surface.get(field)
        if not isinstance(metrics, dict):
            raise ValueError(f"missing or invalid {field}")
        if any(not isinstance(name, str) or name not in allowed for name in metrics):
            raise ValueError(f"unexpected metric name in {field}")

_MAX_MEMBER = 2_000_000
_SHA = re.compile(r"^([a-fA-F0-9]{64})\s+\S+", re.M)
_MEMBERS = ("selected-archive-sha256.txt", "receipt.json", "derived-surface.json")


def _read_member(z: ZipFile, name: str) -> bytes:
    matches = [x for x in z.infolist() if x.filename == name]
    if len(matches) != 1 or matches[0].file_size > _MAX_MEMBER:
        raise ValueError(f"missing, repeated or oversized required member: {name}")
    data = z.read(matches[0])
    if len(data) > _MAX_MEMBER:
        raise ValueError(f"oversized member: {name}")
    return data


def load_evidence(path: str | Path) -> dict:
    with ZipFile(path) as z:
        source = _read_member(z, _MEMBERS[0]).decode("utf-8")
        match = _SHA.search(source)
        if not match:
            raise ValueError("missing valid selected-archive sha256")
        receipt = json.loads(_read_member(z, _MEMBERS[1]))
        surface = json.loads(_read_member(z, _MEMBERS[2]))
    if receipt.get("schema") != "aar-chatgpt-public-recovery-receipt/v1":
        raise ValueError("unsupported receipt schema")
    if surface.get("schema") != "aar-derived-android-surface/v2":
        raise ValueError("unsupported surface schema")
    if type(surface.get("files_scanned")) is not int or surface["files_scanned"] < 0:
        raise ValueError("invalid files_scanned")
    for field in ("feature_markers", "protocol_markers", "library_markers"):
        if not isinstance(surface.get(field), dict):
            raise ValueError(f"missing or invalid {field}")
    _validate_metric_names(surface)
    return {"donor_sha256": match.group(1).lower(), "receipt": receipt, "surface": surface}


def _safe_value(value: object) -> object:
    """Never expose raw path, URL, API shape or free-text donor-derived values."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "content_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "element_count": len(value) if isinstance(value, (dict, list, tuple, str)) else None,
    }


def compare(left: dict, right: dict) -> dict:
    _validate_metric_names(left["surface"])
    _validate_metric_names(right["surface"])
    same_sha = left["donor_sha256"] == right["donor_sha256"]
    identity_ok = all(
        x["receipt"].get("package_id") == "com.openai.chatgpt"
        and x["receipt"].get("official_signer_verified") is True
        and x["receipt"].get("proprietary_bytes_published") is False
        for x in (left, right)
    )
    same_source = left["receipt"].get("selected_source") == right["receipt"].get("selected_source")
    config_left = left["receipt"].get("derivation_config")
    config_right = right["receipt"].get("derivation_config")
    if config_left is None and config_right is None:
        config_status = "BOTH_UNRECORDED"
    elif isinstance(config_left, dict) and isinstance(config_right, dict) and config_left == config_right:
        config_status = "EXACT_CONFIG_MATCH"
    else:
        config_status = "INCOMPARABLE_DERIVATION_CONFIGURATION"
    if not identity_ok:
        status = "INVALID_OR_UNVERIFIED_PROVENANCE"
    elif not same_sha or not same_source:
        status = "INCOMPARABLE_SOURCE_IDENTITY"
    elif config_status != "EXACT_CONFIG_MATCH":
        # Historical runs lacking a recorded configuration are comparable only
        # as observations, not evidence of same-configuration repeatability.
        status = "INCOMPARABLE_DERIVATION_CONFIGURATION"
    else:
        status = "PENDING_COMPARISON"
    diffs: dict[str, object] = {}
    if status == "PENDING_COMPARISON":
        for field in ("files_scanned", "feature_markers", "protocol_markers", "library_markers"):
            a, b = left["surface"].get(field), right["surface"].get(field)
            if isinstance(a, dict) and isinstance(b, dict):
                keys = sorted(set(a) | set(b))
                changed = {
                    k: {"left": _safe_value(a.get(k)), "right": _safe_value(b.get(k))}
                    for k in keys if a.get(k) != b.get(k)
                }
                if changed:
                    diffs[field] = changed
            elif a != b:
                diffs[field] = {"left": _safe_value(a), "right": _safe_value(b)}
        status = "SAME_DONOR_DERIVATION_DRIFT" if diffs else "SAME_DONOR_BOUNDED_REPEATABLE"
    return {
        "schema": "aar-android-repeated-donor-diagnostic/v1",
        "status": status,
        "same_donor_sha256": same_sha,
        "same_acquisition_source": same_source,
        "derivation_config_status": config_status,
        "bounded_signer_claims_present": identity_ok,
        "donor_sha256": left["donor_sha256"] if same_sha else None,
        "left_decompiler_status": _safe_jadx_status(left["receipt"]),
        "right_decompiler_status": _safe_jadx_status(right["receipt"]),
        "observed_differences": diffs,
        "qualified_full_coverage": False,
        "promotion_authorized": False,
        "claim_boundary": "This compares bounded derived metadata, not complete code, runtime semantics or independent oracle acceptance.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left_zip")
    parser.add_argument("right_zip")
    parser.add_argument("--out", default="-")
    args = parser.parse_args()
    report = compare(load_evidence(args.left_zip), load_evidence(args.right_zip))
    data = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.out == "-":
        print(data, end="")
    else:
        Path(args.out).write_text(data, encoding="utf-8")


if __name__ == "__main__":
    main()
