#!/usr/bin/env python3
"""Evaluate whether BSim earns a role beyond exact/function-hash FID."""

from __future__ import annotations
import argparse
import json
import pathlib

VARIANTS = ("exact-copy", "stripped", "patched", "false-friend", "o0")
FUNCTIONS = ("aar_known_mix", "aar_known_checksum")


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def row(doc, name):
    rows = [x for x in doc["matches"] if x["function"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{doc.get('query_program')}: expected one {name} row, got {len(rows)}")
    return rows[0]


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    a=ap.parse_args()

    root=pathlib.Path(a.dir)
    docs={v:load(root/f"{v}.json") for v in VARIANTS}
    values={v:{f:row(docs[v],f) for f in FUNCTIONS} for v in VARIANTS}

    required = {
        "exact_copy_mix_near_exact": values["exact-copy"]["aar_known_mix"]["similarity"] >= 0.999,
        "exact_copy_checksum_near_exact": values["exact-copy"]["aar_known_checksum"]["similarity"] >= 0.999,
        "stripped_mix_near_exact": values["stripped"]["aar_known_mix"]["similarity"] >= 0.999,
        "stripped_checksum_near_exact": values["stripped"]["aar_known_checksum"]["similarity"] >= 0.999,
        "patched_unchanged_mix_near_exact": values["patched"]["aar_known_mix"]["similarity"] >= 0.999,
    }

    # BSim earns its keep only if at least one optimization-changed target is
    # substantially more similar to the source-known function than its
    # same-name false friend. We record both dimensions rather than declaring a
    # universal production threshold from this tiny golden.
    margins={}
    for f in FUNCTIONS:
        margins[f] = (
            values["o0"][f]["similarity"] - values["false-friend"][f]["similarity"]
        )
    earned = any(m > 0.10 for m in margins.values())

    # The deliberately patched checksum should not be *less* distinguishable
    # than its unrelated false friend. This is a sanity check, not an identity
    # threshold.
    required["patched_checksum_beats_false_friend"] = (
        values["patched"]["aar_known_checksum"]["similarity"]
        > values["false-friend"]["aar_known_checksum"]["similarity"]
    )

    failed=[k for k,v in required.items() if not v]
    result={
        "schema":"aar-ghidra-bsim-qualification/v0",
        "qualification":"PASS" if not failed and earned else "FAIL",
        "required_checks":required,
        "failed_checks":failed,
        "earned_incremental_value":earned,
        "o0_vs_false_friend_similarity_margin":margins,
        "observations":values,
        "policy":{
            "production_similarity_threshold":"UNQUALIFIED",
            "component_identity_from_bsim_alone":False,
            "intended_use":"build-variant/delta candidate evidence after exact/FID evidence is insufficient",
        },
    }
    pathlib.Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["qualification"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(main())
