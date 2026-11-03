#!/usr/bin/env python3
"""A7 evaluator-only, source-known typed Ghidra observation qualification.

The A4 parser receives no producer truth. This evaluator subsequently checks
the SHA of the stripped input ELF and two discovered helper-entry RVAs against
a separate producer-only oracle, then refuses to promote any typed semantics
without independent signedness/ABI evidence. Ghidra-C is not exported.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from recover_ndk_jni_semantics_v0 import read_ir_rows, recover, one
from experiment_ndk_jni_ghidra_recovery_v0 import ABIS, digest

ABSTAIN_REASON = (
    "UNSUPPORTED_SIGNED_OR_MIXED_IR",
    "unhandled pseudocode structure",
    "unsupported decompiled C operation",
    "expression too large",
    "invalid syntax",
    "Ghidra pseudocode size/hidden-symbol leak",
)

def judge(log: str, abi: str, oracle: dict, elf: Path) -> dict:
    if abi not in ABIS or oracle.get("abi") != abi:
        raise ValueError("typed observation wrong ABI")
    if oracle.get("fixture_kind") != "typed" or oracle.get("optimization") != "-O0":
        raise ValueError("not the admitted typed O0 fixture")
    if oracle.get("elf_machine") != ABIS[abi][0] or digest(elf) != oracle.get("elf_sha256"):
        raise ValueError("typed ELF identity or machine mismatch")
    if one(log, "ABI") != abi or int(one(log, "COUNT")) != 2:
        raise ValueError("wrong typed Ghidra ABI or count")
    base = int(one(log, "BASE"), 16)
    observed = read_ir_rows(log)
    try:
        actual = {int(addr, 16) - base for addr, _ in observed}
    except ValueError as exc:
        raise ValueError("invalid typed Ghidra function address") from exc
    truth = oracle.get("helper_truth")
    if (type(truth) is not dict or set(truth) != {"aar_fold", "aar_affine"}
        or len(actual) != 2 or actual != set(truth.values()) or min(actual) <= 0):
        raise ValueError("source-known helper entry mismatch")
    # Structural evidence is checked before the source-blind candidate.
    # No native C types or source-side names flow into recover().
    try:
        result = recover(log, abi)
    except (ValueError, SyntaxError) as exc:
        if not any(reason in str(exc) for reason in ABSTAIN_REASON):
            raise
        category = "UNSUPPORTED_DECOMPILER_BODY_OR_TYPE"
    else:
        # Even two syntactically supported unsigned IR trees do NOT prove that
        # Ghidra inferred the actual source types or signed right-shift ABI.
        if set(result.get("helpers", {})) != {format(i,"x") for i in actual}:
            raise ValueError("typed candidate helper ownership mismatch")
        category = "RESTRICTED_IR_PARSEABLE_BUT_TYPE_PROVENANCE_UNVERIFIED"
    return {
        "schema": 1, "abi": abi, "status": "A7_TYPED_GHIDRA_BOUNDARY_ABSTAIN",
        "fixture_kind": "typed", "optimization": "-O0",
        "elf_sha256": oracle["elf_sha256"],
        "source_known_helper_entries_confirmed": 2,
        "ghidra_ir_complete_records": 2,
        "candidate_parser_state": category,
        "semantic_predictions_accepted": 0,
        "semantics_qualified": False,
        "actual_art_jni_runtime_executed": False,
        "source_oracle_passed_to_ghidra": False,
        "source_oracle_passed_to_candidate": False,
        "decompiler_c_published": False,
        "ai_actor_qualified": False,
        "cross_abi_semantics_qualified": False,
    }

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--abi", choices=tuple(ABIS), required=True)
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if a.log.stat().st_size > 5_000_000:
        raise ValueError("oversized typed Ghidra evidence")
    oracle=json.loads((a.root / (a.abi + "-private-oracle.json")).read_text())
    result=judge(a.log.read_text(errors="replace"),a.abi,oracle,
                 a.root / (a.abi + "-ghidra-stripped.so"))
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("A7_AGGREGATE="+json.dumps(result,sort_keys=True))

if __name__=="__main__":
    try:
        main()
    except (ValueError,KeyError,OSError,SyntaxError) as exc:
        print("A7_ORACLE_FAIL="+str(exc),file=sys.stderr)
        raise SystemExit(1)
