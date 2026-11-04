"""Classify native Android ABI evidence independently of download selection hints."""
from __future__ import annotations


def qualify_native_abi(artifact_characterization: dict | None, requested_abi: str) -> dict:
    summary = (artifact_characterization or {}).get("summary") or {}
    observed = sorted(set(summary.get("abis") or []))
    elf_count = (summary.get("kinds") or {}).get("elf", 0)
    if not requested_abi or not observed:
        verdict = "NATIVE_ABI_NOT_ESTABLISHED"
    elif requested_abi in observed:
        verdict = "NATIVE_ABI_MATCH"
    else:
        verdict = "NATIVE_ABI_MISMATCH"
    return {
        "status": verdict,
        "requested_abi": requested_abi,
        "observed_native_abis": observed,
        "observed_elf_count": elf_count,
        "requested_native_abi_verified": verdict == "NATIVE_ABI_MATCH",
        "claim_boundary": (
            "The acquisition selector and archive filename do not prove installed native ABI. "
            "Verified ABI derives from ELF entries in signed split APKs, not the requested architecture."
        ),
    }
