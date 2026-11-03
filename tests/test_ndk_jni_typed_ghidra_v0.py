#!/usr/bin/env python3
"""A7 source-known synthetic checks: type inference alone never proves JNI semantics."""
from __future__ import annotations
import base64
import hashlib
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from verify_ndk_jni_typed_ghidra_v0 import judge

UNSIGNED="uint FUN_00100080(uint param_1) {return param_1 >> 1;}"
SIGNED="int FUN_001000a0(int param_1) {return param_1 >> 1;}"
def row(addr, text, native=False):
    prefix = "INFO AarJniSemanticEvidence.java> AAR_A4_IR=" if native else "AAR_A4_IR="
    suffix = " (GhidraScript)  " if native else ""
    return prefix+format(addr,"x")+"|"+base64.b64encode(text.encode()).decode()+suffix+"\n"
def log(second=SIGNED,extra="",native=False):
    return ("AAR_A4_ABI=x86_64\nAAR_A4_BASE=100000\n"
            +row(0x100080,UNSIGNED,native)
            +row(0x1000a0,second,native)
            +extra+"AAR_A4_COUNT=2\n")
class TypedGhidraBoundaryOracle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf=pathlib.Path(self.tmp.name)/"stripped.so"
        self.elf.write_bytes(b"source-owned-only-not-actual-ELF")
        self.oracle={
            "abi":"x86_64","fixture_kind":"typed","optimization":"-O0",
            "elf_machine":62,
            "elf_sha256":hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "helper_truth":{"aar_fold":0x80,"aar_affine":0xa0}
        }
    def test_signed_decomp_abstains_but_helper_boundaries_verified(self):
        output=judge(log(),"x86_64",self.oracle,self.elf)
        self.assertEqual(output["status"],"A7_TYPED_GHIDRA_BOUNDARY_ABSTAIN")
        self.assertEqual(output["candidate_parser_state"],"UNSUPPORTED_DECOMPILER_BODY_OR_TYPE")
        self.assertEqual(output["source_known_helper_entries_confirmed"],2)
        self.assertEqual(output["semantic_predictions_accepted"],0)
        self.assertFalse(output["semantics_qualified"])
    def test_real_ghidra_renderer_suffix_remains_unqualified(self):
        out=judge(log(native=True),"x86_64",self.oracle,self.elf)
        self.assertEqual(out["status"],"A7_TYPED_GHIDRA_BOUNDARY_ABSTAIN")
    def test_parseable_lookalike_stays_unqualified(self):
        out=judge(log(second=UNSIGNED),"x86_64",self.oracle,self.elf)
        self.assertEqual(out["candidate_parser_state"],
                         "RESTRICTED_IR_PARSEABLE_BUT_TYPE_PROVENANCE_UNVERIFIED")
        self.assertEqual(out["semantic_predictions_accepted"],0)
        self.assertFalse(out["semantics_qualified"])
    def test_wrong_source_identity_or_abi_rejected(self):
        bad=dict(self.oracle,elf_sha256="0"*64)
        with self.assertRaisesRegex(ValueError,"identity"):
            judge(log(),"x86_64",bad,self.elf)
        with self.assertRaisesRegex(ValueError,"ABI"):
            judge(log(),"aarch64",self.oracle,self.elf)
    def test_wrong_helper_boundaries_rejected(self):
        bad=dict(self.oracle,helper_truth={"aar_fold":0x80,"aar_affine":0x90})
        with self.assertRaisesRegex(ValueError,"helper entry"):
            judge(log(),"x86_64",bad,self.elf)
    def test_unparsed_third_marker_rejected_not_ignored(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            judge(log(extra="AAR_A4_IR=nothex|%%%%\n"),
                  "x86_64",self.oracle,self.elf)
    def test_unknown_fixture_or_optimization_rejected(self):
        for change in ({"fixture_kind":"controlflow"},{"optimization":"-O2"}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError,"typed O0"):
                    judge(log(),"x86_64",dict(self.oracle,**change),self.elf)

if __name__=="__main__":
    unittest.main()
