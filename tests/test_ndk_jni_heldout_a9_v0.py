#!/usr/bin/env python3
"""A9 source-known negatives: disjoint modular uint IR, signed abstention."""
from __future__ import annotations
import base64
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from recover_ndk_jni_typed_partial_v0 import recover_partial
from verify_ndk_jni_typed_partial_native_v0 import judge,vectors,make_host_oracles
from verify_ndk_jni_heldout_a9_v0 import ORACLE_SOURCE

UINT_C="uint FUN_001016e0(uint param_1) {return (param_1 + 0x6d2b79f5) * 0x9e3779b1 ^ 0xa5f1523d;}"
SIGNED_C="uint FUN_00101700(int param_1) {return param_1 >> 1 ^ 0x2468ace;}"

def raw_log(first=UINT_C,second=SIGNED_C,extra=""):
    def line(addr,body):
        return "INFO AarJniSemanticEvidence.java> AAR_A4_IR="+format(addr,"x")+"|"+base64.b64encode(body.encode()).decode()+" (GhidraScript)  \n"
    return "AAR_A4_ABI=x86_64\nAAR_A4_BASE=100000\n"+line(0x1016e0,first)+line(0x101700,second)+extra+"AAR_A4_COUNT=2\n"

class HeldoutA9(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples=vectors()
        cls.native,cls.source_hash=make_host_oracles(ORACLE_SOURCE,cls.samples,"a9_u32_reference")
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.elf=Path(self.t.name)/"owned.so"
        self.elf.write_bytes(b"source-known-only-not-real-ELF")
        self.owner={"abi":"x86_64","fixture_kind":"heldout_a9","optimization":"-O0",
            "elf_machine":62,"elf_sha256":hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "helper_truth":{"aar_fold":0x16e0,"aar_affine":0x1700}}
        self.candidate=recover_partial(raw_log(),"x86_64")
    def verify(self,candidate=None,owner=None):
        return judge(self.candidate if candidate is None else candidate,"x86_64",
            self.owner if owner is None else owner,self.elf,self.samples,self.native,
            self.source_hash,fixture_kind="heldout_a9")
    def test_positive_disjoint_native_heldout(self):
        result=self.verify()
        self.assertEqual(result["status"],"A9_HELDOUT_UINT_NATIVE_MATCH_SIGNED_ABSTAIN")
        self.assertEqual(result["native_unsigned_behavioral_comparisons"],4136)
        self.assertEqual(result["native_unsigned_mismatches"],0)
        self.assertEqual(result["signed_helpers_abstained"],1)
    def test_different_operator_structure_from_a8(self):
        expr=self.candidate["records"][0]["ir"]
        self.assertEqual(expr["op"],"xor")
        self.assertEqual(expr["args"][0]["op"],"mul")
        self.assertEqual(expr["args"][0]["args"][0]["op"],"add")
    def test_bad_constant_is_proven_semantically_wrong(self):
        bad=copy.deepcopy(self.candidate)
        bad["records"][0]["ir"]["args"][1]["constant"] ^= 0x10
        with self.assertRaisesRegex(ValueError,"UNSIGNED_SEMANTIC_MISMATCH"):
            self.verify(bad)
    def test_signed_input_never_promoted(self):
        bad=copy.deepcopy(self.candidate)
        bad["records"][1]["status"]="RESTRICTED_UINT_CANDIDATE"
        bad["records"][1]["ir"]=bad["records"][0]["ir"]
        with self.assertRaisesRegex(ValueError,"signed helper"):
            self.verify(bad)
    def test_swapped_owner_addresses_fail(self):
        bad=dict(self.owner,helper_truth={"aar_fold":0x1700,"aar_affine":0x16e0})
        with self.assertRaises(ValueError):
            self.verify(owner=bad)
    def test_fixture_kind_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError,"unexpected fixture"):
            self.verify(owner=dict(self.owner,fixture_kind="typed"))
    def test_wrong_elf_sha_fails(self):
        with self.assertRaisesRegex(ValueError,"wrong stripped ELF SHA"):
            self.verify(owner=dict(self.owner,elf_sha256="0"*64))
    def test_malformed_ghidra_extra_record_fails(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            recover_partial(raw_log(extra="AAR_A4_IR=GARBAGE|%%%%\n"),"x86_64")
    def test_cross_abi_truth_fails(self):
        with self.assertRaisesRegex(ValueError,"cross-ABI"):
            self.verify(owner=dict(self.owner,abi="aarch64"))

if __name__=="__main__":
    unittest.main()
