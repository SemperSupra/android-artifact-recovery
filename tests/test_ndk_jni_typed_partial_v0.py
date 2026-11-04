#!/usr/bin/env python3
"""A8 source-known tests; original Ghidra native text structure, no ART."""
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
from verify_ndk_jni_typed_partial_native_v0 import judge, vectors, make_host_oracles, SOURCE_ORACLE

U="\nuint FUN_001016e0(uint param_1)\n\n{\n  return param_1 >> 1 ^ 0x13579bdf;\n}\n\n"
S="\nuint FUN_00101700(int param_1)\n\n{\n  return param_1 >> 1 ^ 0x2468ace;\n}\n\n"

def log(unsigned=U,signed=S,extra="",bad_suffix=""):
    def row(addr,code,suffix=""):
        return "INFO AarJniSemanticEvidence.java> AAR_A4_IR="+format(addr,"x")+"|"+base64.b64encode(code.encode()).decode()+suffix+" (GhidraScript)  \n"
    return ("AAR_A4_ABI=x86_64\nAAR_A4_BASE=100000\n"
        +row(0x1016e0,unsigned,bad_suffix)+row(0x101700,signed)
        +extra+"AAR_A4_COUNT=2\n")

class PartialSemanticQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples=vectors()
        cls.native,cls.native_hash=make_host_oracles(SOURCE_ORACLE,cls.samples)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.elf=Path(self.temp.name)/"stripped.so"
        self.elf.write_bytes(b"source-known synthetic unit fixture not ELF")
        self.oracle={"abi":"x86_64","fixture_kind":"typed", "optimization":"-O0",
            "elf_machine":62,"elf_sha256":hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "helper_truth":{"aar_fold":0x16e0,"aar_affine":0x1700}}
        self.candidate=recover_partial(log(),"x86_64")
    def judge(self,candidate=None,oracle=None):
        return judge(self.candidate if candidate is None else candidate,"x86_64",
            self.oracle if oracle is None else oracle,self.elf,
            self.samples,self.native,self.native_hash)
    def test_actual_ghidra_pseudocode_unsigned_recovered_signed_abstained(self):
        c=self.candidate
        self.assertEqual(len(c["records"]),2)
        self.assertEqual([r["status"] for r in c["records"]],
             ["RESTRICTED_UINT_CANDIDATE","ABSTAIN"])
        self.assertFalse(c["producer_oracle_opened"])
        out=self.judge()
        self.assertEqual(out["source_blind_recovered_unsigned_helpers"],1)
        self.assertEqual(out["signed_helpers_abstained"],1)
        self.assertEqual(out["native_unsigned_behavioral_comparisons"],len(self.samples)*4)
        self.assertEqual(out["native_unsigned_mismatches"],0)
        self.assertFalse(out["production_semantics_qualified"])
    def test_independent_oracle_rejects_wrong_unsigned_operator(self):
        bad=copy.deepcopy(self.candidate)
        good=bad["records"][0]["ir"]
        self.assertEqual(good["op"],"xor")
        good["args"][1]["constant"] ^= 1
        with self.assertRaisesRegex(ValueError,"UNSIGNED_SEMANTIC_MISMATCH"):
            self.judge(bad)
    def test_bad_source_identity_denied(self):
        bad=dict(self.oracle,elf_sha256="0"*64)
        with self.assertRaisesRegex(ValueError,"ELF SHA"):
            self.judge(oracle=bad)
    def test_wrong_or_swapped_hidden_helper_attribution_denied(self):
        for truth in ({"aar_fold":0x1700,"aar_affine":0x16e0},
                      {"aar_fold":0x16e0,"aar_affine":0x1800}):
            with self.subTest(truth=truth):
                with self.assertRaises(ValueError):
                    self.judge(oracle=dict(self.oracle,helper_truth=truth))
    def test_signed_candidate_must_not_be_promoted(self):
        bad=copy.deepcopy(self.candidate)
        bad["records"][1]["status"]="RESTRICTED_UINT_CANDIDATE"
        bad["records"][1]["ir"]=copy.deepcopy(bad["records"][0]["ir"])
        with self.assertRaisesRegex(ValueError,"signed helper"):
            self.judge(bad)
    def test_malformed_ghidra_evidence_denied(self):
        with self.assertRaisesRegex(ValueError,"malformed"):
            recover_partial(log(extra="AAR_A4_IR=BAD|%%%\n"),"x86_64")
        with self.assertRaisesRegex(ValueError,"malformed"):
            recover_partial(log(bad_suffix="#junk"),"x86_64")
    def test_cross_abi_oracle_mismatch_denied(self):
        with self.assertRaisesRegex(ValueError,"cross-ABI"):
            self.judge(oracle=dict(self.oracle,abi="aarch64"))
    def test_candidate_integrity_flags_denied(self):
        for key,value in (("source_blind",False),
                          ("producer_oracle_opened",True),
                          ("semantic_predictions_accepted",1)):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.judge(dict(self.candidate,**{key:value}))
    def test_no_unsupported_helper_becomes_valid_on_shape_only(self):
        both_unsigned=recover_partial(log(signed=U),"x86_64")
        self.assertEqual([r["status"] for r in both_unsigned["records"]],
             ["RESTRICTED_UINT_CANDIDATE","RESTRICTED_UINT_CANDIDATE"])
        with self.assertRaisesRegex(ValueError,"signed helper"):
            self.judge(both_unsigned)

if __name__=="__main__":
    unittest.main()
