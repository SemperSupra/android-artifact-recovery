#!/usr/bin/env python3
"""A-6 adversarial oracle: structural recovery != accepted semantics."""
import base64,hashlib,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from verify_ndk_jni_controlflow_v0 import judge,independent_reference

BAD="uint FUN_00100080(uint param_1) { if ((param_1 & 1) != 0) return param_1+2; return param_1; }"
SIMPLE="uint FUN_00100080(uint param_1) { return param_1 + 1; }"
def mklog(first=BAD,second=BAD,extra=""):
    b64=lambda s:base64.b64encode(s.encode()).decode()
    return ("AAR_A4_ABI=x86_64\nAAR_A4_BASE=100000\n"
           + "AAR_A4_IR=100080|"+b64(first)+"\n"
           + "AAR_A4_IR=1000a0|"+b64(second)+"\n"
           +extra+"AAR_A4_COUNT=2\n")
class ControlFlowOracle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.elf=pathlib.Path(self.tmp.name)/"test.so"
        self.elf.write_bytes(b"source-owned-small-fake-ELF-for-unit-test")
        self.oracle={"abi":"x86_64","fixture_kind":"controlflow","optimization":"-O0",
                     "elf_sha256":hashlib.sha256(self.elf.read_bytes()).hexdigest(),
                     "helper_truth":{"aar_fold":0x80,"aar_affine":0xa0}}
    def test_unknown_is_honest_nonpromotion(self):
        a=judge(mklog(),"x86_64",self.oracle,self.elf)
        self.assertEqual(a["status"],"A6_DISJOINT_UNSUPPORTED_ABSTAIN")
        self.assertFalse(a["semantics_qualified"])
        self.assertEqual(a["unknown_helpers"],2)
    def test_signed_simple_expression_is_explicitly_unqualified(self):
        # Even a syntactically simple signed right shift has unsupported
        # implementation-defined semantics in the restricted unsigned A4 IR.
        signed="int FUN_00100080(int param_1) { return param_1 >> 1; }"
        a=judge(mklog(signed,SIMPLE),"x86_64",self.oracle,self.elf)
        self.assertEqual(a["status"],"A6_DISJOINT_UNSUPPORTED_ABSTAIN")
        self.assertFalse(a["semantics_qualified"])
        self.assertEqual(a["unknown_helpers"],2)
        self.assertEqual(a["heldout_vectors_evaluated"],0)
    def test_bad_extra_ir_record_refuses_before_oracle(self):
        bad=mklog(extra="AAR_A4_IR=GGGG|%%%\n")
        with self.assertRaisesRegex(ValueError,"malformed"):
            judge(bad,"x86_64",self.oracle,self.elf)
    def test_ir_record_trailing_junk_refuses(self):
        valid=mklog()
        damaged=valid.replace("AAR_A4_IR=100080|","AAR_A4_IR=100080|!garbage",1)
        with self.assertRaisesRegex(ValueError,"malformed"):
            judge(damaged,"x86_64",self.oracle,self.elf)
    def test_supported_but_wrong_rejects(self):
        with self.assertRaisesRegex(ValueError,"SEMANTIC_MISMATCH"):
            judge(mklog(SIMPLE,SIMPLE),"x86_64",self.oracle,self.elf)
    def test_wrong_abi_and_source_digest_reject(self):
        with self.assertRaises(ValueError):judge(mklog(),"aarch64",self.oracle,self.elf)
        bad=dict(self.oracle,elf_sha256="0"*64)
        with self.assertRaises(ValueError):judge(mklog(),"x86_64",bad,self.elf)
    def test_duplicate_or_missing_helper_reject(self):
        e="AAR_A4_IR=1000a0|"+base64.b64encode(BAD.encode()).decode()+"\n"
        with self.assertRaises(ValueError):judge(mklog(extra=e),"x86_64",self.oracle,self.elf)
    def test_wrong_producer_source_kind_reject(self):
        bad=dict(self.oracle,fixture_kind="baseline")
        with self.assertRaises(ValueError):judge(mklog(),"x86_64",bad,self.elf)
    def test_python_expected_has_distinct_branch_and_bounded_loop(self):
        self.assertNotEqual(independent_reference(5,0),independent_reference(5,1))
        self.assertEqual(independent_reference(7,0x10203040),independent_reference(7,0x10203040))
        self.assertNotEqual(independent_reference(5,12),independent_reference(7,12))
        self.assertTrue(0<=independent_reference(5,-1)<=0xffffffff)

if __name__=="__main__":
    unittest.main()
