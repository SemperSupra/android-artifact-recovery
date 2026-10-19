#!/usr/bin/env python3
"""A5 preflight oracle controls: unsupported O0 expressions must become UNKNOWN."""
import base64,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from experiment_ndk_jni_optimizer_holdout_v0 import run_evaluator
def row(addr,text):
    return "INFO Ghidra> AAR_A4_IR="+format(addr,"x")+"|"+base64.b64encode(text.encode()).decode()+"\n"
FOLD="uint FUN_00101680(uint param_1) { return (param_1 ^ 0x51ad70e5) * -0x61c8864f >> 0x17 | (param_1 ^ 0x51ad70e5) * 0x6ef36200; }"
AFFINE="int FUN_001016a0(int param_1) { return param_1 * 0x11 + 0x7654321; }"
TRUTH={"abi":"x86_64","helper_truth":{"aar_fold":0x1680,"aar_affine":0x16a0}}
def log(a=FOLD,b=AFFINE):
    return "AAR_A4_ABI=x86_64\nAAR_A4_BASE=100000\n"+row(0x101680,a)+row(0x1016a0,b)+"AAR_A4_COUNT=2\n"
class OptimizerHoldoutOracle(unittest.TestCase):
    def test_baseline_supported(self):
        v=run_evaluator(log(),TRUTH,"x86_64")
        self.assertEqual(v["semantic_correct_predictions"],2088)
        self.assertTrue(v["qualified"])
        self.assertFalse(v["actor_qualified"])
    def test_unknown_for_valid_nontrivial_c(self):
        altered="uint FUN_00101680(uint param_1) { uint z = param_1 ^ 1; return z; }"
        v=run_evaluator(log(a=altered),TRUTH,"x86_64")
        self.assertEqual(v["status"],"A5_UNSUPPORTED_DECOMPILER_EXPRESSION")
        self.assertFalse(v["qualified"])
    def test_bad_abi_is_not_unknown(self):
        with self.assertRaises(ValueError):run_evaluator(log(),TRUTH,"aarch64")
    def test_duplicate_ghidra_callee_is_not_unknown(self):
        with self.assertRaises(ValueError):
            run_evaluator(log()+row(0x1016a0,AFFINE),TRUTH,"x86_64")
    def test_wrong_semantics_fail_not_unknown(self):
        bad="int FUN_001016a0(int param_1) { return param_1 * 0x11 + 0x7654322; }"
        with self.assertRaisesRegex(ValueError,"held-out semantic mismatch"):
            run_evaluator(log(b=bad),TRUTH,"x86_64")
if __name__=="__main__":unittest.main()
