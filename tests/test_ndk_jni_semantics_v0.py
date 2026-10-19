#!/usr/bin/env python3
"""A-4 adversarial controls for restricted Ghidra-expression reconstruction."""
import copy,sys,pathlib,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from recover_ndk_jni_semantics_v0 import parse_c,evaluate,recover
from verify_ndk_jni_semantics_v0 import evaluate_withheld,vectors

def stmt(expr, typ="uint"):return f"{typ} FUN_00101680({typ} param_1)\n{{\n  return {expr};\n}}"
def src(x):
    return parse_c(stmt(x))
class SourceBlindOperator(unittest.TestCase):
    def test_arithmetic_wrap_and_signed_negative_constant(self):
        t=src("(param_1 ^ 0x51ad70e5) * -0x61c8864f >> 0x17 | (param_1 ^ 0x51ad70e5) * 0x6ef36200")
        self.assertEqual(evaluate(t,0),((0x51ad70e5*0x9e3779b1)&0xffffffff)<<9&0xffffffff | ((0x51ad70e5*0x9e3779b1)&0xffffffff)>>23)
    def test_affine_parses_but_is_not_hardcoded(self):
        t=src("param_1 * 0x11 + 0x7654321")
        self.assertEqual(evaluate(t,7),(7*17+0x7654321)&0xffffffff)
        self.assertNotEqual(evaluate(t,8),evaluate(t,7))
    def test_no_code_execution_or_unbounded_c(self):
        bad=["__import__('os').system('false')","param_1**50","param_1/3","bad_name + 1",
             "param_1[0]","param_1 if True else 0"]
        for b in bad:
            with self.subTest(b=b),self.assertRaises(ValueError):
                parse_c(stmt(b))
    def test_hidden_source_name_fails(self):
        with self.assertRaises(ValueError):parse_c(stmt("aar_fold(param_1)"))
    def test_extra_statements_fail(self):
        with self.assertRaises(ValueError):
            parse_c("uint FUN_00101680(uint param_1) { uint x=param_1; return x; }")
    def test_expected_heldout_is_nontrivial(self):
        v=vectors()
        self.assertGreaterEqual(len(v),1000)
        self.assertIn(-1,v)
    def test_wrong_helper_and_tampered_constant_rejected(self):
        fold=src("param_1 ^ 1")
        affine=src("param_1 * 3 + 5")
        truth={"abi":"x86_64","helper_truth":{"aar_fold":0x100,"aar_affine":0x200}}
        candidate={"schema":1,"abi":"x86_64","source_blind":True,
                   "helpers":{"100":{"expression":fold},"200":{"expression":affine}}}
        with self.assertRaisesRegex(ValueError,"semantic mismatch"):
            evaluate_withheld(candidate,truth)
        candidate["helpers"]["200"]["expression"]=src("param_1 * 3 + 6")
        with self.assertRaisesRegex(ValueError,"semantic mismatch"):
            evaluate_withheld(candidate,truth)
    def test_abi_and_source_fence(self):
        truth={"abi":"x86_64","helper_truth":{"aar_fold":0x100,"aar_affine":0x200}}
        candidate={"schema":1,"abi":"aarch64","source_blind":True,"helpers":{}}
        with self.assertRaises(ValueError):evaluate_withheld(candidate,truth)
if __name__=="__main__":unittest.main()
