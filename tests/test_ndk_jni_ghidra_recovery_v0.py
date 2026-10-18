#!/usr/bin/env python3
"""A-3 oracle falsification controls, no NDK/Ghidra required."""
import sys, pathlib, unittest, tempfile, json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from experiment_ndk_jni_ghidra_recovery_v0 import evaluate
from unittest.mock import patch

ORACLE={"abi":"x86_64","elf_machine":62,"elf_sha256":"example",
        "jni_address":4096,"helper_truth":{"aar_fold":4112,"aar_affine":4128}}
PROBE="""AAR_A3_ABI=x86_64
AAR_A3_JNI_ENTRY=1000
AAR_A3_CALLEE=1010|25|true
AAR_A3_CALLEE=1020|21|true
AAR_A3_INTERNAL_CALLS=2
"""
class A3Oracle(unittest.TestCase):
    def check(self, text=PROBE, oracle=ORACLE, abi="x86_64"):
        with patch("experiment_ndk_jni_ghidra_recovery_v0.digest",return_value="example"):
            return evaluate(text,oracle,"synthetic.so",abi)
    def test_callgraph_valid_but_not_behavioral(self):
        r=self.check()
        self.assertEqual(r["helpers_identified_against_independent_symbol_truth"],2)
        self.assertFalse(r["helper_semantics_independently_reconstructed"])
    def test_swap_wrong_helper_rejected(self):
        with self.assertRaisesRegex(ValueError,"entries"):
            self.check(PROBE.replace("1010","1030"))
    def test_missing_helper_rejected(self):
        with self.assertRaises(ValueError):
            self.check(PROBE.replace("AAR_A3_CALLEE=1020|21|true\n","").replace("CALLS=2","CALLS=1"))
    def test_wrong_abi_rejected(self):
        with self.assertRaisesRegex(ValueError,"cross-ABI"):
            self.check(abi="aarch64")
    def test_decompiler_failure_rejected(self):
        with self.assertRaisesRegex(ValueError,"not decompiled"):
            self.check(PROBE.replace("21|true","21|false"))
    def test_repeated_address_rejected(self):
        with self.assertRaises(ValueError):
            self.check(PROBE.replace("1020|21|true","1010|21|true"))
    def test_oracle_digest_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError,"digest"):
            with patch("experiment_ndk_jni_ghidra_recovery_v0.digest",return_value="different"):
                evaluate(PROBE,ORACLE,"synthetic.so","x86_64")
if __name__=="__main__":
    unittest.main()
