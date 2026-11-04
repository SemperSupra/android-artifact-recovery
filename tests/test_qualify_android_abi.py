"""Synthetic native-ABI claim controls; no raw APKs or credentials."""
import unittest
from tools.qualify_android_abi import qualify_native_abi


class AndroidAbiQualificationTests(unittest.TestCase):
    def test_real_world_arm64_request_with_arm32_split_is_mismatch(self):
        actual = {"summary": {"abis": ["armeabi-v7a"], "kinds": {"elf": 12}}}
        a = qualify_native_abi(actual, "arm64-v8a")
        self.assertEqual(a["status"], "NATIVE_ABI_MISMATCH")
        self.assertEqual(a["observed_native_abis"], ["armeabi-v7a"])
        self.assertEqual(a["observed_elf_count"], 12)
        self.assertFalse(a["requested_native_abi_verified"])

    def test_arm64_native_split_matches(self):
        a = qualify_native_abi({"summary": {"abis": ["arm64-v8a"], "kinds": {"elf": 1}}}, "arm64-v8a")
        self.assertEqual(a["status"], "NATIVE_ABI_MATCH")
        self.assertTrue(a["requested_native_abi_verified"])

    def test_multisplit_mixed_native_abis_can_satisfy_requested_arch(self):
        a = qualify_native_abi({"summary": {"abis": ["armeabi-v7a", "arm64-v8a"]}}, "arm64-v8a")
        self.assertEqual(a["status"], "NATIVE_ABI_MATCH")

    def test_no_native_code_is_unknown_not_verified(self):
        a = qualify_native_abi({"summary": {"abis": [], "kinds": {"elf": 0}}}, "arm64-v8a")
        self.assertEqual(a["status"], "NATIVE_ABI_NOT_ESTABLISHED")
        self.assertFalse(a["requested_native_abi_verified"])

    def test_missing_characterization_is_unknown(self):
        a = qualify_native_abi(None, "arm64-v8a")
        self.assertEqual(a["status"], "NATIVE_ABI_NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
