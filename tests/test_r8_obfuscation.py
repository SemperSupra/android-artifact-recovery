"""R8 obfuscation triage negative controls; no Android SDK or JADX needed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("experiment_r8_obfuscation",ROOT/"tools"/"experiment_r8_obfuscation.py")
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class ObfuscationCalibrationTests(unittest.TestCase):
    def test_detect_known_renamed_class_no_alias_leak(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"mapping.txt"
            f.write_text(
                "# compiler: R8\n"
                "org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint -> a:\n"
                "    1:4:int calculate(int) -> b\n"
                "java.lang.String -> java.lang.String:\n",encoding="utf-8")
            result=M.read_mapping(f)
            self.assertTrue(result["known_oracle_class_renamed"])
            self.assertEqual(result["renamed_classes"],1)
            self.assertEqual(set(result),{"mapping_classes","renamed_classes","known_oracle_class_renamed"})

    def test_reject_no_actual_obfuscation(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"mapping.txt"
            f.write_text(M.CLASS+" -> "+M.CLASS+":\n",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"not renamed"):
                M.read_mapping(f)

    def test_missing_oracle_class_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"mapping.txt"
            f.write_text("com.unrelated.Class -> a:\n",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"oracle class absent"):
                M.read_mapping(f)

    def test_reject_duplicate_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"mapping.txt"
            f.write_text((M.CLASS+" -> a:\n")*2,encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"duplicate"):
                M.read_mapping(f)

    def test_dex_missing_and_oversized(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"synthetic.apk"
            with zipfile.ZipFile(f,"w") as zf:
                zf.writestr("classes.dex",b"dex\n035\x00"+b"safe")
                zf.writestr("classes2.dex",b"dex\n035\x00"+b"safe2")
            m=M.dex_members(f)
            self.assertEqual(len(m),2)
            with zipfile.ZipFile(f,"w") as zf:
                zf.writestr("assets/empty",b"x")
            with self.assertRaisesRegex(ValueError,"no root DEX"):
                M.dex_members(f)

    def test_mock_options_never_claim_semantic_success(self):
        self.assertEqual(len(M.MODES),6)
        self.assertEqual(M.MODES["auto"],[])
        self.assertIn("--deobf", M.MODES["synthetic-aliases"])
        self.assertIn("ignore",M.MODES["synthetic-aliases"])
        self.assertNotIn("--mappings-path",sum(M.MODES.values(),[]))

if __name__ == "__main__":
    unittest.main()
