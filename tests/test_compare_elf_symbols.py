import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "compare_elf_symbols.py"


class ElfSymbolCorrespondenceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc") and shutil.which("readelf"), "compiler/readelf required")
    def test_reports_overlap_without_identity_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            ref_c = root / "ref.c"
            target_c = root / "target.c"
            ref_c.write_text(
                "int alpha(int x){return x+1;}\n"
                "int beta(int x){return x*2;}\n"
            )
            target_c.write_text(
                "int alpha(int x){return x+99;}\n"
                "int beta(int x){return x*3;}\n"
                "int gamma(int x){return x-1;}\n"
            )
            ref = root / "libref.so"
            target = root / "libtarget.so"
            for src, out in ((ref_c, ref), (target_c, target)):
                cp = subprocess.run(
                    ["cc", "-shared", "-fPIC", "-O2", str(src), "-o", str(out)],
                    text=True, capture_output=True
                )
                self.assertEqual(cp.returncode, 0, cp.stderr)

            report = root / "report.json"
            cp = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--reference", str(ref),
                    "--target", str(target),
                    "--out", str(report),
                ],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(report.read_text())
            self.assertEqual(doc["overlap"]["count"], 2)
            self.assertEqual(doc["overlap"]["reference_coverage"], 1.0)
            self.assertAlmostEqual(doc["overlap"]["target_coverage"], 2 / 3)
            self.assertFalse(doc["policy"]["establishes_exact_identity"])
            self.assertFalse(doc["policy"]["establishes_unmodified_state"])
            self.assertFalse(doc["policy"]["authorizes_residual_suppression"])

    @unittest.skipUnless(shutil.which("cc") and shutil.which("readelf"), "compiler/readelf required")
    def test_zero_overlap_is_valid_evidence_not_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            a = root / "a.c"
            b = root / "b.c"
            a.write_text("int one(void){return 1;}\n")
            b.write_text("int two(void){return 2;}\n")
            so_a = root / "a.so"
            so_b = root / "b.so"
            subprocess.check_call(["cc", "-shared", "-fPIC", str(a), "-o", str(so_a)])
            subprocess.check_call(["cc", "-shared", "-fPIC", str(b), "-o", str(so_b)])
            report = root / "report.json"
            cp = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--reference", str(so_a),
                    "--target", str(so_b),
                    "--out", str(report),
                ],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(report.read_text())
            self.assertEqual(doc["overlap"]["count"], 0)


if __name__ == "__main__":
    unittest.main()
