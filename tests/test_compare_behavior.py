import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "compare_behavior.py"

OBS = """canonical_b64=YWxwaGE9b25lCmJldGE9c2Vjb25kCmJldGE9dHdvIHdvcmRzCg==
sha256=1c94d71cfe92db05be151ffe400360ce0b955ff16e6e40f68c4db54b3d98c73f
record_count=3
unique_key_count=2
"""

class BehaviorComparisonTests(unittest.TestCase):
    def test_match(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            original = td / "original.txt"
            candidate = td / "candidate.txt"
            out = td / "out.json"
            original.write_text(OBS)
            candidate.write_text(OBS)
            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--original", str(original),
                "--candidate", str(candidate),
                "--candidate-state", "executed",
                "--out", str(out),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["status"], "BEHAVIOR-MATCH")
            self.assertTrue(all(x["equal"] for x in doc["comparison"].values()))

    def test_non_executable_candidate_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            original = td / "original.txt"
            out = td / "out.json"
            original.write_text(OBS)
            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--original", str(original),
                "--candidate-state", "compile-failed",
                "--candidate-detail", "javac failed",
                "--out", str(out),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["status"], "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
