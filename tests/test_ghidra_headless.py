import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "tools" / "analyzers" / "ghidra_headless.py"

class GhidraAdapterTests(unittest.TestCase):
    def test_rejects_missing_ghidra(self):
        cp = subprocess.run([
            sys.executable, str(WRAPPER),
            "--ghidra-home", "/definitely/not/ghidra",
            "--binary", str(ROOT / "README.md"),
            "--script-dir", str(ROOT / "tools" / "ghidra"),
            "--out", "/tmp/aar-ghidra-never.json",
            "--log", "/tmp/aar-ghidra-never.log",
        ], text=True, capture_output=True)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("analyzeHeadless not found", cp.stderr)

if __name__ == "__main__":
    unittest.main()
