import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "summarize_recovery_evidence.py"
ART = "a" * 64

class EvidenceSummaryTests(unittest.TestCase):
    def write(self, root, name, doc):
        p = root / name
        p.write_text(json.dumps(doc))
        return p

    def test_preserves_unknowns_and_scoped_confidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            static = self.write(root, "static.json", {
                "schema": "aar-static-recovery/v0",
                "artifact": {"sha256": ART},
                "status": "PARTIAL",
                "tools": {
                    "jadx": {"returncode": 0, "stdout": "1.5.6\n"},
                },
            })
            rebuild = self.write(root, "rebuild.json", {
                "schema": "aar-rebuild-feasibility/v0",
                "status": "NOT-REBUILDABLE-AS-EXPORTED",
                "command": ["gradle", "--no-daemon", "assembleDebug"],
            })
            behavior = self.write(root, "behavior.json", {
                "schema": "aar-behavior-comparison/v0",
                "status": "UNKNOWN",
                "reason": "candidate compile failed",
            })
            out = root / "summary.json"

            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--artifact-sha256", ART,
                "--static", str(static),
                "--rebuild", str(rebuild),
                "--behavior", str(behavior),
                "--out", str(out),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["schema"], "aar-evidence-summary/v0")
            self.assertGreaterEqual(len(doc["unknowns"]), 2)
            by_id = {x["id"]: x for x in doc["claims"]}
            self.assertEqual(by_id["static.representations"]["state"], "PARTIAL")
            self.assertEqual(by_id["rebuild.feasibility"]["confidence"], "high")
            self.assertEqual(by_id["behavior.declared-vector"]["confidence"], "unknown")

    def test_rejects_static_artifact_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            static = self.write(root, "static.json", {
                "schema": "aar-static-recovery/v0",
                "artifact": {"sha256": "b" * 64},
                "status": "PASS",
            })
            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--artifact-sha256", ART,
                "--static", str(static),
                "--out", str(root / "out.json"),
            ], text=True, capture_output=True)
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn("SHA mismatch", cp.stderr)

if __name__ == "__main__":
    unittest.main()
