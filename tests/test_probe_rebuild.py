import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "probe_rebuild.py"


class RebuildProbeTests(unittest.TestCase):
    def test_records_successful_build_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            project = root / "project"
            project.mkdir()
            report = root / "report.json"

            command = [
                sys.executable,
                "-c",
                "import pathlib; p=pathlib.Path('app/build/outputs/apk/debug'); p.mkdir(parents=True); (p/'app-debug.apk').write_bytes(b'apk')",
            ]
            cp = subprocess.run(
                [sys.executable, str(SCRIPT), "--project", str(project), "--output", str(report), "--", *command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(report.read_text())
            self.assertEqual(doc["status"], "REBUILDABLE-AS-EXPORTED")
            self.assertFalse(doc["repair_applied"])
            self.assertEqual(len(doc["outputs"]["apks"]), 1)

    def test_records_failure_without_turning_probe_into_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            project = root / "project"
            project.mkdir()
            report = root / "report.json"

            cp = subprocess.run(
                [sys.executable, str(SCRIPT), "--project", str(project), "--output", str(report), "--", sys.executable, "-c", "raise SystemExit(7)"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(report.read_text())
            self.assertEqual(doc["returncode"], 7)
            self.assertEqual(doc["status"], "NOT-REBUILDABLE-AS-EXPORTED")
            self.assertFalse(doc["repair_applied"])


if __name__ == "__main__":
    unittest.main()
