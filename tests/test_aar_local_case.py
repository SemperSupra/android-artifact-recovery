"""Source-known, zero-secret tests for the local case admission boundary."""
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "aar_local_case.py"
CHARACTERIZER = ROOT / "tools" / "characterize_android_artifact.py"


def fixture() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", b"dex\n035\x00" + b"golden" * 10)
        z.writestr("assets/protocol.js", b"const value = 1;\n")
        z.writestr("assets/opaque.bin", b"\x00asm\x01\x00\x00\x00")
    return out.getvalue()


class LocalCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.artifact = self.root / "golden.apk"
        self.artifact.write_bytes(fixture())
        self.work = self.root / "cases"

    def invoke(self, command, artifact=None, *extra, characterizer=None):
        return subprocess.run([
            sys.executable, str(SCRIPT), command, str(artifact or self.artifact),
            "--work-root", str(self.work),
            "--characterizer", str(characterizer or CHARACTERIZER), *extra,
        ], capture_output=True, text=True, check=False, timeout=30)

    def test_probe_requires_no_artifact_or_endpoint(self):
        cp = subprocess.run([sys.executable, str(SCRIPT), "probe"],
                            capture_output=True, text=True, timeout=30)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("PRESENCE_ONLY_NOT_MODEL_OR_TOOL_PASS", cp.stdout)
        names = json.loads(cp.stdout)["executables"]
        for name in ("pi-bigmac", "aider-bigmac", "goose-bigmac",
                     "vibe-bigmac", "opencode-bigmac", "qwen-bigmac"):
            self.assertIn(name, names)

    def test_plan_is_read_only(self):
        cp = self.invoke("plan")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(json.loads(cp.stdout)["planned_stage"], "CHARACTERIZED_ONLY")
        self.assertFalse(self.work.exists())

    def test_integrated_characterization_and_independent_verify(self):
        cp = self.invoke("run")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        key = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        case = self.work / key
        manifest = json.loads((case / "receipt.json").read_text())
        self.assertEqual(manifest["status"], "PASS")
        self.assertEqual(manifest["stage"], "CHARACTERIZED_ONLY")
        self.assertIn("runtime_behavior", manifest["unknowns"])
        self.assertEqual(manifest["input"]["sha256"], key)
        result = json.loads((case / "characterization.json").read_text())
        self.assertEqual(result["summary"]["kinds"]["dex"], 1)
        self.assertEqual(result["summary"]["kinds"]["wasm"], 1)
        self.assertEqual(self.invoke("verify").returncode, 0)

    def test_resumption_does_not_clobber_existing_evidence(self):
        self.assertEqual(self.invoke("run").returncode, 0)
        key = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        receipt = self.work / key / "receipt.json"
        original = receipt.read_bytes()
        self.assertEqual(self.invoke("run").returncode, 0)
        self.assertEqual(receipt.read_bytes(), original)

    def test_tampered_result_fails_closed_without_overwriting(self):
        self.assertEqual(self.invoke("run").returncode, 0)
        key = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        evidence = self.work / key / "characterization.json"
        evidence.write_text('{"schema":"forged"}')
        self.assertEqual(self.invoke("run").returncode, 2)
        self.assertEqual(self.invoke("verify").returncode, 2)
        self.assertIn("forged", evidence.read_text())

    def test_tool_revision_change_invalidates_existing_receipt(self):
        self.assertEqual(self.invoke("run").returncode, 0)
        revised = self.root / "altered_characterizer.py"
        shutil.copy(CHARACTERIZER, revised)
        revised.write_text(revised.read_text() + "\n# changed tool source\n")
        cp = self.invoke("verify", characterizer=revised)
        self.assertEqual(cp.returncode, 2)
        self.assertIn("mismatch", cp.stderr)

    def test_source_change_does_not_reuse_existing_case(self):
        self.assertEqual(self.invoke("run").returncode, 0)
        key_before = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.artifact.write_bytes(fixture() + b"non-executable-padding")
        cp = self.invoke("run")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        key_after = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.assertNotEqual(key_before, key_after)
        self.assertTrue((self.work / key_before / "receipt.json").exists())
        self.assertTrue((self.work / key_after / "receipt.json").exists())

    def test_traversal_rejected_before_workdir_creation(self):
        with zipfile.ZipFile(self.artifact, "w") as z:
            z.writestr("../outside.dex", b"dex\n035\x00")
        cp = self.invoke("run")
        self.assertEqual(cp.returncode, 2)
        self.assertIn("unsafe", cp.stderr)
        self.assertFalse(self.work.exists())

    def test_duplicate_member_rejected(self):
        with zipfile.ZipFile(self.artifact, "w") as z:
            z.writestr("dup.dex", b"dex\n035\x00")
            z.writestr("dup.dex", b"dex\n035\x00")
        cp = self.invoke("run")
        self.assertEqual(cp.returncode, 2)
        self.assertIn("duplicate", cp.stderr)

    def test_decompression_amplification_rejected(self):
        with zipfile.ZipFile(self.artifact, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("assets/large.bin", b"Z" * 100_000)
        cp = self.invoke("run", None, "--max-ratio", "10")
        self.assertEqual(cp.returncode, 2)
        self.assertIn("ratio", cp.stderr)

    def test_uncompressed_budget_rejected(self):
        cp = self.invoke("run", None, "--max-total-bytes", "10")
        self.assertEqual(cp.returncode, 2)
        self.assertIn("budget", cp.stderr)

    def test_xapk_multi_split_census(self):
        xapk = self.root / "synthetic.xapk"
        with zipfile.ZipFile(xapk, "w") as z:
            z.writestr("base.apk", fixture())
            z.writestr("split_config.en.apk", fixture())
        cp = self.invoke("run", xapk)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        key = hashlib.sha256(xapk.read_bytes()).hexdigest()
        report = json.loads((self.work / key / "characterization.json").read_text())
        self.assertEqual(report["summary"]["apk_count"], 2)

    def test_crc_corruption_rejected(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("classes.dex", b"dex\n035\x00ABCDEF")
        blob = bytearray(raw.getvalue())
        pos = blob.find(b"ABCDEF")
        self.assertGreaterEqual(pos, 0)
        blob[pos] ^= 1
        self.artifact.write_bytes(blob)
        cp = self.invoke("run")
        self.assertEqual(cp.returncode, 2)
        self.assertIn("corrupt", cp.stderr)

    def test_unknown_suffixed_input_rejected(self):
        path = self.root / "specimen.exe"
        path.write_bytes(fixture())
        cp = self.invoke("run", path)
        self.assertEqual(cp.returncode, 2)
        self.assertIn("unsupported", cp.stderr)


if __name__ == "__main__":
    unittest.main()
