"""OCI tool profile and host launcher negative controls; no Docker daemon needed."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


P = module("aar_image_parity", ROOT / "tools" / "aar_image_parity.py")
L = module("aar_container_launch", ROOT / "tools" / "aar_container_launch.py")


def stamped(profile="python-core", arch="x86_64", digest="a" * 64):
    doc = {"schema": P.SCHEMA, "profile": profile, "platform": "linux",
           "architecture": arch, "contract_sha256": "b" * 64,
           "tools": {"python": {"sha256": digest, "path": "/usr/local/bin/python"}},
           "claims": {"apk_source_recovery":"UNKNOWN"}}
    doc["fingerprint_sha256"] = hashlib.sha256(P.canonical(doc).encode()).hexdigest()
    return doc


class ImageParityContractTests(unittest.TestCase):
    def test_contract_supported_profiles_and_explicit_unknowns(self):
        cfg = P.contract(P.CONTRACT)
        self.assertEqual(cfg["platform"], "linux")
        self.assertNotIn("aapt2", cfg["profiles"]["java-static"]["requires"])
        self.assertIn("apktool", cfg["profiles"]["java-static"]["requires"])
        self.assertTrue(cfg["checks"]["immutable_image_digest"])

    def test_identical_observations_pass(self):
        r = P.compare(stamped(), stamped())
        self.assertEqual(r["state"], "PASS_IDENTICAL_OBSERVED_CAPABILITIES")

    def test_byte_drift_fails(self):
        a = stamped()
        b = stamped(digest="c" * 64)
        self.assertEqual(P.compare(a, b)["drift"], ["tools"])

    def test_other_architecture_not_exact_parity(self):
        self.assertIn("architecture", P.compare(stamped(), stamped(arch="aarch64"))["drift"])

    def test_tampered_receipt_fails_closed(self):
        changed = stamped()
        changed["tools"]["python"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "tampered"):
            P.compare(stamped(), changed)

    def test_tool_sha_contract_mismatch_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = pathlib.Path(tmp) / "candidate"
            f.write_bytes(b"safe")
            cfg = {"platform":sys.platform,
                   "profiles":{"python-core":{"requires":["candidate"]}},
                   "tools":{"candidate":{"path":str(f), "sha256":"0"*64}}}
            with self.assertRaisesRegex(ValueError, "digest differs"):
                P.observe("python-core", cfg)


class ImageLauncherTests(unittest.TestCase):
    IMAGE = "ghcr.io/example/aar-tools@sha256:" + "a" * 64

    def test_production_requires_digest(self):
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            L.build_argv(engine="docker", image="aar:latest", action="probe",
                         source=None, output=None)

    def test_probe_is_offline_readonly_without_host_mounts(self):
        argv = L.build_argv(engine="docker", image=self.IMAGE, action="probe",
                            source=None, output=None)
        self.assertIn("none", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--mount", argv)
        self.assertIn("tools/aar_image_parity.py", argv)

    def test_artifact_read_only_output_separate(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            source = root / "in" / "fixture.apk"
            source.parent.mkdir()
            source.write_bytes(b"ZIP")
            output = root / "out"
            argv = L.build_argv(engine="docker", image=self.IMAGE, action="plan",
                                source=source, output=output, prepare_output=False)
            self.assertFalse(output.exists())
            self.assertEqual(argv.count("--mount"), 2)
            self.assertTrue(any("readonly" in a and "/inputs" in a for a in argv))
            self.assertIn("--network", argv)
            self.assertNotIn("host", argv)

    def test_input_must_exist(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                L.build_argv(engine="docker", image=self.IMAGE, action="run",
                             source=pathlib.Path(td)/"missing.apk",
                             output=pathlib.Path(td)/"out")

    def test_reject_input_inside_output(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "case.apk"
            path.write_bytes(b"safe")
            with self.assertRaisesRegex(ValueError, "output"):
                L.build_argv(engine="docker", image=self.IMAGE, action="run",
                             source=path, output=path.parent)

    def test_cli_dry_run_requires_no_docker(self):
        command = [sys.executable, str(ROOT/"tools"/"aar_container_launch.py"),
                   "probe", "--image", self.IMAGE, "--dry-run"]
        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertFalse(doc["executed"])
        self.assertEqual(doc["network"], "none")


if __name__ == "__main__":
    unittest.main()
