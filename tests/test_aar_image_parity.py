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

    def test_explicit_architecture_selection(self):
        argv = L.build_argv(engine="docker", image=self.IMAGE, action="probe",
                            source=None, output=None, platform="linux/amd64")
        self.assertEqual(argv[argv.index("--platform")+1], "linux/amd64")
        with self.assertRaisesRegex(ValueError, "unsupported OCI"):
            L.build_argv(engine="docker", image=self.IMAGE, action="probe",
                         source=None, output=None, platform="windows/amd64")

    def test_artifact_read_only_output_separate(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            source = root / "in" / "fixture.apk"
            source.parent.mkdir()
            source.write_bytes(b"ZIP")
            output = root / "out"
            argv = L.build_argv(engine="docker", image=self.IMAGE, action="run",
                                source=source, output=output, prepare_output=False)
            self.assertFalse(output.exists())
            self.assertEqual(argv.count("--mount"), 2)
            self.assertTrue(any("readonly" in a and "dst=/inputs/artifact.apk" in a for a in argv))
            self.assertFalse(any("src="+str(source.parent.resolve())+"," in a for a in argv))
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


    def test_plan_no_evidence_mount_or_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            source=root/"source.apk"
            source.write_bytes(b"specimen")
            evidence=root/"evidence"
            argv=L.build_argv(engine="docker", image=self.IMAGE, action="plan",
                              source=source, output=evidence)
            self.assertFalse(evidence.exists())
            self.assertEqual(argv.count("--mount"),1)
            self.assertEqual(argv[argv.index("--mount")+1],
                             f"type=bind,src={source.resolve()},dst=/inputs/artifact.apk,readonly")

    def test_verify_requires_existing_evidence_mounted_readonly(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            source=root/"source.apk"
            source.write_bytes(b"specimen")
            evidence=root/"evidence"
            with self.assertRaisesRegex(ValueError,"existing output directory"):
                L.build_argv(engine="docker",image=self.IMAGE,action="verify",
                             source=source,output=evidence)
            evidence.mkdir()
            argv=L.build_argv(engine="docker",image=self.IMAGE,action="verify",
                              source=source,output=evidence)
            self.assertEqual(argv.count("--mount"),2)
            self.assertIn(f"type=bind,src={evidence.resolve()},dst=/work,readonly",argv)

    def test_reject_input_and_output_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            source=root/"original.apk"
            source.write_bytes(b"specimen")
            alias=root/"alias.apk"
            alias.symlink_to(source)
            with self.assertRaisesRegex(ValueError,"input artifact symlink"):
                L.build_argv(engine="docker",image=self.IMAGE,action="plan",
                             source=alias,output=root/"out")
            real=root/"real"
            real.mkdir()
            linked=root/"linked"
            linked.symlink_to(real,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,"output symlink"):
                L.build_argv(engine="docker",image=self.IMAGE,action="run",
                             source=source,output=linked)

    def test_no_sibling_file_exposure(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            source=root/"allowed.apk"
            private=root/"other-sensitive-thing.txt"
            source.write_bytes(b"fixture")
            private.write_text("secret",encoding="utf-8")
            argv=L.build_argv(engine="docker",image=self.IMAGE,action="run",
                              source=source,output=root/"results",prepare_output=False)
            mounts=[argv[i+1] for i,x in enumerate(argv) if x=="--mount"]
            self.assertEqual(len(mounts),2)
            self.assertTrue(mounts[0].startswith("type=bind,src="+str(source.resolve())+","))
            self.assertNotIn(str(private),str(mounts))
            self.assertNotIn("src="+str(root.resolve())+",",str(mounts))

    def test_probe_specific_profile_no_unneeded_mounts(self):
        argv=L.build_argv(engine="docker",image=self.IMAGE,action="probe",
                          source=None,output=None,profile="sdk-mounted",
                          platform="linux/amd64")
        self.assertEqual(argv[-2:],["--profile","sdk-mounted"])
        self.assertNotIn("--mount",argv)
        with self.assertRaisesRegex(ValueError,"probe-only"):
            L.build_argv(engine="docker",image=self.IMAGE,action="run",
                         source=pathlib.Path("missing.apk"),output=pathlib.Path("evidence"),
                         profile="sdk-mounted")

    def test_comma_delimited_mount_path_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            source=root/"fixture,evil.apk"
            source.write_bytes(b"specimen")
            with self.assertRaisesRegex(ValueError,"unsupported delimiter"):
                L.build_argv(engine="docker",image=self.IMAGE,action="plan",
                             source=source,output=root/"out")

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
