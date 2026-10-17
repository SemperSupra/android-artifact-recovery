"""Negative tests for license-gated preinstalled SDK import; no actual SDK needed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_aar_image_parity import P, ROOT

spec = importlib.util.spec_from_file_location("aar_sdk_stage", ROOT/"tools"/"aar_sdk_stage.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class PrivateSdkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sdk = Path(self.temp.name) / "sdk"
        self.output = Path(self.temp.name) / "staged"
        f = {
            "build-tools/37.0.0/aapt2": b"aapt2-source",
            "build-tools/37.0.0/dexdump": b"dexdump-source",
            "build-tools/37.0.0/apksigner": b"apksigner-source",
            "build-tools/37.0.0/d8": b"d8-script",
            "platforms/android-35/android.jar": b"android-jar",
        }
        for rel,data in f.items():
            p = self.sdk/rel
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(data)
        expected={rel:hashlib.sha256(data).hexdigest() for rel,data in f.items() if rel in S.ROOT_FILES}
        patch=mock.patch.object(S,"ROOT_FILES",expected)
        patch.start()
        self.addCleanup(patch.stop)
        patch2=mock.patch.object(S.sys,"platform","linux")
        patch2.start()
        self.addCleanup(patch2.stop)
        patch3=mock.patch.object(S.platform,"machine",return_value="x86_64")
        patch3.start()
        self.addCleanup(patch3.stop)

    def test_stage_exact_subset_with_no_license_or_paths(self):
        m=S.stage(self.sdk,self.output)
        self.assertFalse(m["registry_publication_authorized"])
        self.assertEqual(m["license_reuse_or_redistribution"],"UNREVIEWED")
        self.assertEqual(len(m["tool_sha256"]),3)
        self.assertNotIn(str(self.sdk),json.dumps(m))
        self.assertTrue((self.output/"platforms/android-35/android.jar").exists())
        self.assertEqual(m["android_platform"],"android-35")

    def test_reject_modified_sdk_hash_and_no_partial_staging(self):
        (self.sdk/"build-tools/37.0.0/aapt2").write_bytes(b"substitution")
        with self.assertRaisesRegex(ValueError,"hash mismatch"):
            S.stage(self.sdk,self.output)
        self.assertFalse(self.output.exists())

    def test_no_overwrite(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError,"already exists"):
            S.stage(self.sdk,self.output)

    def test_reject_any_symlink(self):
        (self.sdk/"build-tools/37.0.0/unsafe").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError,"symlink"):
            S.stage(self.sdk,self.output)

    def test_reject_arm_host_for_exact_native_sdk(self):
        with mock.patch.object(S.platform,"machine",return_value="aarch64"):
            with self.assertRaisesRegex(ValueError,"amd64"):
                S.stage(self.sdk,self.output)

    def test_profile_declares_no_distribution_rights(self):
        cfg=P.contract(P.CONTRACT)
        self.assertFalse(cfg["checks"]["sdk_redistribution"])
        self.assertIn("android-sdk-redistribution",cfg["profiles"]["sdk-mounted"]["prohibits"])


if __name__ == "__main__":
    unittest.main()
