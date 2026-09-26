import importlib.util
import pathlib
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("aar_play_host", ROOT / "tools" / "aar_play_host.py")
assert SPEC and SPEC.loader
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class PlayHostTests(unittest.TestCase):
    def test_supported_host_matrix(self):
        lock = HOST.load_lock()
        cases = [
            ("Windows", "AMD64", "windows-x86_64", "WHPX"),
            ("Linux", "x86_64", "linux-x86_64", "KVM"),
            ("Darwin", "x86_64", "macos-x86_64", "Hypervisor.Framework"),
            ("Darwin", "arm64", "macos-arm64", "Hypervisor.Framework"),
        ]
        for system, machine, expected, accel in cases:
            key, profile = HOST.host_profile(lock, system, machine)
            self.assertEqual(key, expected)
            self.assertEqual(profile["acceleration"], accel)

    def test_unsupported_arm_guards(self):
        lock = HOST.load_lock()
        for system, machine in (("Windows", "arm64"), ("Linux", "aarch64")):
            with self.assertRaises(HOST.AarHostError) as ctx:
                HOST.host_profile(lock, system, machine)
            self.assertEqual(ctx.exception.failure_type, "unsupported_host")
            self.assertEqual(ctx.exception.exit_code, HOST.EXIT_UNSUPPORTED)

    def test_lock_has_host_specific_pinned_archives(self):
        lock = HOST.load_lock()
        for key in lock["profiles"]:
            for section in (
                lock["java"]["archives"][key],
                lock["android"]["cmdline_tools"]["archives"][key],
                lock["android"]["emulator"]["archives"][key],
            ):
                self.assertTrue(section["url"].startswith("https://"))
                self.assertEqual(len(section["sha256"]), 64)

    def test_acceleration_classifier_is_fail_closed(self):
        self.assertTrue(HOST.emulator_accel_ok("WHPX is installed and usable.", 0))
        self.assertTrue(HOST.emulator_accel_ok("KVM (version 12) is installed and usable.", 0))
        self.assertFalse(HOST.emulator_accel_ok("acceleration is not supported", 0))
        self.assertFalse(HOST.emulator_accel_ok("anything", 1))

    def test_safe_zip_rejects_parent_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape", "bad")
            with self.assertRaises(HOST.AarHostError):
                HOST.safe_extract_zip(archive, root / "out")

    def test_plan_requires_explicit_license_acceptance(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(HOST.AarHostError) as ctx:
                HOST.create_plan(pathlib.Path(td), False)
            self.assertEqual(ctx.exception.failure_type, "license_acceptance_required")


    def test_interface_contract_is_discoverable_for_all_audiences(self):
        contract = HOST.interface_contract()
        self.assertEqual(
            set(contract["audiences"]),
            {"human", "automation", "agent"},
        )
        self.assertEqual(
            contract["lifecycle"],
            ["observe", "plan", "apply", "verify", "cleanup"],
        )
        self.assertEqual(contract["audiences"]["agent"]["discover"], "contract --format json")

    def test_linux_sudo_emulator_prefix_is_narrow_and_explicit(self):
        env = {
            "HOME": "/home/runner",
            "PATH": "/tools",
            "ANDROID_AVD_HOME": "/tmp/avd",
            "JAVA_HOME": "/tmp/jdk",
        }
        prefix = HOST.emulator_command_prefix(env, True)
        self.assertEqual(prefix[:3], ["sudo", "-n", "env"])
        self.assertIn("HOME=/home/runner", prefix)
        self.assertIn("ANDROID_AVD_HOME=/tmp/avd", prefix)
        self.assertNotIn("-E", prefix)


if __name__ == "__main__":
    unittest.main()
