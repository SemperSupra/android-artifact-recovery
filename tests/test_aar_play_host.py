import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock
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

    def test_adb_device_parser_preserves_offline_to_device_state(self):
        self.assertEqual(
            HOST.parse_adb_devices(
                "List of devices attached\nemulator-5554\toffline\nemulator-5556\tdevice product:sdk\n"
            ),
            {"emulator-5554": "offline", "emulator-5556": "device"},
        )

    def test_emulator_venue_failure_classifies_hvf_unsupported(self):
        self.assertEqual(
            HOST.emulator_venue_failure("HVF error: HV_UNSUPPORTED\nfailed to initialize HVF"),
            "hypervisor_framework_unavailable",
        )
        self.assertIsNone(HOST.emulator_venue_failure("normal emulator startup"))

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

    def test_existing_healthy_runtime_plans_as_noop_without_license_reacceptance(self):
        with tempfile.TemporaryDirectory() as td:
            state = pathlib.Path(td)
            runtime = state / "runtime" / "linux-x86_64"
            config = runtime / "avd" / "aar-play-api35-x86_64.avd" / "config.ini"
            config.parent.mkdir(parents=True)
            config.write_text("hw.keyboard=yes\n", encoding="utf-8")
            lock = {"profiles": {"linux-x86_64": {"os": "linux", "arch": "x86_64", "image_abi": "x86_64", "acceleration": "KVM"}}}
            identity = {"identity_sha256": "1" * 64}
            with mock.patch.object(HOST, "load_lock", return_value=lock), mock.patch.object(
                HOST, "host_profile", return_value=("linux-x86_64", lock["profiles"]["linux-x86_64"])
            ), mock.patch.object(HOST, "critical_identity", return_value=identity), mock.patch.object(
                HOST, "sha256_file", return_value="2" * 64
            ):
                receipt = HOST.create_plan(state, False)
            self.assertEqual(receipt["status"], "no-op-planned")
            self.assertEqual(receipt["evidence"]["plan_mode"], "verify-existing")
            plan = HOST.read_json(pathlib.Path(receipt["evidence"]["plan"]))
            self.assertEqual(plan["status"], "applied")
            self.assertEqual(plan["mutations"], [])
            self.assertEqual(plan["toolchain_identity"], identity)



    def test_optional_memory_sensor_fails_open_on_probe_timeout(self):
        with mock.patch.object(
            HOST,
            "run",
            side_effect=HOST.AarHostError("command timeout: powershell.exe", failure_type="timeout"),
        ):
            self.assertIsNone(HOST.memory_bytes("windows"))


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


    def test_windows_runtime_process_cleanup_is_scoped_to_runtime_path(self):
        result = mock.Mock(
            returncode=0,
            stdout='[{"Pid":123,"Path":"C:\\\\runtime\\\\sdk\\\\emulator\\\\emulator.exe","Stopped":true}]',
            stderr="",
        )
        with mock.patch.object(HOST.platform, "system", return_value="Windows"), mock.patch.object(
            HOST.shutil, "which", return_value="powershell.exe"
        ), mock.patch.object(HOST, "run", return_value=result) as runner:
            observed = HOST.stop_runtime_processes_windows(pathlib.Path(r"C:\runtime"))
        self.assertTrue(observed["attempted"])
        self.assertEqual(len(observed["terminated"]), 1)
        argv = runner.call_args.args[0]
        self.assertIn("powershell.exe", argv[0])
        command = argv[-1]
        self.assertIn(r"C:\runtime", command)
        self.assertIn("ExecutablePath.StartsWith", command)
        self.assertNotIn("Get-Process emulator", command)

    def test_linux_runtime_ownership_restore_is_narrow(self):
        result = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(HOST.os, "getuid", return_value=1001, create=True), mock.patch.object(
            HOST.os, "getgid", return_value=1002, create=True
        ), mock.patch.object(HOST, "run", return_value=result) as runner:
            observed = HOST.restore_runtime_ownership(pathlib.Path("/tmp/aar-runtime"))
        self.assertTrue(observed["passed"])
        argv = runner.call_args.args[0]
        self.assertEqual(argv[:4], ["sudo", "-n", "chown", "-R"])
        self.assertIn("1001:1002", argv)
        self.assertNotIn("-E", argv)


if __name__ == "__main__":
    unittest.main()
