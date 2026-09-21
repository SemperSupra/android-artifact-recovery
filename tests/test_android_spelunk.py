import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "android_spelunk.py"


FAKE_ADB = r"""#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ["version"]:
    print("Android Debug Bridge version 1.0.41")
    raise SystemExit(0)
if args and args[0] == "-s":
    args = args[2:]
table = {
    ("get-state",): (0, "device\n", ""),
    ("get-serialno",): (0, "emulator-5554\n", ""),
    ("shell","getprop"): (0, "[ro.product.cpu.abi]: [x86_64]\n", ""),
    ("shell","uname","-a"): (0, "Linux localhost 6.1 test\n", ""),
    ("shell","id"): (0, "uid=2000(shell) gid=2000(shell)\n", ""),
    ("shell","cat","/proc/cpuinfo"): (0, "processor : 0\n", ""),
    ("shell","cat","/proc/meminfo"): (0, "MemTotal: 4096000 kB\n", ""),
    ("shell","cat","/proc/mounts"): (0, "tmpfs /dev tmpfs rw 0 0\n", ""),
    ("shell","pm","list","features"): (0, "feature:android.hardware.touchscreen\n", ""),
    ("shell","getprop","dalvik.vm.isa.arm64.variant"): (0, "\n", ""),
    ("shell","getenforce"): (127, "", "/system/bin/sh: getenforce: inaccessible or not found\n"),
    ("shell","cat","/proc/self/cgroup"): (1, "", "cat: /proc/self/cgroup: Permission denied\n"),
}
rc, out, err = table.get(tuple(args), (99, "", "unexpected fake-adb invocation\n"))
sys.stdout.write(out)
sys.stderr.write(err)
raise SystemExit(rc)
"""


class SpelunkerTests(unittest.TestCase):
    def test_bounded_passive_observations(self):
        with tempfile.TemporaryDirectory() as td:
            fake = pathlib.Path(td) / "adb"
            fake.write_text(FAKE_ADB, encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

            cp = subprocess.run(
                [sys.executable, str(SCRIPT), "--adb", str(fake), "--serial", "emulator-5554"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(cp.stdout)
            self.assertEqual(doc["schema"], "aar-environment-spelunk/v0")
            self.assertEqual(doc["mode"], "passive")
            self.assertFalse(doc["mutation_authorized"])
            self.assertEqual(len(doc["observations"]), 12)

            by_id = {x["id"]: x for x in doc["observations"]}
            self.assertEqual(by_id["device.state"]["classification"], "PRESENT")
            self.assertEqual(by_id["runtime.process"]["capability_level"], 1)
            self.assertEqual(by_id["security.selinux"]["classification"], "ABSENT")
            self.assertEqual(by_id["cgroups"]["classification"], "INACCESSIBLE")

    def test_only_allowlisted_probe_commands_are_declared(self):
        text = SCRIPT.read_text(encoding="utf-8")
        forbidden = [" install ", " uninstall ", " settings put ", " am start ", " pm grant "]
        for item in forbidden:
            self.assertNotIn(item, text)


if __name__ == "__main__":
    unittest.main()
