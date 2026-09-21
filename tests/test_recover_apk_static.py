import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "recover_apk_static.py"


def make_tool(path: pathlib.Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class StaticRecoveryTests(unittest.TestCase):
    def test_extracts_only_code_bearing_inputs_and_records_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("classes.dex", b"dex\n035\x00fixture")
                z.writestr("lib/arm64-v8a/libsample.so", b"ELFfixture")
                z.writestr("assets/not-code.txt", b"ignore")

            jadx = root / "jadx"
            dexdump = root / "dexdump"
            readelf = root / "llvm-readelf"
            objdump = root / "llvm-objdump"

            make_tool(jadx, 'if [ "$1" = "--version" ]; then echo "1.5.6"; exit 0; fi\nout=""\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-d" ]; then shift; out="$1"; fi; shift; done\nmkdir -p "$out/sources/example"\necho "class Fixture {}" > "$out/sources/example/Fixture.java"')
            make_tool(dexdump, 'if [ "$1" = "--help" ]; then echo "dexdump fixture"; exit 0; fi\necho "Class descriptor : Lexample/Fixture;"')
            make_tool(readelf, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "ELF header"')
            make_tool(objdump, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "disassembly"')

            out = root / "out"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(apk),
                    "--out", str(out),
                    "--jadx", str(jadx),
                    "--dexdump", str(dexdump),
                    "--llvm-readelf", str(readelf),
                    "--llvm-objdump", str(objdump),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)

            doc = json.loads((out / "recovery-manifest.json").read_text())
            self.assertEqual(doc["schema"], "aar-static-recovery/v0")
            self.assertEqual(doc["status"], "PASS")
            self.assertEqual(len(doc["discovery"]["dex"]), 1)
            self.assertEqual(len(doc["discovery"]["native"]), 1)
            self.assertTrue((out / "lowlevel/dexdump/classes.dex.txt").is_file())
            self.assertTrue((out / "highlevel/jadx/sources/example/Fixture.java").is_file())
            self.assertFalse((out / "inputs/assets/not-code.txt").exists())


    def test_native_only_split_is_valid_recovery_unit(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "config.arm64_v8a.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libnative.so", b"ELFfixture")

            jadx = root / "jadx"
            dexdump = root / "dexdump"
            readelf = root / "llvm-readelf"
            objdump = root / "llvm-objdump"

            make_tool(jadx, 'if [ "$1" = "--version" ]; then echo "1.5.6"; exit 0; fi\necho "jadx must not execute for native-only split" >&2\nexit 99')
            make_tool(dexdump, 'if [ "$1" = "--help" ]; then echo "dexdump fixture"; exit 0; fi\necho "dexdump must not execute for native-only split" >&2\nexit 99')
            make_tool(readelf, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "ELF header"')
            make_tool(objdump, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "disassembly"')

            out = root / "out"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(apk),
                    "--out", str(out),
                    "--jadx", str(jadx),
                    "--dexdump", str(dexdump),
                    "--llvm-readelf", str(readelf),
                    "--llvm-objdump", str(objdump),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)

            doc = json.loads((out / "recovery-manifest.json").read_text())
            self.assertEqual(doc["status"], "PASS")
            self.assertEqual(doc["dex_recovery"]["status"], "ABSENT")
            self.assertEqual(doc["native_recovery"]["status"], "PRESENT")
            self.assertEqual(len(doc["discovery"]["native"]), 1)
            self.assertFalse(any(x["kind"].startswith("dex-") for x in doc["representations"]))
            self.assertTrue(
                (out / "lowlevel/native/arm64-v8a/libnative.so.readelf.txt").is_file()
            )
            self.assertTrue(
                (out / "lowlevel/native/arm64-v8a/libnative.so.objdump.txt").is_file()
            )


    def test_native_recovery_bounds_are_explicit_partial(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "config.arm64_v8a.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/liba.so", b"ELFa")
                z.writestr("lib/arm64-v8a/libb.so", b"ELFb")

            jadx = root / "jadx"
            dexdump = root / "dexdump"
            readelf = root / "llvm-readelf"
            objdump = root / "llvm-objdump"

            make_tool(jadx, 'if [ "$1" = "--version" ]; then echo "1.5.6"; exit 0; fi\nexit 99')
            make_tool(dexdump, 'if [ "$1" = "--help" ]; then echo "dexdump fixture"; exit 0; fi\nexit 99')
            make_tool(readelf, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "ELF header"')
            make_tool(objdump, 'if [ "$1" = "--version" ]; then echo "LLVM fixture"; exit 0; fi\necho "disassembly"')

            out = root / "out"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(apk),
                    "--out", str(out),
                    "--jadx", str(jadx),
                    "--dexdump", str(dexdump),
                    "--llvm-readelf", str(readelf),
                    "--llvm-objdump", str(objdump),
                    "--max-native-files", "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)

            doc = json.loads((out / "recovery-manifest.json").read_text())
            self.assertEqual(doc["status"], "PARTIAL")
            self.assertEqual(doc["native_recovery"]["status"], "PARTIAL")
            self.assertEqual(doc["native_recovery"]["discovered_count"], 2)
            self.assertEqual(doc["native_recovery"]["selected_count"], 1)
            self.assertEqual(len(doc["native_recovery"]["skipped"]), 1)
            self.assertEqual(doc["native_recovery"]["skipped"][0]["state"], "SKIPPED_BOUND")
            self.assertIn("native:bounded-skip:1", doc["partials"])
            native_outputs = list((out / "lowlevel/native").rglob("*.objdump.txt"))
            self.assertEqual(len(native_outputs), 1)



if __name__ == "__main__":
    unittest.main()
