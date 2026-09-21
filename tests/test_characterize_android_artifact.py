import io
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "characterize_android_artifact.py"


def apk_bytes(*, native=True, wasm=True, script=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00" + b"A" * 32)
        z.writestr("classes2.dex", b"dex\n039\x00" + b"B" * 16)
        if native:
            hdr = bytearray(64)
            hdr[:4] = b"\x7fELF"
            hdr[4] = 2
            hdr[5] = 1
            hdr[18:20] = struct.pack("<H", 183)
            z.writestr("lib/arm64-v8a/libfixture.so", bytes(hdr))
        if wasm:
            z.writestr("assets/engine.wasm", b"\x00asm\x01\x00\x00\x00")
        if script:
            z.writestr("assets/app.js", b"console.log('fixture');\n")
        z.writestr("res/raw/data.txt", b"not code")
    return buf.getvalue()


class CharacterizeArtifactTests(unittest.TestCase):
    def run_tool(self, artifact, out, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(artifact), "--out", str(out), *extra],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_single_apk_discovers_dex_elf_wasm_and_script(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "fixture.apk"
            apk.write_bytes(apk_bytes())
            out = root / "out.json"
            cp = self.run_tool(apk, out)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["schema"], "aar-artifact-characterization/v0")
            self.assertEqual(doc["summary"]["apk_count"], 1)
            self.assertEqual(doc["summary"]["kinds"]["dex"], 2)
            self.assertEqual(doc["summary"]["kinds"]["elf"], 1)
            self.assertEqual(doc["summary"]["kinds"]["wasm"], 1)
            self.assertEqual(doc["summary"]["kinds"]["javascript"], 1)
            self.assertEqual(doc["summary"]["abis"], ["arm64-v8a"])
            apk_doc = doc["apks"][0]
            self.assertEqual(apk_doc["summary"]["root_dex_count"], 2)
            elf = next(x for x in apk_doc["code_entries"] if x["kind"] == "elf")
            self.assertEqual(elf["metadata"]["machine"]["name"], "aarch64")

    def test_xapk_enumerates_base_and_config_split_without_unbounded_extract(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            xapk = root / "fixture.xapk"
            with zipfile.ZipFile(xapk, "w") as z:
                z.writestr("com.example.app.apk", apk_bytes())
                z.writestr("config.en.apk", apk_bytes(native=False, wasm=False, script=False))
                z.writestr("manifest.json", "{}")
            out = root / "out.json"
            cp = self.run_tool(xapk, out)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["summary"]["apk_count"], 2)
            roles = {x["logical_name"]: x["role_hint"] for x in doc["apks"]}
            self.assertEqual(roles["config.en.apk"], "config-split")
            self.assertEqual(roles["com.example.app.apk"], "base-or-feature-candidate")

    def test_nested_apk_bound_is_explicit_unknown_not_silent_drop(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            xapk = root / "fixture.xapk"
            with zipfile.ZipFile(xapk, "w") as z:
                z.writestr("base.apk", apk_bytes())
            out = root / "out.json"
            cp = self.run_tool(xapk, out, "--max-nested-apk-bytes", "16")
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["summary"]["apk_count"], 0)
            self.assertEqual(doc["summary"]["unknown_or_skipped"], 1)
            self.assertEqual(doc["skipped"][0]["state"], "SKIPPED_BOUND")


if __name__ == "__main__":
    unittest.main()
