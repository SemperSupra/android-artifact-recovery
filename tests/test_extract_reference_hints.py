import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "extract_reference_hints.py"


class ReferenceHintTests(unittest.TestCase):
    def test_extracts_maven_npm_and_native_version_hints_without_identity_claims(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            elf = (
                b"\x7fELF" + b"\x00" * 128 +
                b"OpenSSL 1.1.1w  11 Sep 2023\x00" +
                b"https://www.openssl.org/\x00"
            )
            js = (
                b'//# sourceMappingURL=index.js.map\n' +
                b'"/workspace/node_modules/react-native/index.js"\n'
            )
            package = json.dumps({"name": "left-pad", "version": "1.3.0"}).encode()
            pom = b"groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.12.0\n"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties", pom)
                z.writestr("assets/node/package.json", package)
                z.writestr("assets/index.js", js)
                z.writestr("lib/arm64-v8a/libcrypto.1.1.so", elf)

            out = root / "hints.json"
            cp = subprocess.run(
                [sys.executable, str(SCRIPT), str(apk), "--out", str(out)],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertFalse(doc["policy"]["identity_claims"])
            values = [
                (h["family"], h["kind"], h["value"])
                for obj in doc["objects"]
                for h in obj["hints"]
            ]
            self.assertIn(("maven", "gav", "com.squareup.okhttp3:okhttp:4.12.0"), values)
            self.assertIn(("npm", "package-version", "left-pad@1.3.0"), values)
            self.assertIn(("npm", "source-path-package", "react-native"), values)
            self.assertIn(("openssl", "version", "1.1.1w"), values)


    def test_ffmpeg_nonversion_phrase_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            elf = (
                b"\x7fELF" + b"\x00" * 128 +
                b"FFmpeg version 4.4.2 Copyright..." + b"\x00" +
                b"Use FFmpeg version to configure this component" + b"\x00"
            )
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libavutil.so", elf)
            out = root / "hints.json"
            cp = subprocess.run(
                [sys.executable, str(SCRIPT), str(apk), "--out", str(out)],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            ffmpeg = [
                h["value"]
                for obj in doc["objects"]
                for h in obj["hints"]
                if h["family"] == "ffmpeg"
            ]
            self.assertEqual(ffmpeg, ["4.4.2"])


    def test_large_entry_is_explicitly_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("assets/version.txt", b"1.2.3" * 100)
            out = root / "hints.json"
            cp = subprocess.run(
                [
                    sys.executable, str(SCRIPT), str(apk),
                    "--out", str(out), "--max-entry-bytes", "32"
                ],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["summary"]["hint_count"], 0)
            self.assertEqual(doc["skipped"][0]["state"], "SKIPPED_BOUND")


    def test_ffmpeg_non_version_word_is_not_a_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            elf = (
                b"\x7fELF" + b"\x00" * 64 +
                b"FFmpeg version to enable runtime diagnostics\x00" +
                b"FFmpeg version 4.4.2 Copyright\x00"
            )
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libavutil.so", elf)
            out = root / "hints.json"
            cp = subprocess.run(
                [sys.executable, str(SCRIPT), str(apk), "--out", str(out)],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            values = [
                (h["family"], h["kind"], h["value"])
                for obj in doc["objects"]
                for h in obj["hints"]
            ]
            self.assertIn(("ffmpeg", "version", "4.4.2"), values)
            self.assertNotIn(("ffmpeg", "version", "to"), values)


if __name__ == "__main__":
    unittest.main()
