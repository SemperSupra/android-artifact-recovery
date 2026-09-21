import hashlib
import json
import pathlib
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXTRACT = ROOT / "tools" / "extract_component_evidence.py"
RESOLVE = ROOT / "tools" / "resolve_reference_catalog.py"


def make_fake_dex(descriptor: str) -> bytes:
    raw = descriptor.encode("utf-8")
    header_size = 112
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4
    class_defs_off = type_ids_off + 4
    data_off = class_defs_off + 32
    data = bytearray(data_off + 1 + len(raw) + 1)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, len(data))
    struct.pack_into("<I", data, 36, header_size)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<II", data, 56, 1, string_ids_off)
    struct.pack_into("<II", data, 64, 1, type_ids_off)
    struct.pack_into("<II", data, 96, 1, class_defs_off)
    struct.pack_into("<I", data, string_ids_off, data_off)
    struct.pack_into("<I", data, type_ids_off, 0)
    struct.pack_into("<I", data, class_defs_off, 0)
    data[data_off] = len(descriptor)
    data[data_off + 1:data_off + 1 + len(raw)] = raw
    data[-1] = 0
    return bytes(data)


def make_fake_readelf(path: pathlib.Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "cat <<'EOF'\n"
        " 0x000000000000000e (SONAME)             Library soname: [libfixture.so]\n"
        " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n"
        "    Build ID: aabbccdd\n"
        "String dump of section '.comment':\n"
        "  [     0]  Android clang version 18.0\n"
        "\n"
        "Symbol table '.dynsym' contains 2 entries:\n"
        "   1: 0000000000001000    12 FUNC    GLOBAL DEFAULT    1 fixture_symbol\n"
        "EOF\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class CheapEvidenceTests(unittest.TestCase):
    def test_extracts_dex_namespace_elf_identity_and_js_markers(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            apk = root / "sample.apk"
            elf = b"\x7fELF" + bytes([2, 1]) + b"\x00" * 12 + struct.pack("<H", 183) + b"fixture"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("classes.dex", make_fake_dex("Lcom/example/library/Thing;"))
                z.writestr("lib/arm64-v8a/libfixture.so", elf)
                z.writestr("assets/index.js", b"/* SPDX-License-Identifier: MIT */\nvar webpackChunk=[];")
            readelf = root / "readelf"
            make_fake_readelf(readelf)
            out = root / "observations.json"
            cp = subprocess.run([
                sys.executable, str(EXTRACT), str(apk),
                "--out", str(out),
                "--readelf", str(readelf),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["schema"], "aar-component-observations/v0")
            by_kind = {x["kind"]: x for x in doc["objects"]}
            self.assertIn("com.example.library", by_kind["dex"]["metadata"]["namespaces"])
            self.assertEqual(by_kind["elf"]["metadata"]["sonames"], ["libfixture.so"])
            self.assertEqual(by_kind["elf"]["metadata"]["build_ids"], ["aabbccdd"])
            self.assertIn("webpackChunk", by_kind["javascript"]["metadata"]["runtime_markers"])

    def test_resolver_requires_and_verifies_expected_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            source = root / "reference.bin"
            source.write_bytes(b"known reference bytes")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            request = root / "request.json"
            request.write_text(json.dumps({
                "schema": "aar-reference-request/v0",
                "references": [{
                    "component_id": "fixture@1",
                    "name": "Fixture",
                    "version": "1",
                    "purl": None,
                    "provenance_class": "R0",
                    "source_ref": "https://example.invalid/source/tag/v1",
                    "artifacts": [{
                        "url": source.as_uri(),
                        "expected_sha256": digest,
                        "kind": "elf",
                        "abi": "arm64-v8a",
                        "logical_name": "libfixture.so",
                    }],
                }],
            }))
            out = root / "catalog.json"
            cp = subprocess.run([
                sys.executable, str(RESOLVE),
                "--request", str(request),
                "--cache", str(root / "cache"),
                "--out", str(out),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["references"][0]["binaries"][0]["sha256"], digest)

    def test_resolver_fails_closed_on_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            source = root / "reference.bin"
            source.write_bytes(b"not expected")
            request = root / "request.json"
            request.write_text(json.dumps({
                "schema": "aar-reference-request/v0",
                "references": [{
                    "component_id": "fixture@1",
                    "name": "Fixture",
                    "version": "1",
                    "provenance_class": "R0",
                    "source_ref": "https://example.invalid/source/tag/v1",
                    "artifacts": [{
                        "url": source.as_uri(),
                        "expected_sha256": "0" * 64,
                        "kind": "elf",
                    }],
                }],
            }))
            cp = subprocess.run([
                sys.executable, str(RESOLVE),
                "--request", str(request),
                "--cache", str(root / "cache"),
                "--out", str(root / "catalog.json"),
            ], text=True, capture_output=True)
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn("hash mismatch", cp.stderr)


if __name__ == "__main__":
    unittest.main()
