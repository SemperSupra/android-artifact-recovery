import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "classify_android_native_boundaries.py"


class AndroidNativeBoundaryTests(unittest.TestCase):
    def test_classifies_platform_bundled_runtime_and_unknown_edges(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            observations = root / "observations.json"
            observations.write_text(json.dumps({
                "schema": "aar-component-observations/v0",
                "artifact": {"sha256": "a" * 64},
                "objects": [
                    {
                        "object_id": "elf:libapp.so",
                        "kind": "elf",
                        "sha256": "b" * 64,
                        "metadata": {
                            "sonames": ["libapp.so"],
                            "needed": [
                                "libc.so",
                                "liblog.so",
                                "libknown.so",
                                "libc++_shared.so",
                                "libmystery.so",
                            ],
                        },
                    },
                    {
                        "object_id": "elf:libknown.so",
                        "kind": "elf",
                        "sha256": "c" * 64,
                        "metadata": {
                            "sonames": ["libknown.so"],
                            "needed": ["libm.so"],
                        },
                    },
                ],
            }))
            out = root / "boundaries.json"
            cp = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--observations", str(observations),
                    "--out", str(out),
                ],
                text=True, capture_output=True
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(out.read_text())
            by = {(x["from_object_id"], x["needed"]): x for x in doc["edges"]}
            self.assertEqual(by[("elf:libapp.so", "libc.so")]["state"], "ANDROID_PLATFORM_BOUNDARY")
            self.assertEqual(by[("elf:libapp.so", "liblog.so")]["state"], "ANDROID_PLATFORM_BOUNDARY")
            self.assertEqual(by[("elf:libapp.so", "libknown.so")]["state"], "BUNDLED_DEPENDENCY")
            self.assertEqual(by[("elf:libapp.so", "libc++_shared.so")]["state"], "NDK_RUNTIME_CANDIDATE")
            self.assertEqual(by[("elf:libapp.so", "libmystery.so")]["state"], "UNRESOLVED_EXTERNAL")
            self.assertEqual(by[("elf:libknown.so", "libm.so")]["state"], "ANDROID_PLATFORM_BOUNDARY")
            self.assertTrue(doc["policy"]["platform_boundary_is_semantic_reference_not_exact_runtime_bytes"])


if __name__ == "__main__":
    unittest.main()
