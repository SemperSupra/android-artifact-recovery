import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MATCHER = ROOT / "tools" / "component_correspondence.py"
PLANNER = ROOT / "tools" / "plan_residual_recovery.py"

ARTIFACT = "a" * 64


class ComponentCorrespondenceTests(unittest.TestCase):
    def run_case(self, objects, references):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            observations = td / "observations.json"
            catalog = td / "references.json"
            correspondence = td / "correspondence.json"
            plan = td / "plan.json"

            observations.write_text(json.dumps({
                "schema": "aar-component-observations/v0",
                "artifact": {"sha256": ARTIFACT},
                "objects": objects,
            }))
            catalog.write_text(json.dumps({
                "schema": "aar-reference-catalog/v0",
                "references": references,
            }))

            cp = subprocess.run([
                sys.executable, str(MATCHER),
                "--observations", str(observations),
                "--references", str(catalog),
                "--out", str(correspondence),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)

            cp = subprocess.run([
                sys.executable, str(PLANNER),
                "--correspondence", str(correspondence),
                "--out", str(plan),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)

            return (
                json.loads(correspondence.read_text()),
                json.loads(plan.read_text()),
            )

    def reference(self, sha256):
        return {
            "component_id": "oss.example@1.2.3",
            "name": "OSS Example",
            "version": "1.2.3",
            "purl": "pkg:generic/oss-example@1.2.3",
            "provenance_class": "R0",
            "source_ref": "https://example.invalid/oss-example/v1.2.3",
            "binaries": [
                {"sha256": sha256, "kind": "elf", "abi": "arm64-v8a"}
            ],
            "metadata": {
                "sonames": ["libexample.so"],
                "version_strings": ["OSS Example 1.2.3"],
            },
        }

    def test_exact_hash_is_reference_only_but_boundary_is_retained(self):
        sha = hashlib.sha256(b"exact-reference").hexdigest()
        correspondence, plan = self.run_case(
            [{
                "object_id": "elf:libexample.so",
                "kind": "elf",
                "sha256": sha,
                "archive_path": "lib/arm64-v8a/libexample.so",
                "metadata": {"sonames": ["libexample.so"]},
            }],
            [self.reference(sha)],
        )

        obj = correspondence["objects"][0]
        self.assertEqual(obj["residual_state"], "KNOWN_REFERENCE")
        self.assertEqual(obj["claims"][0]["identity_state"], "EXACT_BYTES")
        self.assertEqual(obj["claims"][0]["disposition"], "REFERENCE_ONLY")
        self.assertTrue(obj["claims"][0]["boundary_analysis_required"])

        self.assertEqual(len(plan["reference_only"]), 1)
        self.assertEqual(len(plan["boundary_analysis"]), 1)
        self.assertEqual(len(plan["residual_recovery"]), 0)
        self.assertFalse(plan["policy"]["physical_subtraction"])

    def test_metadata_overlap_never_erases_residual(self):
        ref_sha = hashlib.sha256(b"official-reference").hexdigest()
        observed_sha = hashlib.sha256(b"vendor-modified-or-unrelated").hexdigest()
        correspondence, plan = self.run_case(
            [{
                "object_id": "elf:libexample.so",
                "kind": "elf",
                "sha256": observed_sha,
                "archive_path": "lib/arm64-v8a/libexample.so",
                "metadata": {
                    "sonames": ["libexample.so"],
                    "version_strings": ["OSS Example 1.2.3"],
                },
            }],
            [self.reference(ref_sha)],
        )

        obj = correspondence["objects"][0]
        self.assertEqual(obj["residual_state"], "RESIDUAL")
        self.assertEqual(obj["claims"][0]["identity_state"], "FAMILY_MATCH")
        self.assertEqual(obj["claims"][0]["disposition"], "RESIDUAL_RECOVERY")
        self.assertEqual(len(plan["reference_only"]), 0)
        self.assertEqual(len(plan["residual_recovery"]), 1)

    def test_no_match_stays_unknown_and_in_residual_plan(self):
        observed_sha = hashlib.sha256(b"unknown").hexdigest()
        ref_sha = hashlib.sha256(b"reference").hexdigest()
        correspondence, plan = self.run_case(
            [{
                "object_id": "elf:libmystery.so",
                "kind": "elf",
                "sha256": observed_sha,
                "metadata": {"sonames": ["libmystery.so"]},
            }],
            [self.reference(ref_sha)],
        )

        obj = correspondence["objects"][0]
        self.assertEqual(obj["residual_state"], "UNKNOWN")
        self.assertEqual(obj["claims"], [])
        self.assertEqual(len(correspondence["unknowns"]), 1)
        self.assertEqual(len(plan["residual_recovery"]), 1)
        self.assertEqual(len(plan["unknowns"]), 1)


if __name__ == "__main__":
    unittest.main()
