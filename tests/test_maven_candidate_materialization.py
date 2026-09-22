from __future__ import annotations

import importlib.util
import io
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "tools" / "materialize_maven_candidates.py"
SPEC = importlib.util.spec_from_file_location("materialize_maven_candidates", PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class MavenCandidateMaterializerTests(unittest.TestCase):
    def test_builds_exact_url_and_records_unpinned_digest(self):
        req = {
            "schema": "aar-maven-candidate-request/v0",
            "candidates": [{
                "id": "fixture",
                "repository": "https://repo.example/maven2",
                "group_id": "com.example.lib",
                "artifact_id": "demo",
                "version": "1.2.3",
                "packaging": "jar",
            }],
        }
        seen = []
        def opener(url, timeout=60):
            seen.append(url)
            return FakeResponse(b"jar-bytes")
        with tempfile.TemporaryDirectory() as td:
            result = MOD.materialize(req, pathlib.Path(td), max_bytes=1024, opener=opener)
        self.assertEqual(
            seen,
            ["https://repo.example/maven2/com/example/lib/demo/1.2.3/demo-1.2.3.jar"],
        )
        self.assertEqual(result["candidates"][0]["digest_status"], "observed_unpinned")
        self.assertFalse(result["policy"]["version_identity_claims"])
        self.assertFalse(result["policy"]["unpinned_digest_is_reference_truth"])

    def test_expected_digest_is_verified(self):
        digest = MOD.sha256_bytes(b"candidate")
        req = {
            "schema": "aar-maven-candidate-request/v0",
            "candidates": [{
                "id": "pinned",
                "repository": "https://repo.example/maven2",
                "group_id": "a.b",
                "artifact_id": "c",
                "version": "2.0.0",
                "expected_sha256": digest,
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            result = MOD.materialize(
                req,
                pathlib.Path(td),
                max_bytes=1024,
                opener=lambda *_args, **_kwargs: FakeResponse(b"candidate"),
            )
        self.assertEqual(result["candidates"][0]["digest_status"], "verified_expected")

    def test_rejects_dynamic_version_and_non_https_repository(self):
        for version, repository in [
            ("LATEST", "https://repo.example/maven2"),
            ("1.+", "https://repo.example/maven2"),
            ("1.0.0", "http://repo.example/maven2"),
        ]:
            req = {
                "schema": "aar-maven-candidate-request/v0",
                "candidates": [{
                    "id": "bad",
                    "repository": repository,
                    "group_id": "a.b",
                    "artifact_id": "c",
                    "version": version,
                }],
            }
            with self.assertRaises(MOD.RequestError):
                MOD.validate_request(req)

    def test_rejects_path_like_id_and_classifier(self):
        base = {
            "schema": "aar-maven-candidate-request/v0",
            "candidates": [{
                "id": "../escape",
                "repository": "https://repo.example/maven2",
                "group_id": "a.b",
                "artifact_id": "c",
                "version": "1.0.0",
            }],
        }
        with self.assertRaises(MOD.RequestError):
            MOD.validate_request(base)
        base["candidates"][0]["id"] = "safe"
        base["candidates"][0]["classifier"] = "../../escape"
        with self.assertRaises(MOD.RequestError):
            MOD.validate_request(base)

    def test_does_not_resolve_transitives(self):
        req = {
            "schema": "aar-maven-candidate-request/v0",
            "candidates": [{
                "id": "one",
                "repository": "https://repo.example/maven2",
                "group_id": "a.b",
                "artifact_id": "c",
                "version": "1.0.0",
            }],
        }
        calls = []
        def opener(url, timeout=60):
            calls.append(url)
            return FakeResponse(b"x")
        with tempfile.TemporaryDirectory() as td:
            MOD.materialize(req, pathlib.Path(td), max_bytes=1024, opener=opener)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
