"""Synthetic held-out controls for same-donor metadata repeatability."""
from __future__ import annotations
import json
import tempfile
import unittest
import warnings
from pathlib import Path
from zipfile import ZipFile

from tools.compare_android_recovery_receipts import compare, load_evidence

SHA = "a" * 64


def make_zip(path, *, sha=SHA, files=10, marker=2, verified=True, source="apkpure", extra=None, extra_feature_key=None, config=None):
    receipt = {
        "schema": "aar-chatgpt-public-recovery-receipt/v1",
        "package_id": "com.openai.chatgpt",
        "official_signer_verified": verified,
        "selected_source": source,
        "proprietary_bytes_published": False,
        "decompiler_qualification": {"status": "JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE"},
    }
    if config is not None:
        receipt["derivation_config"] = config
    surface = {
        "schema": "aar-derived-android-surface/v2",
        "files_scanned": files,
        "feature_markers": {"sse": marker, "voice": 12},
        "protocol_markers": {"grpc_surface": ["matched"]},
        "library_markers": {"okhttp": 3},
    }
    if extra_feature_key is not None:
        surface["feature_markers"][extra_feature_key] = 1
    with ZipFile(path, "w") as z:
        z.writestr("selected-archive-sha256.txt", f"{sha}  donor.xapk\n")
        z.writestr("receipt.json", json.dumps(receipt))
        z.writestr("derived-surface.json", json.dumps(surface))
        for name, data in extra or []:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr(name, data)


class RepeatabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = Path(self.tmp.name) / "a.zip"
        self.b = Path(self.tmp.name) / "b.zip"

    def score(self):
        return compare(load_evidence(self.a), load_evidence(self.b))

    def test_same_bytes_same_derived_not_full_coverage(self):
        make_zip(self.a); make_zip(self.b)
        r = self.score()
        self.assertEqual(r["status"], "SAME_DONOR_BOUNDED_REPEATABLE")
        self.assertFalse(r["promotion_authorized"])
        self.assertFalse(r["qualified_full_coverage"])

    def test_same_bytes_scanner_drift_fails_repeatability(self):
        make_zip(self.a); make_zip(self.b, files=11, marker=3)
        r = self.score()
        self.assertEqual(r["status"], "SAME_DONOR_DERIVATION_DRIFT")
        self.assertEqual(r["observed_differences"]["files_scanned"], {"left": 10, "right": 11})
        self.assertEqual(r["observed_differences"]["feature_markers"]["sse"], {"left": 2, "right": 3})

    def test_explicit_jadx_configuration_mismatch_is_incomparable(self):
        make_zip(self.a, config={"threads_count": 1, "jadx_version": "1.5.6"})
        make_zip(self.b, config={"threads_count": 3, "jadx_version": "1.5.6"}, files=11)
        r = self.score()
        self.assertEqual(r["status"], "INCOMPARABLE_DERIVATION_CONFIGURATION")
        self.assertEqual(r["derivation_config_status"], "INCOMPARABLE_DERIVATION_CONFIGURATION")
        self.assertEqual(r["observed_differences"], {})
        self.assertFalse(r["promotion_authorized"])

    def test_one_missing_configuration_is_not_repeatability_claim(self):
        make_zip(self.a)
        make_zip(self.b, config={"threads_count": 1})
        self.assertEqual(self.score()["status"], "INCOMPARABLE_DERIVATION_CONFIGURATION")

    def test_same_explicit_config_can_still_show_bounded_drift(self):
        config = {"threads_count": 1, "jadx_version": "1.5.6"}
        make_zip(self.a, config=config)
        make_zip(self.b, config=config, files=12)
        r = self.score()
        self.assertEqual(r["derivation_config_status"], "EXACT_CONFIG_MATCH")
        self.assertEqual(r["status"], "SAME_DONOR_DERIVATION_DRIFT")

    def test_different_original_is_incomparable(self):
        make_zip(self.a); make_zip(self.b, sha="b" * 64)
        self.assertEqual(self.score()["status"], "INCOMPARABLE_SOURCE_IDENTITY")

    def test_different_source_is_not_same_rep(self):
        make_zip(self.a); make_zip(self.b, source="play")
        self.assertEqual(self.score()["status"], "INCOMPARABLE_SOURCE_IDENTITY")

    def test_unsigned_receipt_does_not_promote(self):
        make_zip(self.a); make_zip(self.b, verified=False)
        self.assertEqual(self.score()["status"], "INVALID_OR_UNVERIFIED_PROVENANCE")

    def test_unknown_derived_metric_key_rejected_before_public_comparison(self):
        # Metadata in an imported ZIP is untrusted. A malicious/derived string
        # must not become an unredacted dictionary key in the public report.
        make_zip(self.a, extra_feature_key="private-token-in-derived-key")
        with self.assertRaisesRegex(ValueError, "unexpected metric"):
            load_evidence(self.a)

    def test_duplicate_required_member_rejected(self):
        make_zip(self.a, extra=[("receipt.json", "{}")])
        with self.assertRaisesRegex(ValueError, "repeated"):
            load_evidence(self.a)

    def test_missing_evidence_rejected(self):
        with ZipFile(self.a, "w") as z:
            z.writestr("receipt.json", "{}")
        with self.assertRaisesRegex(ValueError, "missing"):
            load_evidence(self.a)


if __name__ == "__main__":
    unittest.main()
