"""R8 sequence must be honest about confounded flags and sealed evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import experiment_r8_factor_matrix as F

class R8FactorControls(unittest.TestCase):
    def test_sequence_rejects_orthogonal_claims(self):
        self.assertEqual(len(F.PROFILES),5)
        self.assertEqual(len(F.COMPARISONS),4)
        self.assertFalse(F.PROFILES["rename-only"]["shrinking"])
        self.assertFalse(F.PROFILES["rename-only"]["optimization"])
        self.assertFalse(F.PROFILES["shrink-only"]["renaming"])
        self.assertTrue(F.PROFILES["shrink-optimize"]["optimization"])
        self.assertFalse(F.PROFILES["shrink-optimize"]["renaming"])
        self.assertTrue(F.PROFILES["full-r8"]["renaming"])

    def test_no_partial_matrix_without_complete_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with self.assertRaisesRegex(ValueError,"five"):
                F.examine({"release":d/"x.apk"}, {}, d/"jadx",d/"out")
            self.assertFalse((d/"out").exists())

    def test_missing_renaming_evaluator_mapping_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with self.assertRaisesRegex(ValueError,"two evaluator-only"):
                F.examine({k:d/k for k in F.PROFILES},{},d/"jadx",d/"out")
            self.assertFalse((d/"out").exists())

    def test_existing_result_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            (d/"out").mkdir()
            with self.assertRaisesRegex(ValueError,"already exists"):
                F.examine({}, {}, d/"jadx",d/"out")

    def test_recovery_is_not_automatically_marked_equivalent(self):
        self.assertEqual(F.PROFILES["release"]["r8"],False)
        self.assertEqual(F.PROFILES["full-r8"]["r8"],True)
        self.assertNotIn("mapping", " ".join(["--no-res","--no-imports","--show-bad-code"]))
