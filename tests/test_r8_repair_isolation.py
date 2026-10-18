"""Repair experiment cannot overwrite raw or revive renamed class via mapping."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import experiment_r8_repair_isolation as M

class ScopedRepairTests(unittest.TestCase):
    def test_only_three_identifier_stable_variants_are_repairable(self):
        self.assertEqual(len(M.LABELS),5)
        self.assertEqual(len(M.ELIGIBLE),3)
        self.assertNotIn("rename-only",M.ELIGIBLE)
        self.assertNotIn("full-r8",M.ELIGIBLE)

    def test_rule_category_is_stable_and_no_error_source_leaks(self):
        self.assertEqual(
            M.rejected_rule_name("jadx.kotlin.duplicate-data-class-getters: private data /home/user/file"),
            "jadx.kotlin.duplicate-data-class-getters")
        self.assertEqual(M.rejected_rule_name("strange arbitrary content: /etc/passwd"),
                         "UNKNOWN_RULE")

    def test_repair_requires_existing_raw_inputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with self.assertRaisesRegex(ValueError,"five immutable"):
                M.stage(root/"raw",root/"output")
            self.assertFalse((root/"output").exists())

    def test_existing_evidence_cannot_be_overwritten(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"output").mkdir()
            with self.assertRaisesRegex(ValueError,"overwrite"):
                M.stage(root/"raw",root/"output")
