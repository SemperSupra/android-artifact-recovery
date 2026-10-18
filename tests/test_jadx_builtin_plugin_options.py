"""JADX 1.5.6 built-in Kotlin metadata options are explicitly bounded."""
import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import experiment_jadx_builtin_plugin_options as P

class SourceInformedJadxProbeTests(unittest.TestCase):
    def test_only_two_source_known_variants(self):
        self.assertEqual(P.LABELS,("shrink-only","shrink-optimize"))
        self.assertEqual(len(P.MODES),4)
        self.assertEqual(P.MODES["baseline"],())
        self.assertIn("-Pkotlin-metadata.getters=no",P.MODES["getters-off"])
        self.assertIn("-Pkotlin-metadata.to-string=no",P.MODES["tostring-off"])
        self.assertNotIn("rename-mappings"," ".join(" ".join(v) for v in P.MODES.values()))

    def test_reject_absent_inputs_without_creating_results(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            with self.assertRaisesRegex(ValueError,"existing R8"):
                P.run({"shrink-only":root/"nonexistent.apk"},
                      root/"jadx",root/"stdlib",root/"out")
            self.assertFalse((root/"out").exists())

    def test_refuse_to_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"out").mkdir()
            with self.assertRaisesRegex(ValueError,"output exists"):
                P.run({},root/"jadx",root/"stdlib",root/"out")
