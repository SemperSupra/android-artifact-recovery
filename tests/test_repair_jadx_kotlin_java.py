import pathlib
import subprocess
import sys
import tempfile
import unittest
import json

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "repair_jadx_kotlin_java.py"

SOURCE = r'''public final class Fixture {
        public final java.lang.String getCanonical() {
            return this.canonical;
        }
        public final java.lang.String getSha256() {
            return this.sha256;
        }
        public final int getRecordCount() {
            return this.recordCount;
        }
        public final int getUniqueKeyCount() {
            return this.uniqueKeyCount;
        }
        public final java.lang.String getCanonical() {
            return this.canonical;
        }
        public final java.lang.String getSha256() {
            return this.sha256;
        }
        public final int getRecordCount() {
            return this.recordCount;
        }
        public final int getUniqueKeyCount() {
            return this.uniqueKeyCount;
        }

    public final java.lang.String canonicalize(java.lang.String input) {
        boolean a = kotlin.text.StringsKt.startsWith$default(it, "#", false, 2, (java.lang.Object) null);
        int b = kotlin.text.StringsKt.indexOf$default((java.lang.CharSequence) line, '=', 0, false, 6, (java.lang.Object) null);
        Object c = kotlin.collections.CollectionsKt.joinToString$default(arrayList, " ", null, null, 0, null, null, 62, null);
        Object d = kotlin.collections.CollectionsKt.joinToString$default(list, "\n", null, "\n", 0, null, new kotlin.jvm.functions.Function1() {
        }, 26, null);
        return "";
    }

    public final org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint.Result fingerprint(java.lang.String input) {
        Object x = kotlin.collections.ArraysKt.joinToString$default(bArrDigest, (java.lang.CharSequence) "", (java.lang.CharSequence) null, (java.lang.CharSequence) null, 0, (java.lang.CharSequence) null, new kotlin.jvm.functions.Function1() {
        }, 30, (java.lang.Object) null);
        arrayList.add(kotlin.text.StringsKt.substringBefore$default((java.lang.String) it.next(), '=', (java.lang.String) null, 2, (java.lang.Object) null));
        return null;
    }
}'''

class RepairTests(unittest.TestCase):
    def test_repairs_expected_kotlin_jadx_artifacts_and_records_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            src = root / "in.java"
            out = root / "out.java"
            manifest = root / "manifest.json"
            src.write_text(SOURCE)
            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--input", str(src),
                "--output", str(out),
                "--manifest", str(manifest),
            ], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            repaired = out.read_text()
            self.assertNotIn("startsWith$default", repaired)
            self.assertNotIn("indexOf$default", repaired)
            self.assertNotIn("joinToString$default", repaired)
            self.assertNotIn("substringBefore$default", repaired)
            self.assertEqual(repaired.count("getCanonical()"), 1)
            self.assertIn("aarRepairSubstringBeforeEq", repaired)
            doc = json.loads(manifest.read_text())
            self.assertEqual(doc["schema"], "aar-repair-manifest/v0")
            self.assertEqual(doc["semantic_claim"], "NONE")
            self.assertGreaterEqual(len(doc["repairs"]), 9)

    def test_fails_closed_when_expected_pattern_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            src = root / "in.java"
            src.write_text("public final class Empty {}")
            cp = subprocess.run([
                sys.executable, str(SCRIPT),
                "--input", str(src),
                "--output", str(root / "out.java"),
                "--manifest", str(root / "manifest.json"),
            ], text=True, capture_output=True)
            self.assertNotEqual(cp.returncode, 0)

if __name__ == "__main__":
    unittest.main()
