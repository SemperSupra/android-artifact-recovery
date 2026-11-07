"""Synthetic bounded multi-DEX oracle; no real app source or binary execution."""
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from tools.run_sharded_jadx import run
from tests.test_qualify_dex_header_inventory import dex


def fake_tool(path):
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,sys\n"
        "output=pathlib.Path(sys.argv[sys.argv.index('-d')+1])\n"
        "source=pathlib.Path(sys.argv[-1])\n"
        "(output/'sources').mkdir(parents=True,exist_ok=True)\n"
        "(output/'sources'/'Synthetic.java').write_text('// synthetic fixture only')\n"
        "print('ERROR - finished with errors, count: 1' if source.name=='classes2.dex' else '')\n"
        "sys.exit(3 if source.name=='classes2.dex' else 0)\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class ShardJadxTests(unittest.TestCase):
    def test_bounded_two_shard_partial_and_no_raw_code_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);app=root/"synthetic.apk";tool=root/"jadx";fake_tool(tool)
            with zipfile.ZipFile(app,"w") as z:
                z.writestr("classes.dex",dex(classes=4,methods=7))
                z.writestr("classes2.dex",dex(classes=5,methods=8))
            receipt=root/"receipt.json"
            result=run(app,tool,root/"outputs",receipt,seconds=10)
            self.assertEqual(result["root_dex_count"],2)
            self.assertEqual(result["total_dex_class_defs"],9)
            self.assertEqual(result["total_dex_method_ids"],15)
            self.assertEqual(result["all_original_dex_method_ids"],15)
            self.assertEqual(result["failed_shard_count"],1)
            self.assertEqual(result["total_java_files_observed"],2)
            self.assertEqual(result["java_relative_path_overlap_count"],1)
            self.assertEqual(result["status"],"JADX_SHARDED_PARTIAL_EVIDENCE")
            self.assertFalse(result["coverage_verified"])
            public=receipt.read_text()
            self.assertNotIn("Synthetic.java",public)
            self.assertNotIn("// synthetic",public)
            self.assertNotIn(str(root),public)

    def test_targeted_fallback_has_distinct_grade_and_original_denominator(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);apk=root/"synthetic.apk";tool=root/"jadx";fake_tool(tool)
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",dex(classes=4,methods=7))
                z.writestr("classes2.dex",dex(classes=5,methods=8))
            result=run(apk,tool,root/"outputs",root/"receipt.json",seconds=10,
                       mode="fallback",targets=("classes2.dex",))
            self.assertEqual(result["original_root_dex_count"],2)
            self.assertEqual(result["root_dex_count"],1)
            self.assertEqual(result["selected_dex_names"],["classes2.dex"])
            self.assertEqual(result["total_dex_class_defs"],5)
            self.assertEqual(result["all_original_dex_class_defs"],9)
            self.assertEqual(result["total_dex_method_ids"],8)
            self.assertEqual(result["all_original_dex_method_ids"],15)
            self.assertEqual(result["status"],"JADX_TARGETED_FALLBACK_PARTIAL_EVIDENCE")
            self.assertEqual(result["evidence_grade"],"FALLBACK_RAW_INSTRUCTION_RENDERING")
            self.assertNotIn("Synthetic.java",(root/"receipt.json").read_text())

    def test_fallback_scope_abstains_for_missing_duplicate_and_injection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);apk=root/"synthetic.apk";tool=root/"jadx";fake_tool(tool)
            with zipfile.ZipFile(apk,"w") as z:z.writestr("classes.dex",dex())
            for names in (None,("classes3.dex",),("../classes.dex",),
                          ("classes.dex","classes.dex"),
                          ("classes.dex","classes2.dex","classes3.dex")):
                with self.subTest(names=names):
                    with self.assertRaises(ValueError):
                        run(apk,tool,root/"out",root/"receipt",seconds=10,
                            mode="fallback",targets=names)
            with self.assertRaisesRegex(ValueError,"unsupported"):
                run(apk,tool,root/"out",root/"receipt",mode="other")

    def test_unlaunchable_tool_emits_typed_failure_not_raw_error(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);app=root/"synthetic.apk";tool=root/"jadx"
            tool.write_text("not executable")
            with zipfile.ZipFile(app,"w") as z:
                z.writestr("classes.dex", dex(classes=1,methods=1))
            result=run(app,tool,root/"outputs",root/"receipt.json",seconds=10)
            self.assertEqual(result["failed_shard_count"],1)
            self.assertEqual(result["shards"][0]["process_status"],"TOOL_LAUNCH_FAILED")
            self.assertEqual(result["shards"][0]["exit_code"],127)

    def test_invalid_timeout_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);app=root/"no.apk";tool=root/"jadx";fake_tool(tool)
            with self.assertRaisesRegex(ValueError,"invalid timeout"):
                run(app,tool,root/"out",root/"receipt.json",seconds=0)

    def test_missing_tool_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);app=root/"no.apk"
            with self.assertRaisesRegex(ValueError,"tool file not present"):
                run(app,root/"missing-tool",root/"out",root/"receipt.json")


if __name__ == "__main__":
    unittest.main()
