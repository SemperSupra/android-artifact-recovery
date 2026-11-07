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
            self.assertEqual(result["failed_shard_count"],1)
            self.assertEqual(result["total_java_files_observed"],2)
            self.assertEqual(result["java_relative_path_overlap_count"],1)
            self.assertEqual(result["status"],"JADX_SHARDED_PARTIAL_EVIDENCE")
            self.assertFalse(result["coverage_verified"])
            public=receipt.read_text()
            self.assertNotIn("Synthetic.java",public)
            self.assertNotIn("// synthetic",public)
            self.assertNotIn(str(root),public)

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
