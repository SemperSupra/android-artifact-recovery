"""AOSP DEX class->type->string synthetic held-out fixtures and no-leak controls."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from tools.qualify_dex_class_correspondence import (
    _uleb, _descriptor, evaluate, qualify_dex,
)


def make_dex(names):
    n=len(names)
    sid=112;tid=sid+4*n;cid=tid+4*n;start=cid+32*n
    buf=bytearray(start)
    buf[:8]=b"dex\n037\x00"
    struct.pack_into("<II",buf,56,n,sid)
    struct.pack_into("<II",buf,64,n,tid)
    struct.pack_into("<II",buf,96,n,cid)
    for j,name in enumerate(names):
        off=len(buf)
        raw=name.encode("ascii")
        if len(raw)>=128:raise ValueError("test fixture length")
        buf.extend(bytes([len(raw)])+raw+b"\x00")
        struct.pack_into("<I",buf,sid+4*j,off)
        struct.pack_into("<I",buf,tid+4*j,j)
        struct.pack_into("<I",buf,cid+32*j,j)
    struct.pack_into("<III",buf,32,len(buf),112,0x12345678)
    return bytes(buf)


class ClassCorrespondenceTests(unittest.TestCase):
    def test_exact_parent_and_missing_are_distinct_counts_no_names_exported(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td);sources=folder/"shard-01"/"sources"/"com"/"unit"
            sources.mkdir(parents=True)
            (sources/"A.java").write_text("// secret from synthetic fixture")
            dex=make_dex(["Lcom/unit/A;","Lcom/unit/A$Inner;","Lcom/unit/B;"])
            apk=folder/"test.apk"
            with zipfile.ZipFile(apk,"w") as z:z.writestr("classes.dex",dex)
            result=evaluate(apk,folder,("classes.dex",))
            self.assertEqual(result["total_target_class_defs"],3)
            self.assertEqual(result["aggregate"]["exact_top_level_file"],1)
            self.assertEqual(result["aggregate"]["dollar_named_parent_file_only"],1)
            self.assertEqual(result["aggregate"]["top_level_without_exact_file"],1)
            self.assertFalse(result["complete_class_coverage_verified"])
            public=json.dumps(result)
            for raw in ("com/unit/A","secret from synthetic","A$Inner","/shard-01"):
                self.assertNotIn(raw,public)

    def test_dollar_named_own_file_is_not_fused_onto_parent(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);sources=root/"sources"/"com"/"unit"
            sources.mkdir(parents=True)
            (sources/"A$Inner.java").touch()
            r=qualify_dex(make_dex(["Lcom/unit/A$Inner;"]),root/"sources")
            self.assertEqual(r["observed_correspondence"]["dollar_named_own_file"],1)

    def test_bad_type_and_string_indices_fail_closed(self):
        base=make_dex(["Lcom/unit/A;"])
        for offset,value in ((120,99),(116,99),(112,10**6)):
            with self.subTest(offset=offset):
                raw=bytearray(base);struct.pack_into("<I",raw,offset,value)
                with self.assertRaises(ValueError):
                    qualify_dex(bytes(raw),Path("/nonexistent"))

    def test_invalid_ascii_is_counted_not_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            r=qualify_dex(make_dex(["L../private;"]),Path(td))
            self.assertEqual(r["observed_correspondence"]["invalid_ascii_descriptor"],1)
            self.assertNotIn("private",json.dumps(r))

    def test_duplicate_signed_archive_dex_name_refused_before_lookup(self):
        import warnings
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"dup.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore",UserWarning)
                with zipfile.ZipFile(p,"w") as z:
                    z.writestr("classes.dex",make_dex(["Lcom/unit/A;"]))
                    z.writestr("classes.dex",make_dex(["Lcom/unit/B;"]))
            with self.assertRaisesRegex(ValueError,"duplicate"):
                evaluate(p,Path(td),("classes.dex",))

    def test_uleb_truncation_and_bad_target_abstain(self):
        with self.assertRaisesRegex(ValueError,"truncated"):
            _uleb(b"\x80",0)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"test.apk"
            with zipfile.ZipFile(p,"w") as z:z.writestr("classes.dex",make_dex(["Lcom/unit/A;"]))
            with self.assertRaisesRegex(ValueError,"unreviewed"):
                evaluate(p,Path(td),("../classes.dex",))
            with self.assertRaisesRegex(ValueError,"1-2"):
                evaluate(p,Path(td),("classes.dex","classes.dex"))

if __name__=="__main__":
    unittest.main()
