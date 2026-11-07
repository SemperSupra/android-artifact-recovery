"""Synthetic DEX cardinality and malformed-archive counterexamples."""
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from tools.qualify_dex_header_inventory import census, read_header


def dex(classes=4, methods=7, corrupt=None):
    buf=bytearray(2048)
    buf[:8]=b"dex\n037\x00"
    struct.pack_into("<III",buf,32,len(buf),112,0x12345678)
    struct.pack_into("<II",buf,88,methods,128 if methods else 0)
    struct.pack_into("<II",buf,96,classes,512 if classes else 0)
    if corrupt: corrupt(buf)
    return bytes(buf)

def apk(path,entries):
    with zipfile.ZipFile(path,"w") as zf:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore",UserWarning)
            for name,content in entries:zf.writestr(name,content)

class DEXHeaderTests(unittest.TestCase):
    def test_two_root_files_independent_counts(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.apk"
            apk(p,[("classes.dex",dex(4,7)),("classes2.dex",dex(5,8))])
            r=census(p)
            self.assertEqual(r["root_dex_count"],2)
            self.assertEqual(r["aggregate"]["class_defs"],9)
            self.assertEqual(r["aggregate"]["method_ids"],15)
            self.assertEqual(r["java_source_coverage"],"NOT_ESTABLISHED")
            self.assertFalse(r["runtime_qualified"])

    def test_missing_root_dex_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.apk"
            apk(p,[("assets/classes.dex",dex()),("../classes.dex",dex())])
            with self.assertRaisesRegex(ValueError,"missing"):census(p)

    def test_duplicate_root_dex_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.apk";apk(p,[("classes.dex",dex()),("classes.dex",dex())])
            with self.assertRaisesRegex(ValueError,"duplicate"):census(p)

    def test_corrupt_header_and_table_bounds_rejected(self):
        faults=(lambda b:struct.pack_into("<I",b,32,1),
                lambda b:struct.pack_into("<I",b,36,3),
                lambda b:struct.pack_into("<I",b,40,0),
                lambda b:struct.pack_into("<II",b,96,4,2040))
        for fault in faults:
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                p=Path(d)/"test.apk";apk(p,[("classes.dex",dex(corrupt=fault))])
                with self.assertRaises(ValueError):census(p)

    def test_missing_base_or_skipped_dex_index_rejected(self):
        for names in (("classes2.dex",), ("classes.dex", "classes3.dex")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as d:
                path=Path(d)/"test.apk"
                apk(path, [(name,dex()) for name in names])
                with self.assertRaisesRegex(ValueError, "noncontiguous"):
                    census(path)

    def test_bad_magic_is_not_accepted(self):
        with self.assertRaises(ValueError):read_header(bytes(112),112)

    def test_empty_tables_are_valid_without_source_coverage_claim(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.apk";apk(p,[("classes.dex",dex(0,0))])
            self.assertEqual(census(p)["aggregate"]["class_defs"],0)

if __name__ == "__main__":
    unittest.main()
