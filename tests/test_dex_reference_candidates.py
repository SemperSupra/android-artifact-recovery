from __future__ import annotations

import io
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
TOOL=ROOT/"tools"/"score_dex_reference_candidates.py"


def make_fake_dex(descriptor: str) -> bytes:
    raw=descriptor.encode("utf-8")
    header_size=112
    string_ids_off=header_size
    type_ids_off=string_ids_off+4
    class_defs_off=type_ids_off+4
    data_off=class_defs_off+32
    data=bytearray(data_off+1+len(raw)+1)
    data[:8]=b"dex\n035\x00"
    struct.pack_into("<I",data,32,len(data))
    struct.pack_into("<I",data,36,header_size)
    struct.pack_into("<I",data,40,0x12345678)
    struct.pack_into("<II",data,56,1,string_ids_off)
    struct.pack_into("<II",data,64,1,type_ids_off)
    struct.pack_into("<II",data,96,1,class_defs_off)
    struct.pack_into("<I",data,string_ids_off,data_off)
    struct.pack_into("<I",data,type_ids_off,0)
    struct.pack_into("<I",data,class_defs_off,0)
    data[data_off]=len(descriptor)
    data[data_off+1:data_off+1+len(raw)]=raw
    data[-1]=0
    return bytes(data)


def write_jar(path: pathlib.Path, class_path: str) -> None:
    with zipfile.ZipFile(path,"w") as z:
        z.writestr(class_path,b"fixture")


class DexReferenceCandidateTests(unittest.TestCase):
    def test_exact_class_overlap_is_recorded_but_not_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            target=root/"classes.dex"
            target.write_bytes(make_fake_dex("Lcom/example/library/Thing;"))
            exact=root/"exact.jar"
            write_jar(exact,"com/example/library/Thing.class")
            false=root/"false.jar"
            write_jar(false,"org/other/Thing.class")
            out=root/"out.json"
            cp=subprocess.run([
                sys.executable,str(TOOL),str(target),
                "--candidate",f"exact={exact}",
                "--candidate",f"false={false}",
                "--out",str(out),
            ],text=True,capture_output=True)
            self.assertEqual(cp.returncode,0,cp.stderr)
            doc=json.loads(out.read_text())
            by={x["label"]:x for x in doc["candidates"]}
            self.assertEqual(by["exact"]["exact_class_overlap_count"],1)
            self.assertEqual(by["exact"]["target_exact_coverage"],1.0)
            self.assertEqual(by["false"]["exact_class_overlap_count"],0)
            self.assertEqual(by["false"]["simple_name_overlap_count"],1)
            self.assertFalse(by["false"]["simple_name_overlap_is_identity_evidence"])
            self.assertFalse(doc["policy"]["component_identity_claims"])
            self.assertTrue(doc["policy"]["structural_fid_or_stronger_evidence_required_for_attribution"])

    def test_reads_classes_jar_from_aar(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            target=root/"classes.dex"
            target.write_bytes(make_fake_dex("Lcom/example/library/Thing;"))

            jar_bytes=io.BytesIO()
            with zipfile.ZipFile(jar_bytes,"w") as j:
                j.writestr("com/example/library/Thing.class",b"fixture")
            aar=root/"fixture.aar"
            with zipfile.ZipFile(aar,"w") as z:
                z.writestr("classes.jar",jar_bytes.getvalue())

            out=root/"out.json"
            cp=subprocess.run([
                sys.executable,str(TOOL),str(target),
                "--candidate",f"aar={aar}",
                "--out",str(out),
            ],text=True,capture_output=True)
            self.assertEqual(cp.returncode,0,cp.stderr)
            doc=json.loads(out.read_text())
            self.assertEqual(doc["candidates"][0]["exact_class_overlap_count"],1)

    def test_requires_bounded_candidate_set(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            target=root/"classes.dex"
            target.write_bytes(make_fake_dex("Lcom/example/library/Thing;"))
            cp=subprocess.run([
                sys.executable,str(TOOL),str(target),"--out",str(root/"out.json")
            ],text=True,capture_output=True)
            self.assertNotEqual(cp.returncode,0)
            self.assertIn("at least one",cp.stderr)


if __name__=="__main__":
    unittest.main()
