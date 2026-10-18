"""Independent Java-oracle scorer: counterexamples and no model-output execution."""
import hashlib,importlib.util,json
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("v",HERE/"verify_interview.py")
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
SRC=(HERE/"OverloadOracle.java").read_text()
BASE={"schema":"aar-jadx-local-actor-interview/v0","task":V.TASK,
    "external_disclosure":False,"source_scope":"PUBLIC_SYNTHETIC",
    "code_sha256":hashlib.sha256(SRC.encode()).hexdigest(),
    "role":"DETERMINISTIC_CANDIDATE","status":"OBSERVED_UNVERIFIED",
    "requested_model":"qwen3:1.7b","observed_model":"qwen3:1.7b",
    "prompt_sha256":"abc","elapsed_ms":100}
class VerdictTests(unittest.TestCase):
    def good(self):
        a=dict(BASE)
        a["candidate"]=json.dumps({"runtime_output":"OBJECT",
            "selected_signature":"a(Object)","original_source_names":"UNKNOWN",
            "evidence":["L5","L8"]})
        return a
    def test_exact(self):self.assertTrue(V.verdict(self.good(),SRC,"OBJECT")["pass"])
    def test_wrong_overload(self):
        a=self.good();a["candidate"]=a["candidate"].replace("a(Object)","a(String)")
        self.assertFalse(V.verdict(a,SRC,"OBJECT")["pass"])
    def test_false_source_names(self):
        a=self.good();a["candidate"]=a["candidate"].replace('"UNKNOWN"','"a was original"')
        self.assertFalse(V.verdict(a,SRC,"OBJECT")["pass"])
    def test_invalid_citation(self):
        a=self.good();a["candidate"]=a["candidate"].replace('"L8"','"L999"')
        self.assertFalse(V.verdict(a,SRC,"OBJECT")["pass"])
    def test_nonstring_citation_no_crash(self):
        a=self.good();a["candidate"]=a["candidate"].replace('"L8"','{}')
        self.assertFalse(V.verdict(a,SRC,"OBJECT")["pass"])
    def test_malformed_json(self):
        a=self.good();a["candidate"]="object likely"
        self.assertEqual(V.verdict(a,SRC,"OBJECT")["status"],"INVALID_JSON")
    def test_incomplete_retains_unknown(self):
        a=self.good();a["status"]="INCOMPLETE";a.pop("candidate")
        self.assertFalse(V.verdict(a,SRC,"OBJECT")["scored"])
    def test_privacy_guard(self):
        a=self.good();a["external_disclosure"]=True
        with self.assertRaisesRegex(ValueError,"boundary"):V.verdict(a,SRC,"OBJECT")
    def test_preimage_sha_guard(self):
        a=self.good();a["code_sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"SHA"):V.verdict(a,SRC,"OBJECT")
if __name__=="__main__":unittest.main()
