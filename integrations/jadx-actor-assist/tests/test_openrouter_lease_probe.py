"""Offline key management lease controls; never use real provider tokens in CI."""
from __future__ import annotations
import importlib.util
import io
import json
from pathlib import Path
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "openrouter_lease_probe",ROOT/"scripts"/"openrouter_lease_probe.py")
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class Response:
    status=200
    def __init__(self,content):
        self.raw=json.dumps(content).encode()
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.raw[:n]

class Fake:
    def __init__(self):
        self.calls=[]
        self.fail_child=False
    def open(self,request,timeout):
        path=request.full_url.removeprefix(M.BASE)
        method=request.get_method()
        self.calls.append((method,path,json.loads(request.data) if request.data else None))
        if path=="/api/v1/key":
            key=request.headers["Authorization"]
            if "child" in key:
                return Response({"data":{"is_management_key":False,"include_byok_in_limit":True}})
            return Response({"data":{"is_management_key":True}})
        if path=="/api/v1/byok":
            return Response({"data":[{"provider":"private-sensitive-provider-label",
                                      "disabled":False}]})
        if path=="/api/v1/keys" and method=="POST":
            return Response({"data":{"hash":"a"*64,"include_byok_in_limit":True,
                                     "limit":0.1},"key":"sk-or-child-only-fixture"})
        if path=="/api/v1/keys/"+"a"*64 and method=="DELETE":
            return Response({"deleted":True})
        raise AssertionError((method,path))

class LeaseTests(unittest.TestCase):
    def test_preflight_only_reports_aggregate_and_does_not_leak_token_or_provider(self):
        fake=Fake()
        m=M.Manager("secret-parent-token",fake)
        s=m.preflight()
        self.assertEqual(s["management"],"VERIFIED")
        self.assertEqual(s["byok_registered_active"],1)
        self.assertNotIn("private-sensitive",str(s))
        self.assertEqual([x[0] for x in fake.calls],["GET","GET"])

    def test_temporary_key_limited_and_revoked_after_success(self):
        fake=Fake()
        m=M.Manager("secret-parent-token",fake)
        with m.lease("aar-jadx-test",0.1,10) as child:
            self.assertEqual(child,"sk-or-child-only-fixture")
        self.assertEqual([x[0] for x in fake.calls],["POST","DELETE"])
        self.assertEqual(fake.calls[0][2]["include_byok_in_limit"],True)
        self.assertLessEqual(fake.calls[0][2]["limit"],0.10)
        self.assertIn("Z",fake.calls[0][2]["expires_at"])
        self.assertIsNone(fake.calls[0][2]["limit_reset"])

    def test_temporary_key_revoked_after_exception(self):
        fake=Fake()
        with self.assertRaisesRegex(RuntimeError,"controlled test"):
            with M.Manager("secret-parent-token",fake).lease("aar-jadx-test"):
                raise RuntimeError("controlled test")
        self.assertEqual(fake.calls[-1][0],"DELETE")

    def test_disallow_unbounded_budget_and_duration(self):
        fake=Fake()
        m=M.Manager("secret-parent-token",fake)
        with self.assertRaisesRegex(M.LeaseFailure,"BUDGET"):
            with m.lease("aar-jadx-test",0.26,15): pass
        with self.assertRaisesRegex(M.LeaseFailure,"BUDGET"):
            with m.lease("aar-jadx-test",0.1,31): pass
        self.assertEqual(fake.calls,[])

    def test_no_management_secret_no_network(self):
        with self.assertRaisesRegex(M.LeaseFailure,"CREDENTIAL"):
            M.Manager("",Fake())

    def test_no_url_redirect_for_management_key(self):
        handler=M.NoRedirect()
        with self.assertRaisesRegex(ValueError,"REDIRECT_REJECTED"):
            handler.redirect_request(None,None,302,"redirect",{},"https://evil.example/")

if __name__=="__main__":
    unittest.main()
