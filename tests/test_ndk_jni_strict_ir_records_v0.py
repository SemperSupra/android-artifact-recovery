#!/usr/bin/env python3
"""Fail-first proof that all A4 evidence markers are parsed or rejected.

The pre-patch regular-expression search silently ignored extra malformed
AAR_A4_IR rows and accepted valid prefixes followed by junk. This suite
uses public-safe, source-authored synthetic records; no actual Ghidra run,
Android device, private binary or actor qualification is implied.
"""
from __future__ import annotations

import base64
import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tools"))
from recover_ndk_jni_semantics_v0 import recover,read_ir_rows

C = "uint FUN_00100080(uint param_1) { return param_1 + 1; }"
B = base64.b64encode(C.encode()).decode("ascii")

def log(*rows):
    return ("INFO Ghidra> AAR_A4_ABI=x86_64\n"
            "INFO Ghidra> AAR_A4_BASE=100000\n"
            + "".join("INFO Ghidra> AAR_A4_IR="+s+"\n" for s in rows)
            + "INFO Ghidra> AAR_A4_COUNT=2\n")

class StrictIRCardinality(unittest.TestCase):
    def test_complete_valid_two_rows(self):
        raw=log("100080|"+B,"1000a0|"+B)
        self.assertEqual(len(read_ir_rows(raw)),2)
        self.assertEqual(len(recover(raw,"x86_64")["helpers"]),2)

    def test_extra_invalid_row_must_not_be_ignored(self):
        for extra in ("BAD|%%%%","1000b0|%%%%","1000b0|"+B+"!bad"):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError,"malformed|count"):
                    recover(log("100080|"+B,"1000a0|"+B,extra),"x86_64")

    def test_trailing_junk_must_not_be_partially_accepted(self):
        for suffix in ("#garbage","!forged"," extra-text"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError,"malformed"):
                    recover(log("100080|"+B+suffix,"1000a0|"+B),"x86_64")

    def test_duplicate_or_missing_rows_refused(self):
        cases=((),("100080|"+B,),("100080|"+B,"100080|"+B),
                ("100080|"+B,"1000a0|"+B,"1000b0|"+B))
        for rows in cases:
            with self.subTest(rows=len(rows)):
                with self.assertRaises(ValueError):
                    recover(log(*rows),"x86_64")

    def test_no_relaxed_base64_forms(self):
        for encoded in ("","%%%%","A===","QQ==\x00","YWJjZA==junk"):
            with self.subTest(encoded=encoded):
                with self.assertRaises(ValueError):
                    read_ir_rows(log("100080|"+encoded,"1000a0|"+B))

if __name__=="__main__":
    unittest.main()
