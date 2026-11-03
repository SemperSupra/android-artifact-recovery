#!/usr/bin/env python3
"""Opt-in source-known native C oracle: not JNI/ART/Ghidra or a release test."""
from __future__ import annotations
import ctypes
import importlib.util
import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "tools" / "recover_ndk_jni_semantics_v0.py"
FIXTURE = Path(__file__).with_name("shift.c")
spec = importlib.util.spec_from_file_location("aar_typed_native", SOURCE)
if spec is None or spec.loader is None:
    raise SystemExit("source unavailable")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
rows = []
with tempfile.TemporaryDirectory() as tmp:
    for compiler in ("gcc", "clang"):
        if not shutil.which(compiler):
            raise SystemExit("REQUIRES_NATIVE_COMPILER: " + compiler)
        for opt in ("-O0", "-O2"):
            output = Path(tmp) / (compiler + opt[2:] + ".so")
            subprocess.run([compiler, "-shared", "-fPIC", opt, "-std=c11",
                str(FIXTURE), "-o", str(output)], check=True, capture_output=True)
            library = ctypes.CDLL(str(output))
            func = library.f_uu
            func.argtypes = [ctypes.c_uint32]
            func.restype = ctypes.c_uint32
            tree = mod.parse_c("uint FUN_1000(uint param_1) {return param_1 >> 1;}")
            for value in (0, 1, 7, 127, 0x7fffffff, 0x80000000, 0xffffffff):
                actual = int(func(value))
                predicted = mod.evaluate(tree, value)
                if actual != predicted:
                    raise SystemExit("NATIVE_ORACLE_MISMATCH")
                rows.append({"compiler": compiler, "optimization": opt, "input": value,
                             "matched": True})
for signature in (("int", "int"), ("int", "uint"), ("uint", "int")):
    try:
        mod.parse_c(f"{signature[0]} FUN_1000({signature[1]} param_1) {{return param_1 >> 1;}}")
    except ValueError as ex:
        if "UNSUPPORTED_SIGNED_OR_MIXED_IR" not in str(ex):
            raise
    else:
        raise SystemExit("SIGNED_INPUT_NOT_REFUSED")
receipt = {"grade": "SOURCE_KNOWN_NATIVE_C_ONLY_NOT_JNI",
           "platform": platform.platform(), "python": sys.version.split()[0],
           "observations": len(rows), "unsigned_mismatches": 0,
           "signed_or_mixed_type_refusal": True, "status": "PASS"}
print(json.dumps(receipt, sort_keys=True))
