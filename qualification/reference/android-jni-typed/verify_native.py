#!/usr/bin/env python3
"""Source-known native C oracle, including actual signed/mixed calls.

This runs GCC/Clang x86_64 C in public-safe CI; it DOES NOT run JNI/ART,
Ghidra, any private APK, or a target AArch64 ABI. Signed-negative right shift
is implementation-defined in C; only the observed compiler outputs are recorded.
"""
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

unsigned_inputs = (0, 1, 7, 127, 0x7fffffff, 0x80000000, 0xffffffff)
signed_inputs = (-7, -1, 0, 7, 0x7fffffff)
mixed_uint_inputs = (0, 1, 7, 0x80000000, 0xffffffff)
unsigned_count = 0
signed_mixed_count = 0
signed_negative_native_logical_disagreements = 0
observed_signed_negative_values = 0
per_variant = {}

with tempfile.TemporaryDirectory() as tmp:
    for compiler in ("gcc", "clang"):
        if not shutil.which(compiler):
            raise SystemExit("REQUIRES_NATIVE_COMPILER: " + compiler)
        for opt in ("-O0", "-O2"):
            output = Path(tmp) / (compiler + opt[2:] + ".so")
            subprocess.run(
                [compiler, "-shared", "-fPIC", opt, "-std=c11",
                 str(FIXTURE), "-o", str(output)],
                check=True, capture_output=True,
            )
            library = ctypes.CDLL(str(output))
            # Actual unsigned native C and the real A4 parser/evaluator must agree.
            fn = library.f_uu
            fn.argtypes = [ctypes.c_uint32]
            fn.restype = ctypes.c_uint32
            tree = mod.parse_c("uint FUN_1000(uint param_1) {return param_1 >> 1;}")
            for value in unsigned_inputs:
                actual = int(fn(value))
                predicted = mod.evaluate(tree, value)
                if actual != predicted:
                    raise SystemExit("NATIVE_UNSIGNED_ORACLE_MISMATCH")
                unsigned_count += 1

            # The three ABI variants are actually built and invoked; merely
            # parsing their source signatures is not native qualification.
            variants = (
                ("f_ii", "int", "int", ctypes.c_int32, ctypes.c_int32, signed_inputs),
                ("f_ui", "uint", "int", ctypes.c_uint32, ctypes.c_int32, signed_inputs),
                ("f_iu", "int", "uint", ctypes.c_int32, ctypes.c_uint32, mixed_uint_inputs),
            )
            for name, ret_type, arg_type, ret_ctype, arg_ctype, values in variants:
                unsupported = (
                    f"{ret_type} FUN_1000({arg_type} param_1) "
                    "{return param_1 >> 1;}"
                )
                try:
                    mod.parse_c(unsupported)
                except ValueError as ex:
                    if "UNSUPPORTED_SIGNED_OR_MIXED_IR" not in str(ex):
                        raise
                else:
                    raise SystemExit("NATIVE_SIGNED_OR_MIXED_NOT_REFUSED")
                native_fn = getattr(library, name)
                native_fn.argtypes = [arg_ctype]
                native_fn.restype = ret_ctype
                for value in values:
                    actual = int(native_fn(value))
                    signed_mixed_count += 1
                    per_variant[name] = per_variant.get(name, 0) + 1
                    if name in ("f_ii", "f_ui") and value < 0:
                        observed_signed_negative_values += 1
                        naive_unsigned = (value & 0xffffffff) >> 1
                        if (actual & 0xffffffff) != naive_unsigned:
                            signed_negative_native_logical_disagreements += 1

if unsigned_count != 28 or signed_mixed_count != 60:
    raise SystemExit("NATIVE_CENSUS_MISMATCH")
if set(per_variant) != {"f_ii", "f_ui", "f_iu"} or any(
    count != 20 for count in per_variant.values()
):
    raise SystemExit("NATIVE_VARIANT_CENSUS_MISMATCH")

receipt = {
    "grade": "SOURCE_KNOWN_NATIVE_C_ONLY_NOT_JNI",
    "platform": platform.platform(),
    "python": sys.version.split()[0],
    "gcc_clang_o0_o2_builds": 4,
    "unsigned_native_calls": unsigned_count,
    "signed_and_mixed_native_calls": signed_mixed_count,
    "total_native_calls": unsigned_count + signed_mixed_count,
    "signed_or_mixed_type_refusal": True,
    "signed_negative_native_logical_disagreements": signed_negative_native_logical_disagreements,
    "signed_negative_observation_count": observed_signed_negative_values,
    "signed_negative_C_right_shift_implementation_defined": True,
    "native_calls_by_variant": per_variant,
    "unsigned_mismatches": 0,
    "android_art_jni_executed": False,
    "ghidra_decompiler_executed": False,
    "cross_abi_proven": False,
    "status": "PASS",
}
print(json.dumps(receipt, sort_keys=True))
