"""Source-level safety regressions for the restricted unsigned A4 JNI expression IR.

These tests do not prove Android ART, Ghidra decompilation, or general C semantics.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "recover_ndk_jni_semantics_v0.py"
spec = importlib.util.spec_from_file_location("aar_typed_ir_under_test", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("AAR recovery source unavailable")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class TypedIRGuards(unittest.TestCase):
    def test_signed_and_mixed_signatures_abstain(self):
        for result_type, parameter_type in [
            ("int", "int"), ("int", "uint"), ("uint", "int")
        ]:
            with self.subTest(result_type=result_type, parameter_type=parameter_type):
                source = f"{result_type} FUN_1000({parameter_type} param_1) {{return param_1 >> 1;}}"
                with self.assertRaisesRegex(ValueError, "UNSUPPORTED_SIGNED_OR_MIXED_IR"):
                    mod.parse_c(source)

    def test_unsigned_logical_shift_preserved(self):
        tree = mod.parse_c("uint FUN_1000(uint param_1) {return param_1 >> 1;}")
        for value in (-7, -1, 0, 1, 7, 0x7fffffff, 0x80000000, 0xffffffff):
            with self.subTest(value=value):
                self.assertEqual(((value & 0xffffffff) >> 1), mod.evaluate(tree, value))

    def test_undefined_large_shifts_abstain(self):
        for operation in (">>", "<<"):
            with self.subTest(operation=operation):
                tree = mod.parse_c(f"uint FUN_1000(uint param_1) {{return param_1 {operation} 32;}}")
                with self.assertRaisesRegex(ValueError, "UNDEFINED_SHIFT_COUNT"):
                    mod.evaluate(tree, 7)
        dynamic = mod.parse_c("uint FUN_1000(uint param_1) {return 1 << param_1;}")
        with self.assertRaisesRegex(ValueError, "UNDEFINED_SHIFT_COUNT"):
            mod.evaluate(dynamic, 32)

    def test_uint32_wrap_and_existing_operators(self):
        cases = [
            ("param_1 + 1", lambda u: (u + 1) & 0xffffffff),
            ("param_1 * 3", lambda u: (u * 3) & 0xffffffff),
            ("param_1 ^ 5", lambda u: u ^ 5),
        ]
        for expression, expected in cases:
            with self.subTest(expression=expression):
                tree = mod.parse_c(f"uint FUN_1000(uint param_1) {{return {expression};}}")
                for value in (0, 1, 7, 0xffffffff):
                    self.assertEqual(expected(value & 0xffffffff), mod.evaluate(tree, value))

if __name__ == "__main__":
    unittest.main()
