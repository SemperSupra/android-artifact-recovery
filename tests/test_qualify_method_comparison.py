"""Synthetic, oracle-known qualification of the methodology evidence comparator.

These tests qualify the comparison *logic only*, not Android recovery quality.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from qualify_method_comparison import compare  # noqa: E402

H = "a" * 64
ORACLE = {
    "schema": "aar-method-oracle/v0",
    "artifact_sha256": H,
    "questions": {
        "q1": {"expected": "alpha", "consequential": True},
        "q2": {"expected": "beta", "consequential": True},
        "q3": {"expected": "cosmetic", "consequential": False},
    },
}


def run(method, elapsed=100, observations=None):
    return {
        "schema": "aar-method-observations/v0",
        "artifact_sha256": H,
        "method_id": method,
        "elapsed_ms": elapsed,
        "observations": observations or {},
    }


def seen(value):
    return {"state": "OBSERVED", "value": value}


class MethodComparisonTests(unittest.TestCase):
    def test_missing_means_unknown_not_success(self):
        x = compare(ORACLE, run("a"), run("b", observations={"q1": seen("alpha")}))
        self.assertEqual(x["baseline"]["consequential_unknown"], 2)
        self.assertEqual(x["candidate"]["consequential_unknown"], 1)
        self.assertEqual(x["signal"], "CANDIDATE_QUALITY_SIGNAL")
        self.assertFalse(x["qualified_improvement"])

    def test_wrong_claim_blocks_signal_even_with_additional_correct_answer(self):
        x = compare(
            ORACLE,
            run("a", observations={"q1": seen("alpha")}),
            run("b", observations={"q1": seen("alpha"), "q2": seen("beta"), "q3": seen("wrong")}),
        )
        self.assertEqual(x["candidate"]["all_mismatch"], 1)
        self.assertEqual(x["signal"], "NO_PROMOTION_EVIDENCE")

    def test_faster_same_outcomes_yields_only_cost_signal(self):
        observations = {"q1": seen("alpha"), "q2": {"state": "UNKNOWN"}}
        x = compare(ORACLE, run("a", 123, observations), run("b", 70, observations))
        self.assertEqual(x["signal"], "CANDIDATE_COST_SIGNAL")
        self.assertFalse(x["qualified_improvement"])

    def test_no_correct_claim_not_promoted_for_speed(self):
        x = compare(ORACLE, run("a", 999), run("b", 1))
        self.assertEqual(x["signal"], "NO_PROMOTION_EVIDENCE")

    def test_disjoint_fixture_rejected(self):
        other = run("b")
        other["artifact_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "artifact identity"):
            compare(ORACLE, run("a"), other)

    def test_unknown_must_not_include_guessed_value(self):
        with self.assertRaisesRegex(ValueError, "smuggle"):
            compare(ORACLE, run("a"), run("b", observations={"q1": {"state": "UNKNOWN", "value": "alpha"}}))

    def test_unregistered_claim_rejected(self):
        with self.assertRaisesRegex(ValueError, "undeclared"):
            compare(ORACLE, run("a"), run("b", observations={"injected": seen("secret")}))

    def test_identical_method_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "distinct"):
            compare(ORACLE, run("a"), run("a"))

    def test_boolean_duration_rejected(self):
        with self.assertRaisesRegex(ValueError, "elapsed"):
            compare(ORACLE, run("a"), run("b", True))

    def test_cli_emits_deterministic_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            paths = [p / name for name in ("oracle.json", "baseline.json", "candidate.json")]
            for target, doc in zip(paths, (
                ORACLE, run("a", observations={"q1": seen("alpha")}),
                run("b", observations={"q1": seen("alpha"), "q2": seen("beta")}),
            )):
                target.write_text(json.dumps(doc), encoding="utf-8")
            out = p / "out.json"
            args = [sys.executable, str(ROOT / "tools" / "qualify_method_comparison.py"),
                    "--oracle", str(paths[0]), "--baseline", str(paths[1]),
                    "--candidate", str(paths[2]), "--out", str(out)]
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            result = json.loads(out.read_text())
            self.assertEqual(result["signal"], "CANDIDATE_QUALITY_SIGNAL")
            self.assertEqual(result["required_next_gate"], "INDEPENDENT_REPRODUCTION_AND_HELD_OUT_VALIDATION")


if __name__ == "__main__":
    unittest.main()
