"""Raw recovered Java behavior evidence: negative controls and no false success."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import experiment_r8_behavior_oracle as O

class RawOracleControls(unittest.TestCase):
    def test_exact_ten_vector_match(self):
        original=[f"case={i}|x={i}" for i in range(10)]
        result=O.classify(original,("\n".join(original)+"\n").encode())
        self.assertEqual(result["state"],"MATCH_10_VECTORS")
        self.assertEqual(result["matched"],10)

    def test_mutated_vector_detected(self):
        original=[f"case={i}|x={i}" for i in range(10)]
        changed=list(original)
        changed[4]="case=4|WRONG"
        result=O.classify(original,("\n".join(changed)+"\n").encode())
        self.assertEqual(result["state"],"MISMATCH_OBSERVED")
        self.assertEqual(result["mismatched"],1)

    def test_truncation_does_not_claim_success(self):
        original=[f"case={i}|x={i}" for i in range(10)]
        result=O.classify(original,("\n".join(original[:9])).encode())
        self.assertEqual(result["state"],"OUTPUT_INVALID")
        self.assertEqual(result["unknown"],10)

    def test_renamed_profiles_not_unblinded(self):
        self.assertEqual(O.RENAMED,("rename-only","full-r8"))
        self.assertEqual(len(O.LABELS),5)
