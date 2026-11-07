"""Synthetic and known-native-log negative controls for JADX receipt fidelity."""
import unittest

from tools.qualify_jadx_log import qualify_jadx_log


class QualifyJadxLogTests(unittest.TestCase):
    def test_missing_exit_code_not_silently_pass(self):
        d = qualify_jadx_log("INFO - progress: 4 of 8 (50%)")
        self.assertEqual(d["status"], "MISSING_JADX_EXIT_CODE")
        self.assertIsNone(d["exit_code"])
        self.assertFalse(d["full_class_coverage_verified"])

    def test_original_2026_11_04_failure_classification(self):
        d = qualify_jadx_log("INFO  - progress: 21541 of 54543 (39%)\nERROR - finished with errors, count: 112\njadx_returncode=3\n")
        self.assertEqual(d["status"], "JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE")
        self.assertEqual(d["exit_code"], 3)
        self.assertEqual(d["reported_error_count"], 112)
        self.assertEqual(d["last_progress_log_only"]["last_observed_total"], 54543)
        self.assertFalse(d["full_class_coverage_verified"])

    def test_zero_exit_does_not_prove_full_coverage(self):
        d = qualify_jadx_log("INFO - progress: 9 of 9 (100%)\njadx_returncode=0\n")
        self.assertEqual(d["status"], "JADX_EXIT_ZERO_COVERAGE_UNVERIFIED")
        self.assertFalse(d["full_class_coverage_verified"])

    def test_reported_error_overrides_zero_exit(self):
        d = qualify_jadx_log("ERROR - finished with errors, count: 1\njadx_returncode=0\n")
        self.assertEqual(d["status"], "JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE")

    def test_latest_progress_is_observation_not_coverage(self):
        d = qualify_jadx_log("progress: 2 of 10 (20%)\nprogress: 4 of 10 (40%)\njadx_returncode=3\n")
        self.assertEqual(d["last_progress_log_only"]["last_observed_processed"], 4)
        self.assertFalse(d["full_class_coverage_verified"])


if __name__ == "__main__":
    unittest.main()
