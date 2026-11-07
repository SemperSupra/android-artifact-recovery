"""Zero-donor admission controls for expensive original APK acquisition."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.select_chatgpt_android_donor import select, main

EVENT = {"action": "synchronize", "before": "a" * 40, "after": "b" * 40}


class AndroidDonorAdmissionTests(unittest.TestCase):
    def test_initial_and_manual_reps_are_admitted(self):
        self.assertTrue(select("workflow_dispatch", {})[0])
        self.assertTrue(select("pull_request", {"action": "opened"})[0])
        self.assertTrue(select("pull_request", {"action": "reopened"})[0])

    def test_changes_only_to_comparator_skip_donor(self):
        for name in ("tools/compare_android_recovery_receipts.py",
                     "tests/test_compare_android_recovery_receipts.py",
                     "tests/test_select_chatgpt_android_donor.py",
                     ".github/workflows/chatgpt-android-source-contract.yml"):
            with self.subTest(name=name), patch(
                "tools.select_chatgpt_android_donor.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, name + chr(10), ""),
            ):
                self.assertEqual(select("pull_request", EVENT),
                                 (False, "SOURCE_ONLY_CHANGE_SKIP_DONOR"))

    def test_source_processor_and_original_workflow_change_admit(self):
        for name in ("tools/summarize_android_surface.py",
                     "tools/qualify_jadx_log.py", "tools/qualify_android_abi.py",
                     "tools/qualify_dex_header_inventory.py",
                     "tools/run_sharded_jadx.py",
                     ".github/workflows/recover-chatgpt-public.yml"):
            with self.subTest(name=name), patch(
                "tools.select_chatgpt_android_donor.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, name + chr(10), ""),
            ):
                self.assertEqual(select("pull_request", EVENT),
                                 (True, "ACQUISITION_INPUT_CHANGED"))

    def test_missing_or_malformed_heads_fail_open(self):
        for e in ({"action": "synchronize"},
                  {"action": "synchronize", "before": "invalid", "after": "b" * 40}):
            with self.subTest(e=e):
                self.assertTrue(select("pull_request", e)[0])

    def test_git_failure_also_admits_donor(self):
        with patch("tools.select_chatgpt_android_donor.subprocess.run",
                   side_effect=subprocess.CalledProcessError(128, ["git", "diff"])):
            self.assertEqual(select("pull_request", EVENT),
                             (True, "UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY"))

    def test_output_is_parseable_two_line_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / "event.json"
            out = Path(temp) / "output.txt"
            event.write_text(json.dumps(EVENT))
            with patch.dict("os.environ", {"GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(out)}), patch(
                "tools.select_chatgpt_android_donor.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "tests/test.py" + chr(10), ""),
            ):
                self.assertEqual(main(), 0)
            self.assertEqual(out.read_text().splitlines(),
                ["acquire=false", "reason=SOURCE_ONLY_CHANGE_SKIP_DONOR"])


if __name__ == "__main__":
    unittest.main()
