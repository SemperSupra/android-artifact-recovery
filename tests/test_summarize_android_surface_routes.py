"""Synthetic host/route-regex regression checks for public-safe AAR static scanner.

No Android APK, account credentials, proprietary code, or network access.
Run from the repository root: python -m unittest tests.test_summarize_android_surface_routes -v
"""
import unittest

from tools.summarize_android_surface import HOSTISH_RE, ROUTE_RE


class RecoverySurfaceRegexTests(unittest.TestCase):
    def test_bare_first_party_hostname_is_observed(self):
        self.assertEqual(
            HOSTISH_RE.search("android.chat.openai.com").group(0),
            "android.chat.openai.com",
        )

    def test_bare_other_hostname_is_observed(self):
        self.assertEqual(
            HOSTISH_RE.search("cdn.example.dev").group(0),
            "cdn.example.dev",
        )

    def test_non_host_control_is_rejected(self):
        self.assertIsNone(HOSTISH_RE.search("not-a-domain"))

    def test_numbered_v1_api_route_is_observed(self):
        self.assertEqual(
            ROUTE_RE.search("'/v1/responses'").group(1),
            "/v1/responses",
        )

    def test_numbered_v2_api_route_is_observed(self):
        self.assertEqual(
            ROUTE_RE.search('"/v2/models"').group(1),
            "/v2/models",
        )

    def test_existing_backend_api_route_remains_detected(self):
        self.assertEqual(
            ROUTE_RE.search('"/backend-api/test"').group(1),
            "/backend-api/test",
        )

    def test_non_api_path_is_rejected(self):
        self.assertIsNone(ROUTE_RE.search("'/unrelated'"))


if __name__ == "__main__":
    unittest.main()
