import unittest
from scanner import analyze_url, normalize_url


class PhishGuardTests(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_empty_url_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("   ")

    def test_ip_address_flagged(self):
        result = analyze_url("http://192.0.2.1/login")
        self.assertTrue(any("IP address" in reason for reason in result["reasons"]))
        self.assertIn(result["risk"], {"Medium", "High"})

    def test_at_symbol_flagged(self):
        result = analyze_url("http://example.com@192.0.2.1/login")
        self.assertTrue(any("'@'" in reason for reason in result["reasons"]))

    def test_suspicious_terms_flagged(self):
        result = analyze_url("https://example.org/account/verify")
        self.assertTrue(any("security-sensitive terms" in reason for reason in result["reasons"]))

    def test_reserved_example_domain_analyzed(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["host"], "example.com")
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_control_characters_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com/\nmalicious")


if __name__ == "__main__":
    unittest.main()
