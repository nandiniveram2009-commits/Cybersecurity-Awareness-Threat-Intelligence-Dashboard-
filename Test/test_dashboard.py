import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from services.ioc_validator import validate_indicator
from services.risk_engine import calculate_threat_risk, classify_risk_tier

class TestCybersecurityDashboard(unittest.TestCase):
    
    def test_valid_ipv4(self):
        result = validate_indicator("IP ADDRESS", "192.0.2.1")
        self.assertTrue(result["valid"])

    def test_invalid_ipv4(self):
        result = validate_indicator("IP ADDRESS", "999.999.999.999")
        self.assertFalse(result["valid"])

    def test_valid_domain(self):
        result = validate_indicator("DOMAIN", "example.invalid")
        self.assertTrue(result["valid"])

    def test_valid_sha256(self):
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = validate_indicator("FILE HASH", hash_val)
        self.assertTrue(result["valid"])

    def test_valid_cve(self):
        result = validate_indicator("CVE ID", "CVE-2026-1234")
        self.assertTrue(result["valid"])

    def test_risk_calculation(self):
        risk = calculate_threat_risk("HIGH", 85, 10, 90)
        self.assertGreaterEqual(risk, 0)
        self.assertLessEqual(risk, 100)

    def test_risk_classification(self):
        self.assertEqual(classify_risk_tier(15), "INFORMATIONAL")
        self.assertEqual(classify_risk_tier(90), "CRITICAL")

if __name__ == "__main__":
    unittest.main()
