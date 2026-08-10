"""
Tests for the fusion layer (live detectors + database intelligence).

Run from the backend/ folder:
    python -m unittest tests.test_fusion
or from the project root with backend on the path:
    PYTHONPATH=backend python -m unittest discover -s tests
"""

import os
import sys
import unittest

# Make the backend package importable when run from the project root.
BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))

os.environ.pop("OPENAI_API_KEY", None)  # keep tests hermetic: rule engine only

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

SCAM = (
    "Hello, I am currently abroad so we cannot meet in person, but I can send the keys "
    "by post. To reserve the apartment, please transfer the deposit of 1400 euro today, "
    "as there are many other interested tenants."
)
NORMAL = "Hi Skye, want to come see the room this Saturday afternoon? We can discuss the contract in person."
REPORTED_PHONE_MSG = "Landlord contact is +31 6 93311824, wants deposit before viewing."


class FusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def analyze(self, **body):
        r = self.client.post("/api/analyze", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_scam_text_is_dangerous_and_enriched(self):
        j = self.analyze(text=SCAM)
        self.assertEqual(j["verdict"], "dangerous")
        self.assertGreaterEqual(j["risk_score"], 60)
        # live tactics present
        self.assertTrue(any(t["source"] == "live" for t in j["tactics"]))
        # database enrichment present because risk was established
        self.assertTrue(j["matching_patterns"])
        self.assertTrue(j["recommended_actions"])

    def test_normal_email_is_safe_with_no_pattern_panel(self):
        j = self.analyze(text=NORMAL)
        self.assertEqual(j["verdict"], "safe")
        self.assertEqual(j["tactics"], [])
        # enrichment is suppressed for clean messages (no false alarms)
        self.assertEqual(j["matching_patterns"], [])
        self.assertEqual(j["similar_cases"], [])

    def test_fake_url_is_dangerous(self):
        j = self.analyze(url="http://funda-secure-pay.info/login")
        self.assertEqual(j["verdict"], "dangerous")

    def test_pending_report_match_raises_suspicion(self):
        j = self.analyze(text=REPORTED_PHONE_MSG)
        self.assertEqual(j["reported_intelligence"]["pending_report_count"], 1)
        self.assertIn("pending", j["reported_intelligence"]["direct_warning"].lower())
        self.assertIn(j["verdict"], {"suspicious", "dangerous"})

    def test_verified_report_match_forces_dangerous(self):
        # Verify the seed report, then confirm escalation, then revert.
        self.client.put("/api/reports/UR0002", json={"Review_Status": "Verified"})
        try:
            j = self.analyze(text=REPORTED_PHONE_MSG)
            self.assertEqual(j["verdict"], "dangerous")
            self.assertGreaterEqual(j["risk_score"], 85)
            self.assertEqual(j["reported_intelligence"]["verified_report_count"], 1)
        finally:
            self.client.put("/api/reports/UR0002", json={"Review_Status": "Pending"})

    def test_report_submission_roundtrip(self):
        r = self.client.post("/api/reports", json={"Title": "t", "Uploaded_Text": SCAM})
        self.assertEqual(r.status_code, 201, r.text)
        report_id = r.json()["Report_ID"]
        self.assertEqual(r.json()["Review_Status"], "Pending")
        # clean up
        self.assertEqual(self.client.delete(f"/api/reports/{report_id}").status_code, 200)

    def test_localization_to_chinese(self):
        j = self.analyze(text=SCAM, native_language="Chinese")
        # Chinese summary should contain Chinese characters
        self.assertTrue(any("\u4e00" <= ch <= "\u9fff" for ch in j["summary"]))


if __name__ == "__main__":
    unittest.main()
