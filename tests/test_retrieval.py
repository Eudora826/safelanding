import unittest

from safelanding.data_store import add_user_report, delete_user_report, load_database, read_json, update_case, update_user_report, write_json
from safelanding.retrieval import retrieve
from safelanding.server import SafeLandingHandler


class RetrievalTests(unittest.TestCase):
    def test_deposit_before_viewing_matches_fake_landlord(self):
        result = retrieve("Landlord asks me to pay deposit before viewing")
        self.assertEqual(result["matching_patterns"][0]["item"]["Pattern_ID"], "SP001")
        self.assertIn("KG001", result["relevant_knowledge_gaps"][0]["item"]["Gap_ID"])
        self.assertTrue(result["similar_cases"])

    def test_admin_payment_link_matches_group_admin_pattern(self):
        result = retrieve("Housing group admin sent me a payment link")
        self.assertEqual(result["matching_patterns"][0]["item"]["Pattern_ID"], "SP004")

    def test_detailed_user_report_is_normalized_as_pending(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report(
                {
                    "Title": "Suspicious direct landlord",
                    "Description": "Asked for deposit before viewing.",
                    "Rental_Offer_Type": "Direct landlord",
                    "Offering_Person_Name": "Test Landlord",
                    "Offering_Contact_Value": "test@example.com",
                    "Listing_Address": "Example Street 1, Amsterdam",
                    "First_Contact_Date": "2026-06-13",
                    "Payment_Requested": "Deposit before viewing",
                    "Red_Flags_Observed": "Payment before viewing\nPressure to decide today",
                    "Evidence_URLs": ["https://example.test/listing"],
                }
            )
            self.assertEqual(report["Review_Status"], "Pending")
            self.assertEqual(report["Rental_Offer_Type"], "Direct landlord")
            self.assertEqual(report["Offering_Person_Name"], "Test Landlord")
            self.assertEqual(len(report["Red_Flags_Observed"]), 2)
        finally:
            write_json("user_reports.json", original_reports)

    def test_admin_can_update_report_review_fields(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report({"Title": "Needs review", "Description": "Vague report"})
            updated = update_user_report(
                report["Report_ID"],
                {
                    "Review_Status": "Needs More Info",
                    "Admin_Notes": "Missing contact details.",
                    "Reporter_Feedback": "Please add the channel and contact profile.",
                },
            )
            self.assertEqual(updated["Review_Status"], "Needs More Info")
            self.assertEqual(updated["Admin_Notes"], "Missing contact details.")
            self.assertEqual(updated["Reporter_Feedback"], "Please add the channel and contact profile.")
        finally:
            write_json("user_reports.json", original_reports)

    def test_report_review_update_persists_after_reload(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report({"Title": "Persistent report", "Description": "Check refresh"})
            update_user_report(report["Report_ID"], {"Review_Status": "Verified", "Admin_Notes": "Confirmed duplicate."})
            reloaded = {
                item["Report_ID"]: item
                for item in load_database()["user_reports"]
            }
            self.assertEqual(reloaded[report["Report_ID"]]["Review_Status"], "Verified")
            self.assertEqual(reloaded[report["Report_ID"]]["Admin_Notes"], "Confirmed duplicate.")
        finally:
            write_json("user_reports.json", original_reports)

    def test_admin_can_delete_user_report(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report({"Title": "Delete me", "Description": "Temporary report"})
            self.assertTrue(delete_user_report(report["Report_ID"]))
            report_ids = {item["Report_ID"] for item in load_database()["user_reports"]}
            self.assertNotIn(report["Report_ID"], report_ids)
        finally:
            write_json("user_reports.json", original_reports)

    def test_retrieve_directly_warns_on_verified_report_identifier(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report(
                {
                    "Title": "Known scam contact",
                    "Description": "Reported exact phone number.",
                    "Offering_Contact_Value": "+31 6 1234 5678",
                    "Listing_Address": "Example Street 9, Amsterdam",
                }
            )
            update_user_report(report["Report_ID"], {"Review_Status": "Verified"})
            result = retrieve("Is +31 6 1234 5678 a scam?")
            intel = result["reported_scam_intelligence"]
            self.assertEqual(intel["verified_report_count"], 1)
            self.assertIn("verified scam report", intel["direct_warning"])
        finally:
            write_json("user_reports.json", original_reports)

    def test_retrieve_directly_warns_on_verified_landlord_name(self):
        original_reports = read_json("user_reports.json")
        try:
            report = add_user_report(
                {
                    "Title": "Known scam landlord name",
                    "Description": "Reported exact offering person name.",
                    "Offering_Person_Name": "Alex Housing",
                }
            )
            update_user_report(report["Report_ID"], {"Review_Status": "Verified"})
            result = retrieve("Is Alex Housing a scam landlord?")
            intel = result["reported_scam_intelligence"]
            self.assertEqual(intel["verified_report_count"], 1)
            self.assertIn("verified scam report", intel["direct_warning"])
            self.assertIn("name:alex housing", intel["matches"][0]["match_identifiers"])
        finally:
            write_json("user_reports.json", original_reports)

    def test_retrieve_shows_pending_report_history(self):
        original_reports = read_json("user_reports.json")
        try:
            add_user_report(
                {
                    "Title": "Pending address report",
                    "Description": "Reported exact address.",
                    "Listing_Address": "Suspiciousstraat 10, Delft",
                }
            )
            result = retrieve("I found a room at Suspiciousstraat 10 Delft. Is this safe?")
            intel = result["reported_scam_intelligence"]
            self.assertEqual(intel["pending_report_count"], 1)
            self.assertIn("pending review", intel["direct_warning"])
        finally:
            write_json("user_reports.json", original_reports)

    def test_admin_can_update_verified_case_fields(self):
        original_cases = read_json("cases.json")
        try:
            case_id = original_cases[0]["Case_ID"]
            updated = update_case(case_id, {"Summary": "Corrected summary.", "Red_Flags": "Payment before viewing"})
            self.assertEqual(updated["Summary"], "Corrected summary.")
            self.assertEqual(updated["Red_Flags"], ["Payment before viewing"])
        finally:
            write_json("cases.json", original_cases)

    def test_admin_route_serves_admin_page(self):
        calls = []

        def fake_send_static(handler, filename, content_type):
            calls.append((filename, content_type))

        original_send_static = SafeLandingHandler._send_static
        try:
            SafeLandingHandler._send_static = fake_send_static
            handler = object.__new__(SafeLandingHandler)
            handler.path = "/admin"
            handler.do_GET()
            self.assertEqual(calls, [("admin.html", "text/html; charset=utf-8")])
        finally:
            SafeLandingHandler._send_static = original_send_static


if __name__ == "__main__":
    unittest.main()
