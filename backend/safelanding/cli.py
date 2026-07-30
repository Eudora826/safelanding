from __future__ import annotations

import argparse
import json

from .data_store import add_user_report
from .retrieval import retrieve


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeLanding AI threat intelligence CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve patterns, cases, and knowledge gaps")
    retrieve_parser.add_argument("message", help="User message to analyze")
    retrieve_parser.add_argument("--top-n", type=int, default=3)

    report_parser = subparsers.add_parser("report", help="Store a pending community report")
    report_parser.add_argument("--title", required=True)
    report_parser.add_argument("--description", required=True)
    report_parser.add_argument("--rental-offer-type", default="Unknown")
    report_parser.add_argument("--offering-person-name", default="")
    report_parser.add_argument("--contact-info", default="")
    report_parser.add_argument("--location", default="Netherlands")
    report_parser.add_argument("--address", default="")
    report_parser.add_argument("--first-contact-date", default="")
    report_parser.add_argument("--payment-requested", default="")
    report_parser.add_argument("--loss", default="")
    report_parser.add_argument("--url", default="")

    args = parser.parse_args()
    if args.command == "retrieve":
        print(json.dumps(retrieve(args.message, args.top_n), indent=2, ensure_ascii=False))
    elif args.command == "report":
        report = add_user_report(
            {
                "Title": args.title,
                "Description": args.description,
                "Rental_Offer_Type": args.rental_offer_type,
                "Offering_Person_Name": args.offering_person_name,
                "Offering_Contact_Value": args.contact_info,
                "Location": args.location,
                "Listing_Address": args.address,
                "First_Contact_Date": args.first_contact_date,
                "Payment_Requested": args.payment_requested,
                "Amount_Paid": args.loss,
                "Listing_URL": args.url,
            }
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
