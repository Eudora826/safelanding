from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Project root. This package now lives at <root>/backend/safelanding/, so the
# data directory two levels up resolves to <root>/data. An env override lets
# Docker or tests point at a different location.
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("SAFELANDING_DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "safelanding.db"
DATASETS = {
    "cases.json": ("cases", "Case_ID"),
    "patterns.json": ("patterns", "Pattern_ID"),
    "knowledge_gaps.json": ("knowledge_gaps", "Gap_ID"),
    "user_reports.json": ("user_reports", "Report_ID"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(name: str) -> list[dict[str, Any]]:
    path = DATA_DIR / name
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a JSON array")
    return payload


def write_json(name: str, rows: list[dict[str, Any]]) -> None:
    path = DATA_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    if name in DATASETS:
        dataset, id_field = DATASETS[name]
        _replace_dataset(dataset, id_field, rows)


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
          dataset TEXT NOT NULL,
          record_id TEXT NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (dataset, record_id)
        )
        """
    )
    return connection


def _seed_dataset_if_empty(connection: sqlite3.Connection, dataset: str, filename: str, id_field: str) -> None:
    count = connection.execute("SELECT COUNT(*) FROM records WHERE dataset = ?", (dataset,)).fetchone()[0]
    if count:
        return
    for row in read_json(filename):
        record_id = str(row.get(id_field, "")).strip()
        if not record_id:
            continue
        timestamp = _now()
        connection.execute(
            """
            INSERT INTO records (dataset, record_id, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (dataset, record_id, json.dumps(row, ensure_ascii=False), timestamp, timestamp),
        )
    connection.commit()


def init_database() -> None:
    with _connect() as connection:
        for filename, (dataset, id_field) in DATASETS.items():
            _seed_dataset_if_empty(connection, dataset, filename, id_field)


def _replace_dataset(dataset: str, id_field: str, rows: list[dict[str, Any]]) -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM records WHERE dataset = ?", (dataset,))
        timestamp = _now()
        for row in rows:
            record_id = str(row.get(id_field, "")).strip()
            if not record_id:
                continue
            connection.execute(
                """
                INSERT INTO records (dataset, record_id, payload, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (dataset, record_id, json.dumps(row, ensure_ascii=False), timestamp, timestamp),
            )
        connection.commit()


def _read_records(dataset: str, filename: str, id_field: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        _seed_dataset_if_empty(connection, dataset, filename, id_field)
        rows = connection.execute(
            "SELECT payload FROM records WHERE dataset = ? ORDER BY record_id",
            (dataset,),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def _upsert_record(dataset: str, id_field: str, row: dict[str, Any]) -> None:
    record_id = str(row.get(id_field, "")).strip()
    if not record_id:
        raise ValueError(f"{id_field} is required")
    timestamp = _now()
    with _connect() as connection:
        existing = connection.execute(
            "SELECT created_at FROM records WHERE dataset = ? AND record_id = ?",
            (dataset, record_id),
        ).fetchone()
        created_at = existing["created_at"] if existing else timestamp
        connection.execute(
            """
            INSERT OR REPLACE INTO records (dataset, record_id, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (dataset, record_id, json.dumps(row, ensure_ascii=False), created_at, timestamp),
        )
        connection.commit()


def _delete_record(dataset: str, record_id: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE dataset = ? AND record_id = ?",
            (dataset, record_id),
        )
        connection.commit()
    return cursor.rowcount > 0


def load_database() -> dict[str, list[dict[str, Any]]]:
    return {
        "cases": _read_records("cases", "cases.json", "Case_ID"),
        "patterns": _read_records("patterns", "patterns.json", "Pattern_ID"),
        "knowledge_gaps": _read_records("knowledge_gaps", "knowledge_gaps.json", "Gap_ID"),
        "user_reports": _read_records("user_reports", "user_reports.json", "Report_ID"),
    }


def _pick(payload: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return default


def _list_value(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).splitlines() if part.strip()]


def _update_by_id(dataset: str, filename: str, id_field: str, item_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    rows = _read_records(dataset, filename, id_field)
    for row in rows:
        if str(row.get(id_field)) == item_id:
            row.update(updates)
            row["Updated_At"] = _now()
            _upsert_record(dataset, id_field, row)
            return row
    return None


def add_user_report(payload: dict[str, Any]) -> dict[str, Any]:
    reports = _read_records("user_reports", "user_reports.json", "Report_ID")
    existing_numbers = [
        int(str(report.get("Report_ID", ""))[2:])
        for report in reports
        if str(report.get("Report_ID", "")).startswith("UR") and str(report.get("Report_ID", ""))[2:].isdigit()
    ]
    next_id = f"UR{(max(existing_numbers) if existing_numbers else 0) + 1:04d}"
    report = {
        "Report_ID": next_id,
        "Timestamp": _now(),
        "Title": _pick(payload, "Title", "title", default="Untitled report"),
        "Description": _pick(payload, "Description", "description"),
        "Scam_Category": _pick(payload, "Scam_Category", "scam_category", default="Housing Scam"),
        "Rental_Offer_Type": _pick(payload, "Rental_Offer_Type", "rental_offer_type", default="Unknown"),
        "Location": _pick(payload, "Location", "location", default="Netherlands"),
        "City": _pick(payload, "City", "city"),
        "Listing_Address": _pick(payload, "Listing_Address", "listing_address", "Address", "address"),
        "Listing_URL": _pick(payload, "Listing_URL", "listing_url", "Uploaded_URL", "uploaded_url"),
        "First_Contact_Date": _pick(payload, "First_Contact_Date", "first_contact_date", "Date", "date"),
        "Requested_Move_In_Date": _pick(payload, "Requested_Move_In_Date", "requested_move_in_date"),
        "Offering_Person_Name": _pick(payload, "Offering_Person_Name", "offering_person_name", "Landlord_Name", "landlord_name"),
        "Offering_Person_Role": _pick(payload, "Offering_Person_Role", "offering_person_role"),
        "Offering_Contact_Method": _pick(payload, "Offering_Contact_Method", "offering_contact_method"),
        "Offering_Contact_Value": _pick(payload, "Offering_Contact_Value", "offering_contact_value", "Contact_Info", "contact_info"),
        "Communication_Channel": _pick(payload, "Communication_Channel", "communication_channel"),
        "Communication_Channel_Other": _pick(payload, "Communication_Channel_Other", "communication_channel_other"),
        "Payment_Requested": _pick(payload, "Payment_Requested", "payment_requested"),
        "Payment_Method": _pick(payload, "Payment_Method", "payment_method"),
        "Amount_Requested": _pick(payload, "Amount_Requested", "amount_requested"),
        "Amount_Paid": _pick(payload, "Amount_Paid", "amount_paid", "Estimated_Loss", "estimated_loss"),
        "Threat_Actor": _pick(payload, "Threat_Actor", "threat_actor", default="Unknown"),
        "Red_Flags_Observed": _list_value(_pick(payload, "Red_Flags_Observed", "red_flags_observed")),
        "Uploaded_Text": _pick(payload, "Uploaded_Text", "uploaded_text"),
        "Evidence_URLs": _list_value(_pick(payload, "Evidence_URLs", "evidence_urls", "Uploaded_URL", "uploaded_url")),
        "Evidence_Files": _pick(payload, "Evidence_Files", "evidence_files", default=[]),
        "AI_OCR_Analysis": _pick(payload, "AI_OCR_Analysis", "ai_ocr_analysis"),
        "Reporter_Notes": _pick(payload, "Reporter_Notes", "reporter_notes"),
        "Admin_Notes": "",
        "Reporter_Feedback": "",
        "Review_Status": "Pending",
    }
    _upsert_record("user_reports", "Report_ID", report)
    return report


def update_user_report(report_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    allowed_fields = {
        "Review_Status",
        "Admin_Notes",
        "Reporter_Feedback",
        "Threat_Actor",
        "Rental_Offer_Type",
        "Red_Flags_Observed",
    }
    updates = {key: value for key, value in payload.items() if key in allowed_fields}
    if "Red_Flags_Observed" in updates:
        updates["Red_Flags_Observed"] = _list_value(updates["Red_Flags_Observed"])
    return _update_by_id("user_reports", "user_reports.json", "Report_ID", report_id, updates)


def delete_user_report(report_id: str) -> bool:
    return _delete_record("user_reports", report_id)


def update_case(case_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    allowed_fields = {
        "Title",
        "Source_Name",
        "Source_URL",
        "Country",
        "City",
        "Target_Group",
        "Scam_Category",
        "Subcategory",
        "Threat_Actor",
        "Communication_Channel",
        "Attack_Steps",
        "Knowledge_Gaps",
        "Social_Engineering_Techniques",
        "Requested_Action",
        "Impact",
        "Red_Flags",
        "Summary",
    }
    updates = {key: value for key, value in payload.items() if key in allowed_fields}
    for list_field in ("Attack_Steps", "Knowledge_Gaps", "Social_Engineering_Techniques", "Red_Flags"):
        if list_field in updates:
            updates[list_field] = _list_value(updates[list_field])
    return _update_by_id("cases", "cases.json", "Case_ID", case_id, updates)
