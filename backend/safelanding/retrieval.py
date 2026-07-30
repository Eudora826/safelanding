from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from .data_store import load_database

TOKEN_RE = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+31|0031|0)[\d\s().-]{7,}\d")
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "before",
    "but",
    "by",
    "for",
    "from",
    "i",
    "in",
    "is",
    "it",
    "me",
    "my",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}

SEARCH_FIELDS = {
    "cases": [
        "Title",
        "City",
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
    ],
    "patterns": [
        "Pattern_Name",
        "Description",
        "Typical_Threat_Actor",
        "Common_Channels",
        "Trigger_Phrases",
        "Knowledge_Gaps",
        "Red_Flags",
        "Recommended_Actions",
    ],
    "knowledge_gaps": [
        "Gap_Name",
        "Description",
        "Why_It_Matters",
        "Safe_Guidance",
        "Related_Patterns",
    ],
}


def tokenize(text: str) -> list[str]:
    return [
        token.lower()
        for token in TOKEN_RE.findall(text)
        if len(token) > 1 and token.lower() not in STOPWORDS
    ]


def flatten(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(flatten(item) for item in value)
    if isinstance(value, dict):
        return " ".join(flatten(item) for item in value.values())
    return "" if value is None else str(value)


def document_text(row: dict[str, Any], fields: list[str]) -> str:
    return " ".join(flatten(row.get(field, "")) for field in fields)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if digits.startswith("0031"):
        digits = "31" + digits[4:]
    if digits.startswith("0") and len(digits) >= 10:
        digits = "31" + digits[1:]
    return digits


def normalize_address(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return re.sub(r"\s+", " ", normalized).strip()


def normalize_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return re.sub(r"\s+", " ", normalized).strip()


def report_identifiers(report: dict[str, Any]) -> dict[str, set[str]]:
    text_fields = [
        flatten(report.get("Offering_Contact_Value", "")),
        flatten(report.get("Listing_Address", "")),
        flatten(report.get("Listing_URL", "")),
        flatten(report.get("Uploaded_Text", "")),
        flatten(report.get("Evidence_URLs", "")),
    ]
    joined = " ".join(text_fields)
    emails = {email.lower() for email in EMAIL_RE.findall(joined)}
    phones = {normalize_phone(phone) for phone in PHONE_RE.findall(joined)}
    phones = {phone for phone in phones if len(phone) >= 10}

    addresses: set[str] = set()
    address = normalize_address(flatten(report.get("Listing_Address", "")))
    if len(address) >= 8:
        addresses.add(address)

    names: set[str] = set()
    name = normalize_name(flatten(report.get("Offering_Person_Name", "")))
    if len(name) >= 3 and name != "unknown":
        names.add(name)

    contact = flatten(report.get("Offering_Contact_Value", "")).strip().lower()
    if contact and "@" not in contact:
        normalized_contact = normalize_phone(contact)
        if len(normalized_contact) >= 10:
            phones.add(normalized_contact)

    return {"emails": emails, "phones": phones, "addresses": addresses, "names": names}


def input_identifiers(message: str) -> dict[str, set[str]]:
    emails = {email.lower() for email in EMAIL_RE.findall(message)}
    phones = {normalize_phone(phone) for phone in PHONE_RE.findall(message)}
    phones = {phone for phone in phones if len(phone) >= 10}
    normalized_message = normalize_address(message)
    return {
        "emails": emails,
        "phones": phones,
        "addresses": {normalized_message} if normalized_message else set(),
        "names": {normalize_name(message)} if message else set(),
    }


def identifier_overlap(query_ids: dict[str, set[str]], report_ids: dict[str, set[str]]) -> list[str]:
    matches: list[str] = []
    for email in sorted(query_ids["emails"] & report_ids["emails"]):
        matches.append(f"email:{email}")
    for phone in sorted(query_ids["phones"] & report_ids["phones"]):
        matches.append(f"phone:{phone}")
    for address in sorted(report_ids["addresses"]):
        if address and any(address in query_address or query_address in address for query_address in query_ids["addresses"]):
            matches.append(f"address:{address}")
    for name in sorted(report_ids["names"]):
        if name and any(name in query_name for query_name in query_ids["names"]):
            matches.append(f"name:{name}")
    return matches


def matching_report_intelligence(message: str, reports: list[dict[str, Any]]) -> dict[str, Any]:
    query_ids = input_identifiers(message)
    matched: list[dict[str, Any]] = []
    for report in reports:
        identifiers = identifier_overlap(query_ids, report_identifiers(report))
        if identifiers:
            matched.append({"match_identifiers": identifiers, "item": report})

    verified = [hit for hit in matched if hit["item"].get("Review_Status") == "Verified"]
    pending = [hit for hit in matched if hit["item"].get("Review_Status") == "Pending"]
    status_counts = Counter(hit["item"].get("Review_Status", "Unknown") for hit in matched)

    direct_warning = ""
    if verified:
        direct_warning = "This landlord/name, phone, email, or address has a verified scam report in the database."
    elif pending:
        direct_warning = "This landlord/name, phone, email, or address has been reported before and is still pending review."

    return {
        "matched_report_count": len(matched),
        "verified_report_count": len(verified),
        "pending_report_count": len(pending),
        "status_counts": dict(status_counts),
        "direct_warning": direct_warning,
        "matches": matched,
    }


def score_rows(query: str, rows: list[dict[str, Any]], fields: list[str], top_n: int) -> list[dict[str, Any]]:
    query_terms = Counter(tokenize(query))
    if not query_terms:
        return []

    docs = [Counter(tokenize(document_text(row, fields))) for row in rows]
    doc_count = max(len(docs), 1)
    idf: dict[str, float] = {}
    for term in query_terms:
        containing = sum(1 for doc in docs if term in doc)
        idf[term] = math.log((doc_count + 1) / (containing + 1)) + 1

    scored: list[tuple[float, dict[str, Any], list[str]]] = []
    for row, doc_terms in zip(rows, docs):
        score = 0.0
        matched: list[str] = []
        for term, q_weight in query_terms.items():
            if term in doc_terms:
                score += (1 + math.log(doc_terms[term])) * idf[term] * q_weight
                matched.append(term)
        if score > 0:
            scored.append((score, row, matched))

    scored.sort(key=lambda item: item[0], reverse=True)
    max_score = scored[0][0] if scored else 1.0
    return [
        {
            "score": round(score / max_score, 3),
            "matched_terms": matched[:12],
            "item": row,
        }
        for score, row, matched in scored[:top_n]
    ]


def unique_ordered(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    output: list[Any] = []
    for value in values:
        key = flatten(value).lower()
        if key and key not in seen:
            seen.add(key)
            output.append(value)
    return output


def retrieve(message: str, top_n: int = 3, db: dict[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    db = db or load_database()
    top_n = max(1, min(int(top_n), 10))
    patterns = score_rows(message, db["patterns"], SEARCH_FIELDS["patterns"], top_n)
    cases = score_rows(message, db["cases"], SEARCH_FIELDS["cases"], top_n)
    gaps = score_rows(message, db["knowledge_gaps"], SEARCH_FIELDS["knowledge_gaps"], top_n)
    report_intelligence = matching_report_intelligence(message, db["user_reports"])

    threat_actors = unique_ordered(
        [hit["item"].get("Typical_Threat_Actor") for hit in patterns]
        + [hit["item"].get("Threat_Actor") for hit in cases]
    )
    red_flags = unique_ordered(
        [flag for hit in patterns for flag in hit["item"].get("Red_Flags", [])]
        + [flag for hit in cases for flag in hit["item"].get("Red_Flags", [])]
    )
    recommended_actions = unique_ordered(
        [action for hit in patterns for action in hit["item"].get("Recommended_Actions", [])]
        + [hit["item"].get("Safe_Guidance") for hit in gaps]
    )

    return {
        "input": message,
        "top_n": top_n,
        "likely_threat_actors": threat_actors[:5],
        "matching_patterns": patterns,
        "similar_cases": cases,
        "relevant_knowledge_gaps": gaps,
        "reported_scam_intelligence": report_intelligence,
        "red_flags": red_flags[:10],
        "recommended_actions": recommended_actions[:10],
    }
