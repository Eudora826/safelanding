"""
fusion.py
=========
The brain of the merged app. It joins two previously separate things:

  1. The LIVE analyzer (analysis.collect_signals): rule/LLM text checks, real
     URL heuristics, and OCR on screenshots -> a list of (Tactic, weight).

  2. The SafeLanding DATABASE (safelanding.retrieval.retrieve): TF-IDF retrieval
     over known scam patterns / reference cases / knowledge gaps, PLUS exact
     matching of the submitted phone / email / address / name against past
     community reports stored in SQLite.

The live analyzer answers "does this message *look* like a scam?".
The database answers "have we *seen this specific scammer or pattern* before?".
Fusing them gives a single verdict that is both pattern-aware and memory-aware:
a brand-new message that merely looks risky scores moderate; a message whose
phone number already has a *verified* scam report is forced to DANGEROUS.
"""

from analysis import L, collect_signals
from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    CaseHit,
    PatternHit,
    ReportedIntelligence,
    Tactic,
)
from safelanding.retrieval import retrieve

# How much each kind of database evidence adds to the risk score.
#
# IMPORTANT design note: only REPORTED-IDENTIFIER matches (a phone/email/
# address/name that someone already reported) add to the numeric score. That is
# the genuinely new signal the live detectors cannot know. Free-text pattern/
# case retrieval is treated as *explanatory enrichment* (shown in the UI), not
# as an independent score driver: the live rules already score scam wording, and
# the retrieval score is relative (the top hit is always normalized to 1.0), so
# letting it drive the verdict would false-positive on benign messages.
WEIGHT_VERIFIED_REPORT = 60   # a confirmed scammer identifier -> on its own, dangerous
WEIGHT_PENDING_REPORT = 25    # reported but not yet reviewed


def _report_tactics(intel: dict, lang: str) -> list[tuple[Tactic, int]]:
    """Turn reported-identifier matches into scoring (Tactic, weight) pairs."""
    out: list[tuple[Tactic, int]] = []
    report_intel = intel.get("reported_scam_intelligence", {})

    if report_intel.get("verified_report_count", 0) > 0:
        out.append((Tactic(
            name=L({
                "en": "Reported as a scam before (verified)",
                "zh": "此联系人/地址已被举报并核实为诈骗",
                "nl": "Eerder gemeld als oplichting (geverifieerd)",
            }, lang),
            snippet=f"{report_intel.get('verified_report_count')} verified report(s)",
            explanation=L({
                "en": "This landlord name, phone, email, or address already has a VERIFIED scam report in the community database. Treat it as confirmed fraud.",
                "zh": "这个房东姓名/电话/邮箱/地址在社区数据库里已有经核实的诈骗举报。请直接视为确认诈骗。",
                "nl": "Deze naam, telefoon, e-mail of adres heeft al een GEVERIFIEERDE oplichtingsmelding in de database. Beschouw dit als bevestigde fraude.",
            }, lang),
            source="database",
        ), WEIGHT_VERIFIED_REPORT))
    elif report_intel.get("pending_report_count", 0) > 0:
        out.append((Tactic(
            name=L({
                "en": "Reported before (pending review)",
                "zh": "此联系人/地址曾被举报(待核实)",
                "nl": "Eerder gemeld (in beoordeling)",
            }, lang),
            snippet=f"{report_intel.get('pending_report_count')} pending report(s)",
            explanation=L({
                "en": "This identifier has been reported by others but is not yet verified. Be very cautious.",
                "zh": "已有其他人举报过这个联系方式,但尚未核实。请高度警惕。",
                "nl": "Dit gegeven is door anderen gemeld maar nog niet geverifieerd. Wees zeer voorzichtig.",
            }, lang),
            source="database",
        ), WEIGHT_PENDING_REPORT))

    return out


def _pattern_info_tactic(intel: dict, lang: str) -> Tactic | None:
    """A non-scoring, informational signal naming the closest known pattern.
    Only meaningful to show when risk has already been established."""
    patterns = intel.get("matching_patterns", [])
    if not patterns:
        return None
    item = patterns[0]["item"]
    return Tactic(
        name=L({
            "en": "Matches a known scam pattern",
            "zh": "命中已知诈骗套路",
            "nl": "Komt overeen met bekend oplichtingspatroon",
        }, lang) + f": {item.get('Pattern_Name', '')}",
        snippet=", ".join(patterns[0].get("matched_terms", [])[:6]),
        explanation=item.get("Description", ""),
        source="database",
    )


def fuse(req: AnalyzeRequest) -> AnalyzeResponse:
    lang = req.native_language

    # 1) Live detectors + the combined text (typed + url + OCR'd image text).
    live_findings, inputs, combined_text = collect_signals(req)

    # 2) Database retrieval over everything the user submitted.
    intel = retrieve(combined_text, top_n=3) if combined_text else {
        "reported_scam_intelligence": {"direct_warning": "", "matched_report_count": 0,
                                       "verified_report_count": 0, "pending_report_count": 0},
        "matching_patterns": [], "similar_cases": [],
        "likely_threat_actors": [], "recommended_actions": [],
    }
    if combined_text:
        inputs.append("database")

    report_intel = intel.get("reported_scam_intelligence", {})
    verified = report_intel.get("verified_report_count", 0) > 0
    pending = report_intel.get("pending_report_count", 0) > 0

    # 3) Scoring stream = live findings + reported-identifier matches only.
    report_findings = _report_tactics(intel, lang)
    scoring = live_findings + report_findings

    score = min(100, sum(w for _, w in scoring))
    if not scoring:
        score = 5
    if verified:
        score = max(score, 85)  # a confirmed scammer is dangerous regardless of wording

    if score >= 60:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # 4) Enrichment is shown only when risk is already established, so a clean
    #    message never gets a scary "matches a known scam pattern" panel.
    has_risk = bool(live_findings) or verified or pending or verdict != "safe"

    display_tactics = [t for t, _ in scoring]
    if has_risk:
        info = _pattern_info_tactic(intel, lang)
        if info is not None:
            display_tactics.append(info)

    matching_patterns = intel.get("matching_patterns", []) if has_risk else []
    similar_cases = intel.get("similar_cases", []) if has_risk else []
    threat_actors = intel.get("likely_threat_actors", []) if has_risk else []
    recommended = intel.get("recommended_actions", []) if has_risk else []

    # 5) Summary (lead with the database warning when present).
    n = len(display_tactics)
    direct_warning = report_intel.get("direct_warning", "")
    base_summary = {
        "en": (f"Found {n} warning sign(s). Treat this with high caution." if verdict == "dangerous"
               else f"Found {n} warning sign(s). Be careful and verify." if verdict == "suspicious"
               else "No clear scam signals detected - but stay alert."),
        "zh": (f"发现 {n} 个危险信号,请高度警惕。" if verdict == "dangerous"
               else f"发现 {n} 个可疑信号,请小心核实。" if verdict == "suspicious"
               else "没有发现明显诈骗信号——但仍要保持警惕。"),
        "nl": (f"{n} waarschuwingssignaal(en) gevonden. Wees zeer voorzichtig." if verdict == "dangerous"
               else f"{n} waarschuwingssignaal(en) gevonden. Wees voorzichtig en controleer." if verdict == "suspicious"
               else "Geen duidelijke scam-signalen - blijf toch alert."),
    }
    summary = L(base_summary, lang)
    if direct_warning:
        summary = direct_warning + " " + summary

    # 6) Build the response, carrying the database intelligence alongside.
    from analysis import _spotting_tips  # local import to avoid cycle at module load

    return AnalyzeResponse(
        verdict=verdict,
        risk_score=score,
        summary=summary,
        original_message=combined_text,
        inputs_analyzed=inputs,
        tactics=display_tactics,
        how_to_spot=_spotting_tips(lang, "url" in inputs),
        reported_intelligence=ReportedIntelligence(
            direct_warning=direct_warning,
            matched_report_count=report_intel.get("matched_report_count", 0),
            verified_report_count=report_intel.get("verified_report_count", 0),
            pending_report_count=report_intel.get("pending_report_count", 0),
        ),
        matching_patterns=[
            PatternHit(
                name=h["item"].get("Pattern_Name", ""),
                description=h["item"].get("Description", ""),
                score=h.get("score", 0.0),
            )
            for h in matching_patterns
        ],
        similar_cases=[
            CaseHit(
                title=h["item"].get("Title", ""),
                city=h["item"].get("City", ""),
                source_url=h["item"].get("Source_URL", ""),
                score=h.get("score", 0.0),
            )
            for h in similar_cases
        ],
        likely_threat_actors=threat_actors,
        recommended_actions=recommended,
    )
