"""
models.py
=========
Pydantic data shapes for the merged app.

Two halves are fused here:
  - The live analyzer (text / url / image -> tactics + score), and
  - The SafeLanding threat-intelligence database (matching patterns, similar
    cases, recommended actions, and warnings about already-reported scammers).

AnalyzeResponse therefore carries BOTH the live findings and the database
intelligence, so the frontend can render one combined verdict.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------- Request body: what the frontend POSTs to /api/analyze ----------
class AnalyzeRequest(BaseModel):
    text: str = Field(default="", description="Suspicious message text")
    url: str = Field(default="", description="Suspicious link")
    images_base64: list[str] = Field(default_factory=list, description="List of base64 images (no data: prefix)")
    native_language: str = Field(default="English", description="Language used to explain the result")

    @model_validator(mode="after")
    def at_least_one_input(self):
        has_image = any(img.strip() for img in self.images_base64)
        if not (self.text.strip() or self.url.strip() or has_image):
            raise ValueError("Provide at least one of: text, url, or image.")
        return self


# ---------- One "risk signal" inside the response ----------
class Tactic(BaseModel):
    name: str = Field(..., description="Signal type")
    snippet: str = Field(..., description="The specific fragment that triggered it")
    explanation: str = Field(..., description="Why it is dangerous, in the user's language")
    source: str = Field(default="live", description="Where the signal came from: 'live' detector or 'database'")


# ---------- Database-derived blocks (from the retrieval engine) ----------
class ReportedIntelligence(BaseModel):
    """Summary of whether this scammer's phone/email/address/name was reported before."""
    direct_warning: str = Field(default="", description="Plain-language warning if a match exists")
    matched_report_count: int = 0
    verified_report_count: int = 0
    pending_report_count: int = 0


class PatternHit(BaseModel):
    name: str
    description: str = ""
    score: float = 0.0


class CaseHit(BaseModel):
    title: str
    city: str = ""
    source_url: str = ""
    score: float = 0.0


# ---------- Response body ----------
class AnalyzeResponse(BaseModel):
    # --- live verdict (fused score across live signals + database) ---
    verdict: str = Field(..., description="safe / suspicious / dangerous")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    summary: str = Field(..., description="One-sentence summary")
    original_message: str = Field(default="", description="Cleaned text extracted from image OCR / user input, shown in the UI")
    inputs_analyzed: list[str] = Field(default_factory=list)
    tactics: list[Tactic] = Field(default_factory=list, description="Detected risk signals (live + database)")
    how_to_spot: list[str] = Field(default_factory=list)

    # --- database intelligence (the new half) ---
    reported_intelligence: ReportedIntelligence = Field(default_factory=ReportedIntelligence)
    matching_patterns: list[PatternHit] = Field(default_factory=list)
    similar_cases: list[CaseHit] = Field(default_factory=list)
    likely_threat_actors: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


# ---------- Report submission (POST /api/reports) ----------
class ReportIn(BaseModel):
    """Lenient: the database layer (add_user_report) accepts many aliases and
    fills sensible defaults, so we allow extra fields and require nothing."""
    model_config = ConfigDict(extra="allow")

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)
