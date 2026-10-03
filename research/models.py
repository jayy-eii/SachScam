"""
Data models for Phase 2 Live Evidence-Based Claim Verification.
All structures strictly represent real retrieved data or deterministic evaluation states.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


class VerificationStatus:
    """Standardized verification statuses per specification."""
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SourceType:
    """Deterministic source classifications."""
    OFFICIAL_REGULATOR = "OFFICIAL_REGULATOR"
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    OFFICIAL_ORGANIZATION = "OFFICIAL_ORGANIZATION"
    REPUTABLE_SECONDARY = "REPUTABLE_SECONDARY"
    UNVERIFIED_SOURCE = "UNVERIFIED_SOURCE"


@dataclass
class SourceRecord:
    """
    Preserves actual retrieved data from Tavily search results.
    Never fabricated or hallucinated.
    """
    title: str
    url: str
    domain: str
    content: str
    source_type: str = SourceType.UNVERIFIED_SOURCE
    retrieved_at: str = ""
    relevance_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtractedClaim:
    """Represents an extracted factual claim requiring external research."""
    claim_id: str
    original_text: str
    claim_type: str  # e.g., 'REGULATORY_REGISTRATION', 'GUARANTEED_RETURN', 'ENTITY_AFFILIATION'
    extracted_entity: Optional[str] = None
    search_queries: List[str] = field(default_factory=list)
    requires_external_search: bool = True


@dataclass
class ClaimVerificationResult:
    """
    Evidence-based evaluation of a specific claim.
    Links real retrieved sources to claim status.
    """
    claim_id: str
    original_claim: str
    claim_type: str
    status: str  # VerificationStatus
    source_title: Optional[str] = None
    source_url: Optional[str] = None
    source_domain: Optional[str] = None
    source_type: Optional[str] = None
    relevant_text: Optional[str] = None
    what_source_establishes: str = "Not available"
    what_source_does_not_establish: str = "Not available"
    retrieved_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtractedUrlInfo:
    """Analysis of URLs extracted from the user's message."""
    original_url: str
    domain: str
    is_https: bool
    is_shortened: bool
    resolved_destination: Optional[str] = None
    note: str = ""


@dataclass
class ResearchReport:
    """
    Complete report of Phase 2 live evidence-based research.
    Remains strictly separate from the Phase 1 deterministic risk score.
    """
    is_live: bool
    mode_label: str  # 'LIVE WEB VERIFICATION' or 'OFFLINE MODE — LIVE WEB VERIFICATION NOT CONFIGURED'
    claims: List[ClaimVerificationResult] = field(default_factory=list)
    sources: List[SourceRecord] = field(default_factory=list)
    extracted_urls: List[ExtractedUrlInfo] = field(default_factory=list)
    steps_performed: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
