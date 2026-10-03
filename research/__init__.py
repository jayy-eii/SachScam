"""
SachCheck Research Package.
Provides Phase 2 Live Evidence-Based Claim Verification using Tavily.
"""

from research.models import (
    ResearchReport,
    ClaimVerificationResult,
    SourceRecord,
    ExtractedUrlInfo,
    VerificationStatus,
    SourceType,
)
from research.researcher import MessageResearcher
from research.providers.tavily_provider import TavilyProvider

__all__ = [
    "MessageResearcher",
    "TavilyProvider",
    "ResearchReport",
    "ClaimVerificationResult",
    "SourceRecord",
    "ExtractedUrlInfo",
    "VerificationStatus",
    "SourceType",
]
