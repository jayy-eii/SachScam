"""
Configuration module for SachCheck.
Safely loads environment variables and provides global settings for live research.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load variables from .env file if present
load_dotenv()


class Config:
    """Application configuration and Tavily settings."""

    # Tavily API Configuration
    TAVILY_API_KEY: str = os.getenv("TAVILY_API_KEY", "").strip()
    TAVILY_SEARCH_DEPTH: str = "advanced"
    TAVILY_MAX_RESULTS: int = 5
    TAVILY_TIMEOUT_SECONDS: float = 15.0

    # Official regulatory and government domain registries
    OFFICIAL_DOMAINS = {
        "SEBI": [
            "sebi.gov.in",
            "scores.gov.in",
            "investor.sebi.gov.in",
        ],
        "RBI": [
            "rbi.org.in",
            "sachet.rbi.org.in",
        ],
        "GOVERNMENT": [
            "gov.in",
            "nic.in",
            "india.gov.in",
            "mca.gov.in",
        ],
        "CYBERCRIME": [
            "cybercrime.gov.in",
            "i4c.gov.in",
            "ceir.gov.in",
        ],
    }

    # Reputable secondary sources (financial press & official news)
    REPUTABLE_SECONDARY_DOMAINS = [
        "economictimes.indiatimes.com",
        "livemint.com",
        "business-standard.com",
        "thehindubusinessline.com",
        "moneycontrol.com",
        "reuters.com",
        "bloomberg.com",
        "financialexpress.com",
        "ndtvprofit.com",
    ]

    @classmethod
    def is_tavily_configured(cls) -> bool:
        """Return True if a non-empty Tavily API key is configured."""
        return bool(cls.TAVILY_API_KEY and len(cls.TAVILY_API_KEY) > 5)

    @classmethod
    def get_masked_api_key(cls) -> str:
        """Return safely masked API key for UI indicators without exposing the secret."""
        if not cls.is_tavily_configured():
            return "Not Configured (Offline Mode)"
        key = cls.TAVILY_API_KEY
        if len(key) <= 8:
            return "Configured (••••)"
        return f"{key[:4]}••••{key[-4:]}"
