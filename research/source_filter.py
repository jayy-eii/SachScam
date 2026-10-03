"""
Deterministic domain filtering and source classification for SachCheck.
Categorizes sources into strict trust hierarchies without LLM hallucinations.
"""

from typing import List, Tuple
from urllib.parse import urlparse
from config import Config
from research.models import SourceRecord, SourceType


def is_domain_or_subdomain(domain: str, base_domain: str) -> bool:
    """
    Check if a domain exactly matches or is a valid subdomain of a base domain.
    Prevents lookalike domain attacks (e.g., 'sebi-fake.com' or 'fake-sebi.gov.in').
    """
    domain = domain.lower().strip()
    base_domain = base_domain.lower().strip()
    return domain == base_domain or domain.endswith("." + base_domain)


def classify_source_domain(domain: str) -> str:
    """
    Deterministically classifies a domain into trust categories.
    Does NOT rely on page title or LLM guesswork.
    """
    if not domain:
        return SourceType.UNVERIFIED_SOURCE

    clean_domain = domain.lower().strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    # 1. Regulators (SEBI, RBI)
    for sebi_base in Config.OFFICIAL_DOMAINS["SEBI"]:
        if is_domain_or_subdomain(clean_domain, sebi_base):
            return SourceType.OFFICIAL_REGULATOR

    for rbi_base in Config.OFFICIAL_DOMAINS["RBI"]:
        if is_domain_or_subdomain(clean_domain, rbi_base):
            return SourceType.OFFICIAL_REGULATOR

    # 2. Cybercrime reporting & grievance
    for cyber_base in Config.OFFICIAL_DOMAINS["CYBERCRIME"]:
        if is_domain_or_subdomain(clean_domain, cyber_base):
            return SourceType.OFFICIAL_GOVERNMENT

    # 3. General Government (.gov.in, .nic.in)
    for gov_base in Config.OFFICIAL_DOMAINS["GOVERNMENT"]:
        if is_domain_or_subdomain(clean_domain, gov_base):
            return SourceType.OFFICIAL_GOVERNMENT

    # Recognized Exchanges / Intermediaries
    recognized_orgs = ["nseindia.com", "bseindia.com", "amfiindia.com", "cdslindia.com", "nsdl.co.in"]
    for org_base in recognized_orgs:
        if is_domain_or_subdomain(clean_domain, org_base):
            return SourceType.OFFICIAL_ORGANIZATION

    # 4. Reputable financial media
    for media_base in Config.REPUTABLE_SECONDARY_DOMAINS:
        if is_domain_or_subdomain(clean_domain, media_base):
            return SourceType.REPUTABLE_SECONDARY

    return SourceType.UNVERIFIED_SOURCE


def prioritize_sources(sources: List[SourceRecord]) -> List[SourceRecord]:
    """
    Sorts sources prioritizing authoritative official sources:
    OFFICIAL_REGULATOR (1) > OFFICIAL_GOVERNMENT (2) > OFFICIAL_ORGANIZATION (3) >
    REPUTABLE_SECONDARY (4) > UNVERIFIED_SOURCE (5).
    """
    priority_map = {
        SourceType.OFFICIAL_REGULATOR: 1,
        SourceType.OFFICIAL_GOVERNMENT: 2,
        SourceType.OFFICIAL_ORGANIZATION: 3,
        SourceType.REPUTABLE_SECONDARY: 4,
        SourceType.UNVERIFIED_SOURCE: 5,
    }

    # Classify each source if not already classified
    for src in sources:
        src.source_type = classify_source_domain(src.domain)

    # Sort stably by priority, then by relevance score descending if present
    def sort_key(s: SourceRecord) -> Tuple[int, float]:
        prio = priority_map.get(s.source_type, 99)
        rel = -(s.relevance_score or 0.0)
        return (prio, rel)

    return sorted(sources, key=sort_key)
