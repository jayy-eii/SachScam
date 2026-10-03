"""
Unit tests for Phase 2 Live Evidence-Based Claim Verification.
Uses clearly marked MOCK TEST FIXTURES to test Tavily integration without requiring a live API key.
"""

import pytest
from unittest.mock import MagicMock, patch

from research.models import (
    SourceRecord,
    SourceType,
    VerificationStatus,
    ExtractedClaim,
)
from research.providers.tavily_provider import TavilyProvider
from research.source_filter import classify_source_domain, prioritize_sources, is_domain_or_subdomain
from research.claim_extractor import extract_claims, extract_urls, redact_sensitive_information, extract_entity_name
from research.evidence import EvidenceEvaluator
from research.researcher import MessageResearcher
from analyzer.analyzer import MessageAnalyzer


# =====================================================================
# MOCK TEST FIXTURES
# =====================================================================
MOCK_SEBI_OFFICIAL_RESULT = {
    "title": "SEBI | Recognized Stock Brokers Directory",
    "url": "https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognised=yes",
    "content": "Official SEBI Directory: ABC Capital Ltd. Registration No: INZ000123456. Recognized Stock Broker and Investment Adviser.",
    "score": 0.95,
}

MOCK_SEBI_CAUTION_RESULT = {
    "title": "SEBI Caution List | Unregistered Entities",
    "url": "https://www.sebi.gov.in/enforcement/orders/caution-list.html",
    "content": "Public Alert: ABC Capital is not registered with SEBI. Investors are cautioned against dealing with this unregistered entity.",
    "score": 0.92,
}

MOCK_GUARANTEED_PROHIBITION_RESULT = {
    "title": "SEBI Investor Advisory on Guaranteed Returns",
    "url": "https://investor.sebi.gov.in/advisories/no-guaranteed-returns.html",
    "content": "SEBI cautions investors: Promising fixed or guaranteed returns in securities markets is strictly prohibited under SEBI regulations.",
    "score": 0.98,
}

MOCK_EMPTY_RESULT = {"results": []}


# =====================================================================
# 1. PROVIDER & CONFIGURATION TESTS
# =====================================================================
def test_tavily_provider_unconfigured():
    """Provider handles missing API key safely without crashing."""
    provider = TavilyProvider(api_key="")
    assert not provider.is_configured()
    records, err = provider.search("test query")
    assert records == []
    assert "not configured" in err.lower()


def test_tavily_provider_invalid_api_key():
    """Provider catches unauthorized / invalid API key cleanly."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.side_effect = Exception("401 Unauthorized: Invalid API key provided.")
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-invalid-key-1234")
        records, err = provider.search("ABC Capital SEBI")
        assert records == []
        assert "invalid tavily api key" in err.lower()


def test_tavily_provider_successful_parsing():
    """Provider parses authentic search results into SourceRecords without altering URLs."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.return_value = {"results": [MOCK_SEBI_OFFICIAL_RESULT]}
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-valid-mock-key")
        records, err = provider.search("ABC Capital")
        assert err is None
        assert len(records) == 1
        r = records[0]
        assert r.title == "SEBI | Recognized Stock Brokers Directory"
        assert r.url == "https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognised=yes"
        assert r.domain == "sebi.gov.in"
        assert "ABC Capital Ltd" in r.content
        assert r.relevance_score == 0.95


def test_tavily_provider_empty_response():
    """Provider returns empty list when search returns zero results without treating as false."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.return_value = MOCK_EMPTY_RESULT
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-valid-mock-key")
        records, err = provider.search("Unknown Entity That Does Not Exist")
        assert err is None
        assert records == []


def test_tavily_provider_network_and_timeout():
    """Provider handles network timeout without crashing."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.side_effect = Exception("Request timed out after 15 seconds.")
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-valid-mock-key")
        records, err = provider.search("query")
        assert records == []
        assert "timed out" in err.lower()


def test_tavily_provider_rate_limit():
    """Provider handles 429 rate limit without crashing."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.side_effect = Exception("429 Too Many Requests: Rate limit exceeded.")
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-valid-mock-key")
        records, err = provider.search("query")
        assert records == []
        assert "rate limit" in err.lower()


# =====================================================================
# 2. SOURCE FILTERING & DOMAIN CLASSIFICATION TESTS
# =====================================================================
def test_official_domain_classification():
    assert classify_source_domain("sebi.gov.in") == SourceType.OFFICIAL_REGULATOR
    assert classify_source_domain("investor.sebi.gov.in") == SourceType.OFFICIAL_REGULATOR
    assert classify_source_domain("scores.gov.in") == SourceType.OFFICIAL_REGULATOR
    assert classify_source_domain("rbi.org.in") == SourceType.OFFICIAL_REGULATOR
    assert classify_source_domain("sachet.rbi.org.in") == SourceType.OFFICIAL_REGULATOR
    assert classify_source_domain("cybercrime.gov.in") == SourceType.OFFICIAL_GOVERNMENT
    assert classify_source_domain("i4c.gov.in") == SourceType.OFFICIAL_GOVERNMENT
    assert classify_source_domain("mca.gov.in") == SourceType.OFFICIAL_GOVERNMENT


def test_lookalike_domains_rejected():
    """Do NOT accept lookalike domains as official."""
    assert classify_source_domain("fake-sebi-site.com") == SourceType.UNVERIFIED_SOURCE
    assert classify_source_domain("sebi-gov.in.xyz") == SourceType.UNVERIFIED_SOURCE
    assert classify_source_domain("rbi-verification.net") == SourceType.UNVERIFIED_SOURCE
    assert classify_source_domain("official-government.com") == SourceType.UNVERIFIED_SOURCE


def test_reputable_secondary_and_unverified():
    assert classify_source_domain("livemint.com") == SourceType.REPUTABLE_SECONDARY
    assert classify_source_domain("economictimes.indiatimes.com") == SourceType.REPUTABLE_SECONDARY
    assert classify_source_domain("randomblog123.org") == SourceType.UNVERIFIED_SOURCE


def test_source_prioritization():
    s1 = SourceRecord(title="Blog", url="http://blog.com", domain="blog.com", content="", source_type=SourceType.UNVERIFIED_SOURCE)
    s2 = SourceRecord(title="SEBI", url="http://sebi.gov.in", domain="sebi.gov.in", content="", source_type=SourceType.OFFICIAL_REGULATOR)
    s3 = SourceRecord(title="News", url="http://livemint.com", domain="livemint.com", content="", source_type=SourceType.REPUTABLE_SECONDARY)

    sorted_sources = prioritize_sources([s1, s2, s3])
    assert sorted_sources[0].domain == "sebi.gov.in"
    assert sorted_sources[1].domain == "livemint.com"
    assert sorted_sources[2].domain == "blog.com"


# =====================================================================
# 3. CLAIM EXTRACTION & PRIVACY REDACTION TESTS
# =====================================================================
def test_sensitive_credential_redaction():
    text = "Call 9876543210 and send OTP 482019 to unlock your account. Password: pass1234. PIN: 9988."
    redacted = redact_sensitive_information(text)
    assert "482019" not in redacted
    assert "pass1234" not in redacted
    assert "9988" not in redacted
    assert "[REDACTED]" in redacted


def test_claim_and_entity_extraction():
    text = "ABC Capital is SEBI approved and guaranteed 40% returns in 7 days."
    claims = extract_claims(text)
    assert len(claims) >= 2
    claim_types = [c.claim_type for c in claims]
    assert "REGULATORY_REGISTRATION" in claim_types
    assert "GUARANTEED_RETURN" in claim_types

    sebi_claim = next(c for c in claims if c.claim_type == "REGULATORY_REGISTRATION")
    assert sebi_claim.extracted_entity == "ABC Capital"
    assert any('site:sebi.gov.in' in q for q in sebi_claim.search_queries)


def test_url_extraction_and_shortened_detection():
    text = "Join our group at bit.ly/invest-rich or visit https://myportal.org/login"
    urls = extract_urls(text)
    assert len(urls) == 2

    bitly_url = next(u for u in urls if "bit.ly" in u.original_url)
    assert bitly_url.is_shortened is True
    assert bitly_url.domain == "bit.ly"

    portal_url = next(u for u in urls if "myportal.org" in u.original_url)
    assert portal_url.is_https is True
    assert portal_url.is_shortened is False


# =====================================================================
# 4. EVIDENCE EVALUATION & STATUS TESTS
# =====================================================================
def test_status_verified_registration_not_endorsement():
    """
    When registration is confirmed, status is VERIFIED, but the application MUST NOT claim endorsement.
    """
    claim = ExtractedClaim(
        claim_id="c1",
        original_text="ABC Capital is SEBI registered",
        claim_type="REGULATORY_REGISTRATION",
        extracted_entity="ABC Capital",
    )
    src = SourceRecord(
        title="SEBI Recognized Intermediary",
        url="https://sebi.gov.in/brokers/abc.html",
        domain="sebi.gov.in",
        content="ABC Capital is a registered stock broker. Registration No: INZ000123.",
        source_type=SourceType.OFFICIAL_REGULATOR,
    )

    result = EvidenceEvaluator.evaluate_claim(claim, [src])
    assert result.status == VerificationStatus.VERIFIED
    assert "ABC Capital" in result.what_source_establishes
    # Verify mandatory rule: registration != endorsement
    assert "not constitute an endorsement" in result.what_source_does_not_establish.lower()


def test_status_contradicted_debarment():
    """When official regulator has debarred/flagged entity, status is CONTRADICTED."""
    claim = ExtractedClaim(
        claim_id="c1",
        original_text="ABC Capital is SEBI approved",
        claim_type="REGULATORY_REGISTRATION",
        extracted_entity="ABC Capital",
    )
    src = SourceRecord(
        title="SEBI Debarment Order",
        url="https://sebi.gov.in/orders/abc.html",
        domain="sebi.gov.in",
        content="Notice: ABC Capital is unregistered and debarred from securities trading.",
        source_type=SourceType.OFFICIAL_REGULATOR,
    )

    result = EvidenceEvaluator.evaluate_claim(claim, [src])
    assert result.status == VerificationStatus.CONTRADICTED
    assert "cautionary" in result.what_source_establishes.lower() or "unauthorized" in result.what_source_establishes.lower()


def test_status_contradicted_guaranteed_return():
    """Guaranteed returns contradicted by official SEBI regulation prohibiting them."""
    claim = ExtractedClaim(
        claim_id="c2",
        original_text="Guaranteed 40% returns in 7 days",
        claim_type="GUARANTEED_RETURN",
    )
    src = SourceRecord(
        title=MOCK_GUARANTEED_PROHIBITION_RESULT["title"],
        url=MOCK_GUARANTEED_PROHIBITION_RESULT["url"],
        domain="sebi.gov.in",
        content=MOCK_GUARANTEED_PROHIBITION_RESULT["content"],
        source_type=SourceType.OFFICIAL_REGULATOR,
    )

    result = EvidenceEvaluator.evaluate_claim(claim, [src])
    assert result.status == VerificationStatus.CONTRADICTED
    assert "prohibited" in result.what_source_establishes.lower()


def test_status_not_verified_no_records_found():
    """No records found does NOT mean FALSE or CONTRADICTED; status is NOT_VERIFIED."""
    claim = ExtractedClaim(
        claim_id="c1",
        original_text="XYZ Wealth is SEBI registered",
        claim_type="REGULATORY_REGISTRATION",
        extracted_entity="XYZ Wealth",
    )
    src = SourceRecord(
        title="SEBI General Investor Portal",
        url="https://sebi.gov.in/index.html",
        domain="sebi.gov.in",
        content="General guidelines for market participants and investors.",
        source_type=SourceType.OFFICIAL_REGULATOR,
    )

    result = EvidenceEvaluator.evaluate_claim(claim, [src])
    assert result.status == VerificationStatus.NOT_VERIFIED
    # Ensure it's NOT marked as contradicted
    assert result.status != VerificationStatus.CONTRADICTED


def test_status_unable_to_verify_on_search_error():
    claim = ExtractedClaim(
        claim_id="c1",
        original_text="ABC Capital is SEBI registered",
        claim_type="REGULATORY_REGISTRATION",
    )
    result = EvidenceEvaluator.evaluate_claim(claim, [], is_search_successful=False, search_error="Timeout")
    assert result.status == VerificationStatus.UNABLE_TO_VERIFY


def test_fake_source_and_url_prevention():
    """When no search results exist, no fake URLs or sources are fabricated."""
    claim = ExtractedClaim(
        claim_id="c1",
        original_text="Some Random Claim",
        claim_type="GENERAL_FACTUAL_CLAIM",
    )
    result = EvidenceEvaluator.evaluate_claim(claim, [])
    assert result.source_url is None
    assert result.source_title is None
    assert result.status == VerificationStatus.NOT_VERIFIED


# =====================================================================
# 5. INTEGRATION & SEPARATION OF RISK VS VERIFICATION
# =====================================================================
def test_risk_score_and_verification_remain_strictly_separated():
    """
    Phase 1 risk score and Phase 2 research must remain strictly independent.
    Tavily search or verification status MUST NOT modify the Phase 1 risk score.
    """
    text = "URGENT! SEBI approved investment. Guaranteed 40% return in 7 days. Send ₹10,000 to this UPI now."
    analyzer = MessageAnalyzer()
    phase1_result = analyzer.analyze(text)

    assert phase1_result.risk_score == 90
    assert phase1_result.risk_level == "HIGH"

    # Run research with mock provider
    mock_provider = MagicMock(spec=TavilyProvider)
    mock_provider.is_configured.return_value = True
    mock_provider.search.return_value = ([
        SourceRecord(
            title="SEBI Recognized Brokers",
            url="https://sebi.gov.in/brokers.html",
            domain="sebi.gov.in",
            content="Official directory of SEBI brokers.",
            source_type=SourceType.OFFICIAL_REGULATOR,
        )
    ], None)

    researcher = MessageResearcher(provider=mock_provider)
    phase2_report = researcher.research_message(text)

    # Phase 1 score remains completely unchanged
    assert phase1_result.risk_score == 90
    assert phase1_result.risk_level == "HIGH"
    # Phase 2 report has its own structured claims
    assert len(phase2_report.claims) >= 1
    assert phase2_report.is_live is True


def test_offline_fallback_mode_label():
    """When Tavily is unconfigured, research report clearly indicates OFFLINE MODE."""
    unconfigured_provider = TavilyProvider(api_key="")
    researcher = MessageResearcher(provider=unconfigured_provider)

    report = researcher.research_message("SEBI approved fund")
    assert report.is_live is False
    assert "OFFLINE MODE" in report.mode_label
    assert all(c.status == VerificationStatus.UNABLE_TO_VERIFY for c in report.claims)
