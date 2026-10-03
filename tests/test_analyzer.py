"""
Comprehensive test suite for the SachCheck Message Analyzer.
Verifies all 6 detection categories, Hindi/Hinglish support, case-insensitivity,
Unicode/currency symbols, deduplication, scoring thresholds, and false-positive handling.
"""

import pytest
from analyzer.analyzer import MessageAnalyzer
from analyzer.scoring import calculate_risk_level
from utils.highlighting import highlight_risk_evidence


@pytest.fixture
def analyzer():
    return MessageAnalyzer()


# =====================================================================
# 1. GUARANTEED / CERTAIN RETURNS (5 examples)
# =====================================================================
def test_guaranteed_return_english_basic(analyzer):
    text = "Join our fund for guaranteed returns every month with zero loss."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "GUARANTEED_RETURN" in categories
    assert res.risk_score >= 30


def test_guaranteed_return_fixed_profit(analyzer):
    text = "Get fixed profit of 40% every week. Risk free investment opportunity."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "GUARANTEED_RETURN" in categories
    assert any("risk free" in p.lower() or "fixed profit" in p.lower() for p in res.all_matched_phrases)


def test_guaranteed_return_hinglish(analyzer):
    text = "Bhai guaranteed profit hai! loss bilkul nahi hoga, paise double ho jayenge 30 din mein."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "GUARANTEED_RETURN" in categories
    assert res.risk_score >= 30


def test_guaranteed_return_percentage(analyzer):
    text = "Guaranteed 50% return assured on intraday trading calls."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "GUARANTEED_RETURN" in categories


def test_guaranteed_return_capital_protection(analyzer):
    text = "100% capital protection guaranteed with double your money in 6 months."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "GUARANTEED_RETURN" in categories


# =====================================================================
# 2. URGENCY / FOMO (3 examples)
# =====================================================================
def test_urgency_english_urgent(analyzer):
    text = "URGENT! Limited slots available. Act now to secure your entry."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "URGENCY_FOMO" in categories
    assert res.risk_score >= 15


def test_urgency_hinglish(analyzer):
    text = "Sirf aaj ke liye special offer hai. Jaldi karo, mauka mat chhodo!"
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "URGENCY_FOMO" in categories


def test_urgency_market_opens(analyzer):
    text = "Don't miss this opportunity before market opens. Only 5 slots remaining."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "URGENCY_FOMO" in categories


# =====================================================================
# 3. PAYMENT REQUEST (3 examples)
# =====================================================================
def test_payment_request_rupee_amount(analyzer):
    text = "Send ₹10,000 registration fee to activate your investor VIP portal."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "PAYMENT_REQUEST" in categories
    assert res.risk_score >= 25


def test_payment_request_upi_id(analyzer):
    text = "Transfer now via UPI to trader.expert@okaxis for immediate processing."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "PAYMENT_REQUEST" in categories


def test_payment_request_hinglish(analyzer):
    text = "Mere account me bhejo ya UPI pe payment karo abhi."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "PAYMENT_REQUEST" in categories


# =====================================================================
# 4. AUTHORITY / IMPERSONATION CLAIMS (3 examples)
# =====================================================================
def test_authority_sebi_approved(analyzer):
    text = "Our trades are SEBI approved and handled by an official broker team."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "AUTHORITY_IMPERSONATION" in categories
    assert res.risk_score >= 20


def test_authority_rbi_approved(analyzer):
    text = "Invest in this RBI approved investment scheme with institutional secret tips."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "AUTHORITY_IMPERSONATION" in categories


def test_authority_hinglish(analyzer):
    text = "Ye plan SEBI se approved hai aur hamare paas insider information hai."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "AUTHORITY_IMPERSONATION" in categories


def test_authority_sebi_alone_does_not_trigger(analyzer):
    """The word 'SEBI' by itself must NOT trigger authority claim."""
    text = "SEBI regulates securities markets in India to protect investor interests."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "AUTHORITY_IMPERSONATION" not in categories
    assert res.risk_level == "LOW"


# =====================================================================
# 5. SUSPICIOUS LINK PATTERNS (2 examples)
# =====================================================================
def test_suspicious_link_bitly(analyzer):
    text = "Click to join our trading channel: bit.ly/easy-wealth-crypto"
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "SUSPICIOUS_LINK" in categories
    assert res.risk_score >= 20


def test_suspicious_link_tinyurl(analyzer):
    text = "Check the daily portfolio gains here: tinyurl.com/fast-crypto-pnl"
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "SUSPICIOUS_LINK" in categories


# =====================================================================
# 6. MANIPULATIVE TRADING LANGUAGE (2 examples)
# =====================================================================
def test_manipulative_trading_insider_operator(analyzer):
    text = "Get exclusive operator tips and sure shot insider tips on penny stocks."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "MANIPULATIVE_TRADING" in categories
    assert res.risk_score >= 15


def test_manipulative_trading_hinglish(analyzer):
    text = "Kal subah jackpot tip aayega! Operator game chal raha hai, pakka breakout share hai."
    res = analyzer.analyze(text)
    categories = [i.category_id for i in res.indicators]
    assert "MANIPULATIVE_TRADING" in categories


# =====================================================================
# 7. DEDUPLICATION & SCORING TESTS
# =====================================================================
def test_category_deduplication(analyzer):
    """
    Multiple patterns from the same category should only score +30 once,
    while preserving all matched phrases as evidence.
    """
    text = "We guarantee guaranteed profit, fixed profit, no loss, and risk free trading!"
    res = analyzer.analyze(text)
    # Even though 4 patterns matched, score for GUARANTEED_RETURN should only count once (+30)
    assert res.risk_score == 30
    gr_indicators = [i for i in res.indicators if i.category_id == "GUARANTEED_RETURN"]
    assert len(gr_indicators) == 1
    # Multiple distinct phrases should be preserved
    assert len(gr_indicators[0].matched_phrases) >= 3


def test_risk_level_thresholds():
    assert calculate_risk_level(0) == "LOW"
    assert calculate_risk_level(15) == "LOW"
    assert calculate_risk_level(19) == "LOW"
    assert calculate_risk_level(20) == "MEDIUM"
    assert calculate_risk_level(30) == "MEDIUM"
    assert calculate_risk_level(44) == "MEDIUM"
    assert calculate_risk_level(45) == "HIGH"
    assert calculate_risk_level(90) == "HIGH"
    assert calculate_risk_level(120) == "HIGH"


def test_benchmark_high_risk_message(analyzer):
    """Benchmark message from hackathon specification scoring 90."""
    text = "URGENT! Guaranteed 40% return in 7 days. SEBI approved opportunity. Send ₹10,000 to this UPI now."
    res = analyzer.analyze(text)
    assert res.risk_score == 90
    assert res.risk_level == "HIGH"
    categories = {i.category_id for i in res.indicators}
    assert categories == {
        "GUARANTEED_RETURN",
        "PAYMENT_REQUEST",
        "AUTHORITY_IMPERSONATION",
        "URGENCY_FOMO",
    }


# =====================================================================
# 8. FALSE POSITIVE TESTS (EDUCATIONAL & CAUTIONARY CONTEXTS)
# =====================================================================
def test_false_positive_sebi_education(analyzer):
    text = "SEBI investor education resources explain that investors should verify information before investing."
    res = analyzer.analyze(text)
    assert res.risk_level == "LOW"
    assert res.risk_score == 0
    assert len(res.indicators) == 0


def test_false_positive_general_education(analyzer):
    text = "This educational article explains market volatility, diversification, and investment risk."
    res = analyzer.analyze(text)
    assert res.risk_level == "LOW"
    assert res.risk_score == 0
    assert len(res.indicators) == 0


def test_false_positive_never_share_credentials(analyzer):
    text = "Never share your OTP or PIN with anyone under any circumstances."
    res = analyzer.analyze(text)
    assert res.risk_level == "LOW"
    assert res.risk_score == 0
    assert len(res.indicators) == 0


def test_false_positive_warning_against_guaranteed_returns(analyzer):
    text = "Investors should be careful about guaranteed-return scams operating on social media."
    res = analyzer.analyze(text)
    assert res.risk_level == "LOW"
    assert res.risk_score == 0
    assert len(res.indicators) == 0


# =====================================================================
# 9. CASE INSENSITIVITY & UNICODE TESTS
# =====================================================================
def test_case_insensitivity(analyzer):
    text = "uRgEnT! gUaRaNtEeD 20% rEtUrN. sEnD ₹500 vIa uPi."
    res = analyzer.analyze(text)
    assert res.risk_score >= 45
    assert res.risk_level == "HIGH"


def test_unicode_and_emojis(analyzer):
    text = "🚀🚀 URGENT! Guaranteed return of ₹50,000! 💰💰 Send ₹10,000 via UPI."
    res = analyzer.analyze(text)
    assert res.risk_score >= 45
    assert res.risk_level == "HIGH"


# =====================================================================
# 10. TEXT HIGHLIGHTING & HTML SAFETY
# =====================================================================
def test_html_safety_in_highlighting():
    dirty_text = "<script>alert('xss')</script> URGENT message."
    spans = [(31, 37, "Urgency")]
    html_out = highlight_risk_evidence(dirty_text, spans)
    assert "<script>" not in html_out
    assert "&lt;script&gt;" in html_out
    assert '<mark class="risk-highlight"' in html_out


def test_explanations_and_safe_steps(analyzer):
    text = "URGENT! Send ₹10,000 via UPI now."
    res = analyzer.analyze(text)
    assert len(res.explanation_en) > 20
    assert len(res.explanation_hi) > 20
    assert len(res.safe_next_steps) >= 2
    # Verify that safe steps include cybercrime helpline
    assert any("cybercrime.gov.in" in step or "1930" in step for step in res.safe_next_steps)
