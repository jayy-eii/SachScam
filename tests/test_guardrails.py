"""
Tests for financial advice guardrails in SachCheck.
Ensures the system strictly refuses to provide Buy/Sell/Hold recommendations,
stock predictions, or investment tips, and returns the mandatory refusal message.
"""

import pytest
from analyzer.analyzer import MessageAnalyzer
from analyzer.rules import ADVICE_REFUSAL_MESSAGE


@pytest.fixture
def analyzer():
    return MessageAnalyzer()


def test_guardrail_should_i_buy(analyzer):
    text = "Should I buy XYZ stock?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE
    assert res.risk_level == "LOW"
    assert res.risk_score == 0


def test_guardrail_which_stock_to_buy(analyzer):
    text = "Which stock should I buy today for fast profits?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE


def test_guardrail_sell_or_hold(analyzer):
    text = "I have 100 shares of Reliance. Sell or hold?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE


def test_guardrail_will_stock_go_up(analyzer):
    text = "Will this stock go up tomorrow?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE


def test_guardrail_highest_return_share(analyzer):
    text = "Which share will give the highest return in 2026?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE


def test_guardrail_hinglish(analyzer):
    text = "Kya mujhe ye stock kharidna chahiye ya kaunsa share best return dega?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert res.advice_refusal_message == ADVICE_REFUSAL_MESSAGE


def test_guardrail_safe_steps_present(analyzer):
    text = "Should I invest in ABC token?"
    res = analyzer.analyze(text)
    assert res.is_advice_request is True
    assert any("SEBI-registered" in step for step in res.safe_next_steps)
