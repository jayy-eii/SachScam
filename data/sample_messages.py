"""
Synthetic demo and evaluation dataset for SachCheck.

MANDATORY DATA ETHICS NOTICE:
All messages in this file are SYNTHETIC DEMO / TEST MESSAGES.
They are NOT real victim reports, nor do they represent real individuals,
companies, or official statements.
No fake statistics, testimonials, or losses are presented.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SyntheticSample:
    id: str
    label: str  # Always "Synthetic Demo / Test Message"
    text: str
    category_focus: str
    expected_risk_level: str  # "LOW", "MEDIUM", "HIGH"
    expected_categories: List[str]
    is_advice: bool = False
    language: str = "English"
    description: str = ""


SYNTHETIC_TEST_SAMPLES: List[SyntheticSample] = [
    # -------------------------------------------------------------
    # 1. GUARANTEED / CERTAIN RETURNS (5 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-GR-01",
        label="Synthetic Demo / Test Message",
        text="Invest in our elite scheme with 100% profit and zero loss guaranteed. Double your money in 30 days.",
        category_focus="Guaranteed Return",
        expected_risk_level="MEDIUM",
        expected_categories=["GUARANTEED_RETURN"],
        language="English",
        description="Explicit 100% profit, zero loss, and double your money claims."
    ),
    SyntheticSample(
        id="SYN-GR-02",
        label="Synthetic Demo / Test Message",
        text="Assured profit of 50% every month with our fixed return investment plan. Risk free wealth generation.",
        category_focus="Guaranteed Return",
        expected_risk_level="MEDIUM",
        expected_categories=["GUARANTEED_RETURN"],
        language="English",
        description="Fixed return, assured profit, and risk-free claims."
    ),
    SyntheticSample(
        id="SYN-GR-03",
        label="Synthetic Demo / Test Message",
        text="Bhai pakka profit hoga, loss bilkul nahi hoga. Paise double ho jayenge 40 din mein!",
        category_focus="Guaranteed Return",
        expected_risk_level="MEDIUM",
        expected_categories=["GUARANTEED_RETURN"],
        language="Hinglish",
        description="Colloquial Hinglish claims of pakka profit, no loss, and doubling money."
    ),
    SyntheticSample(
        id="SYN-GR-04",
        label="Synthetic Demo / Test Message",
        text="Hamare is VIP group mein guaranteed return milega har hafte. 100% pakka profit hai.",
        category_focus="Guaranteed Return",
        expected_risk_level="HIGH",
        expected_categories=["GUARANTEED_RETURN", "MANIPULATIVE_TRADING"],
        language="Hinglish",
        description="Guaranteed return milega combined with VIP group."
    ),
    SyntheticSample(
        id="SYN-GR-05",
        label="Synthetic Demo / Test Message",
        text="Earn fixed return of 25% weekly with 100% capital protection guaranteed.",
        category_focus="Guaranteed Return",
        expected_risk_level="MEDIUM",
        expected_categories=["GUARANTEED_RETURN"],
        language="English",
        description="Fixed return with capital protection guarantee."
    ),

    # -------------------------------------------------------------
    # 2. URGENCY / FOMO (3 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-URG-01",
        label="Synthetic Demo / Test Message",
        text="URGENT! Only today left to claim early bird investor access. Hurry, only 5 slots available!",
        category_focus="Urgency / FOMO",
        expected_risk_level="LOW",  # 15 points
        expected_categories=["URGENCY_FOMO"],
        language="English",
        description="High-pressure urgency with limited slots and expiring today."
    ),
    SyntheticSample(
        id="SYN-URG-02",
        label="Synthetic Demo / Test Message",
        text="Sirf aaj ke liye offer hai. Jaldi karo, aakhri mauka hai, mauka mat chhodo!",
        category_focus="Urgency / FOMO",
        expected_risk_level="LOW",  # 15 points
        expected_categories=["URGENCY_FOMO"],
        language="Hinglish",
        description="Urgency in Hinglish with sirf aaj and mauka mat chhodo."
    ),
    SyntheticSample(
        id="SYN-URG-03",
        label="Synthetic Demo / Test Message",
        text="Act now! Don't miss this opportunity before market opens. Limited seats closing soon.",
        category_focus="Urgency / FOMO",
        expected_risk_level="LOW",  # 15 points
        expected_categories=["URGENCY_FOMO"],
        language="English",
        description="Pre-market urgency and limited seats."
    ),

    # -------------------------------------------------------------
    # 3. PAYMENT REQUEST (3 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-PAY-01",
        label="Synthetic Demo / Test Message",
        text="Deposit now to activate your trading allotment. Send ₹25,000 registration fee to official@okhdfcbank.",
        category_focus="Payment Request",
        expected_risk_level="MEDIUM",  # 25 points
        expected_categories=["PAYMENT_REQUEST"],
        language="English",
        description="Direct request to send funds to a UPI handle for registration fee."
    ),
    SyntheticSample(
        id="SYN-PAY-02",
        label="Synthetic Demo / Test Message",
        text="Registration ke liye ₹5000 bhejo abhi. Mere account me bhejo ya UPI pe payment karo.",
        category_focus="Payment Request",
        expected_risk_level="MEDIUM",  # 25 points
        expected_categories=["PAYMENT_REQUEST"],
        language="Hinglish",
        description="Hinglish request for payment to personal account or UPI."
    ),
    SyntheticSample(
        id="SYN-PAY-03",
        label="Synthetic Demo / Test Message",
        text="Transfer now ₹15,000 processing fee directly to our personal account via UPI ID trader99@paytm.",
        category_focus="Payment Request",
        expected_risk_level="MEDIUM",  # 25 points
        expected_categories=["PAYMENT_REQUEST"],
        language="English",
        description="Transfer now to personal account via UPI ID."
    ),

    # -------------------------------------------------------------
    # 4. AUTHORITY / IMPERSONATION CLAIMS (3 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-AUTH-01",
        label="Synthetic Demo / Test Message",
        text="Get official recommendations verified by our SEBI registered officer and official broker team.",
        category_focus="Authority Claim",
        expected_risk_level="MEDIUM",  # 20 points
        expected_categories=["AUTHORITY_IMPERSONATION"],
        language="English",
        description="Impersonation of SEBI registered officer and official broker team."
    ),
    SyntheticSample(
        id="SYN-AUTH-02",
        label="Synthetic Demo / Test Message",
        text="Ye investment plan government ka approved plan hai aur SEBI se approved hai with insider information.",
        category_focus="Authority Claim",
        expected_risk_level="MEDIUM",  # 20 points
        expected_categories=["AUTHORITY_IMPERSONATION"],
        language="Hinglish",
        description="Hinglish authority impersonation of SEBI approval and government approval."
    ),
    SyntheticSample(
        id="SYN-AUTH-03",
        label="Synthetic Demo / Test Message",
        text="Participate in this RBI approved investment backed by government backed investment fund.",
        category_focus="Authority Claim",
        expected_risk_level="MEDIUM",  # 20 points
        expected_categories=["AUTHORITY_IMPERSONATION"],
        language="English",
        description="False claims of RBI approval and government backed investment."
    ),

    # -------------------------------------------------------------
    # 5. SUSPICIOUS LINK PATTERNS (2 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-LINK-01",
        label="Synthetic Demo / Test Message",
        text="Join our VIP elite trading channel for daily market signals: bit.ly/wealth-grow-daily",
        category_focus="Suspicious Link",
        expected_risk_level="MEDIUM",  # 20 + 15 = 35 points
        expected_categories=["SUSPICIOUS_LINK", "MANIPULATIVE_TRADING"],
        language="English",
        description="Shortened bit.ly URL accompanied by VIP trading channel."
    ),
    SyntheticSample(
        id="SYN-LINK-02",
        label="Synthetic Demo / Test Message",
        text="Access unlisted high-yield shares portal here: tinyurl.com/fast-crypto-wealth",
        category_focus="Suspicious Link",
        expected_risk_level="MEDIUM",  # 20 points
        expected_categories=["SUSPICIOUS_LINK"],
        language="English",
        description="Shortened tinyurl link masking investment portal."
    ),

    # -------------------------------------------------------------
    # 6. MANIPULATIVE TRADING LANGUAGE (2 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-MANIP-01",
        label="Synthetic Demo / Test Message",
        text="Exclusive operator tip on secret stock! Multibagger guaranteed breakout before market opens.",
        category_focus="Manipulative Trading Language",
        expected_risk_level="HIGH",  # 15 + 15 + 30 = 60 points
        expected_categories=["MANIPULATIVE_TRADING", "URGENCY_FOMO", "GUARANTEED_RETURN"],
        language="English",
        description="Operator tip, multibagger guaranteed, and urgency before market opens."
    ),
    SyntheticSample(
        id="SYN-MANIP-02",
        label="Synthetic Demo / Test Message",
        text="Kal subah jackpot tip aayega! Operator game chal raha hai, pakka breakout share hai.",
        category_focus="Manipulative Trading Language",
        expected_risk_level="LOW",  # 15 points
        expected_categories=["MANIPULATIVE_TRADING"],
        language="Hinglish",
        description="Hinglish operator game, jackpot tip, and pakka breakout."
    ),

    # -------------------------------------------------------------
    # 7. LEGITIMATE EDUCATIONAL EXAMPLES (False Positive Tests) (4 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-EDU-01",
        label="Synthetic Demo / Test Message",
        text="SEBI investor education resources explain that investors should verify information before investing.",
        category_focus="Educational / False Positive Check",
        expected_risk_level="LOW",
        expected_categories=[],
        language="English",
        description="Official SEBI investor education mention with no fraud triggers."
    ),
    SyntheticSample(
        id="SYN-EDU-02",
        label="Synthetic Demo / Test Message",
        text="This educational article explains market volatility, diversification, and investment risk.",
        category_focus="Educational / False Positive Check",
        expected_risk_level="LOW",
        expected_categories=[],
        language="English",
        description="General financial education content about diversification."
    ),
    SyntheticSample(
        id="SYN-EDU-03",
        label="Synthetic Demo / Test Message",
        text="Never share your OTP or PIN with anyone under any circumstances.",
        category_focus="Educational / False Positive Check",
        expected_risk_level="LOW",
        expected_categories=[],
        language="English",
        description="Defensive security warning against sharing credentials."
    ),
    SyntheticSample(
        id="SYN-EDU-04",
        label="Synthetic Demo / Test Message",
        text="Investors should be careful about guaranteed-return scams operating on social media.",
        category_focus="Educational / False Positive Check",
        expected_risk_level="LOW",
        expected_categories=[],
        language="English",
        description="Warning against scams; should not trigger scam alert itself."
    ),

    # -------------------------------------------------------------
    # 8. FINANCIAL ADVICE GUARDRAIL (4 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-ADV-01",
        label="Synthetic Demo / Test Message",
        text="Should I buy XYZ stock?",
        category_focus="Financial Advice Guardrail",
        expected_risk_level="LOW",
        expected_categories=[],
        is_advice=True,
        language="English",
        description="Direct question asking whether to buy a specific stock."
    ),
    SyntheticSample(
        id="SYN-ADV-02",
        label="Synthetic Demo / Test Message",
        text="Which stock should I buy for quick short-term gains?",
        category_focus="Financial Advice Guardrail",
        expected_risk_level="LOW",
        expected_categories=[],
        is_advice=True,
        language="English",
        description="Question asking for stock recommendations."
    ),
    SyntheticSample(
        id="SYN-ADV-03",
        label="Synthetic Demo / Test Message",
        text="I hold 500 shares of Reliance. Sell or hold?",
        category_focus="Financial Advice Guardrail",
        expected_risk_level="LOW",
        expected_categories=[],
        is_advice=True,
        language="English",
        description="Question asking for Sell or Hold recommendation."
    ),
    SyntheticSample(
        id="SYN-ADV-04",
        label="Synthetic Demo / Test Message",
        text="Which share will give the highest return this year?",
        category_focus="Financial Advice Guardrail",
        expected_risk_level="LOW",
        expected_categories=[],
        is_advice=True,
        language="English",
        description="Question asking for highest return share prediction."
    ),

    # -------------------------------------------------------------
    # 9. COMBINED HIGH RISK MESSAGES (2 examples)
    # -------------------------------------------------------------
    SyntheticSample(
        id="SYN-HIGH-01",
        label="Synthetic Demo / Test Message",
        text="URGENT! Guaranteed 40% return in 7 days. SEBI approved opportunity. Send ₹10,000 to this UPI now.",
        category_focus="Combined High Risk",
        expected_risk_level="HIGH",
        expected_categories=["URGENCY_FOMO", "GUARANTEED_RETURN", "AUTHORITY_IMPERSONATION", "PAYMENT_REQUEST"],
        language="English",
        description="Benchmark multi-indicator message from hackathon specification."
    ),
    SyntheticSample(
        id="SYN-HIGH-02",
        label="Synthetic Demo / Test Message",
        text="Sirf aaj! 100% pakka profit aur paise double ho jayenge. SEBI ka official tip hai. Mere account me ₹5000 UPI pe payment bhejo: bit.ly/join-rich",
        category_focus="Combined High Risk",
        expected_risk_level="HIGH",
        expected_categories=["URGENCY_FOMO", "GUARANTEED_RETURN", "AUTHORITY_IMPERSONATION", "PAYMENT_REQUEST", "SUSPICIOUS_LINK"],
        language="Hinglish",
        description="Hinglish multi-indicator high risk message combining all major threat vectors."
    ),
]
