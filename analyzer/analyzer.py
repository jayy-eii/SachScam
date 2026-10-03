"""
Core deterministic message analyzer for SachCheck.
Executes the deterministic rule engine, extracts evidence,
calculates risk scores, and generates structured explanations and safe next steps.
"""

from typing import List, Tuple, Optional, Set
import re

from analyzer.models import AnalysisResult, DetectedIndicator, MatchSpan
from analyzer.rules import (
    ALL_RULES,
    ADVICE_REQUEST_PATTERNS,
    ADVICE_REFUSAL_MESSAGE,
    RuleDefinition,
)
from analyzer.scoring import compute_deterministic_score, calculate_risk_level
from utils.highlighting import highlight_risk_evidence


class MessageAnalyzer:
    """
    Deterministic rule-based analyzer for financial messages.
    Does NOT use an LLM for classification or scoring decisions.
    """

    def __init__(self, rules: Optional[List[RuleDefinition]] = None):
        self.rules = rules if rules is not None else ALL_RULES
        self.advice_patterns = ADVICE_REQUEST_PATTERNS

    def check_financial_advice_request(self, text: str) -> bool:
        """
        Detects if the user input is asking for stock predictions or Buy/Sell/Hold advice.
        """
        for pattern in self.advice_patterns:
            if pattern.search(text):
                return True
        return False

    def is_in_negative_context(self, rule: RuleDefinition, full_text: str, start: int, end: int) -> bool:
        """
        Checks if a matched span falls inside an educational negation or scam-warning context.
        E.g., 'Investors should be careful about guaranteed-return scams'
        """
        if not rule.negative_contexts:
            return False

        # Check a reasonable window around the match (up to 80 chars before and after)
        win_start = max(0, start - 80)
        win_end = min(len(full_text), end + 80)
        window_text = full_text[win_start:win_end]

        for neg_pat in rule.negative_contexts:
            for m in neg_pat.finditer(window_text):
                # Calculate absolute span of the negative context in full_text
                abs_neg_start = win_start + m.start()
                abs_neg_end = win_start + m.end()
                # If the match overlaps with the negative context
                if max(start, abs_neg_start) < min(end, abs_neg_end):
                    return True
        return False

    def analyze(self, text: str) -> AnalysisResult:
        """
        Analyze a financial message through the deterministic pipeline.

        Flow:
        1. Preprocessing & Input Sanitization
        2. Financial Advice Guardrail Check
        3. Deterministic Pattern Matching & Context Filtering
        4. Category Deduplication (score added once per category)
        5. Score & Risk Level Calculation
        6. Exact Text Highlighting
        7. Dual-Language Explanation Generation
        8. Safe Next Steps Formulation
        """
        cleaned_text = text.strip() if text else ""

        # Edge case: Empty input
        if not cleaned_text:
            return AnalysisResult(
                original_text=text,
                is_advice_request=False,
                advice_refusal_message=None,
                risk_level="LOW",
                risk_score=0,
                indicators=[],
                all_matched_phrases=[],
                highlighted_html="",
                explanation_en="No text provided to analyze.",
                explanation_hi="Jaanch ke liye koi text nahi mila.",
                safe_next_steps=[
                    "Paste a message from WhatsApp, Telegram, SMS, or social media to analyze it."
                ],
            )

        # Step 2: Financial Advice Guardrail Check
        if self.check_financial_advice_request(cleaned_text):
            return AnalysisResult(
                original_text=text,
                is_advice_request=True,
                advice_refusal_message=ADVICE_REFUSAL_MESSAGE,
                risk_level="LOW",
                risk_score=0,
                indicators=[],
                all_matched_phrases=[],
                highlighted_html=highlight_risk_evidence(text, []),
                explanation_en=ADVICE_REFUSAL_MESSAGE,
                explanation_hi=(
                    "SachCheck Buy/Sell/Hold recommendations, share prediction ya stock tips nahi deta. "
                    "Ye platform messages mein scam, manipulation ya fraud indicators ki jaanch karta hai."
                ),
                safe_next_steps=[
                    "Never trade on speculative tips or unverified social media suggestions.",
                    "Consult a SEBI-registered Investment Adviser (RIA) or Research Analyst (RA) for personalized advice.",
                    "Verify the credentials of any financial adviser on the official SEBI directory (sebi.gov.in)."
                ],
            )

        # Step 3: Deterministic Rule Matching with Context Filtering
        detected_indicators: List[DetectedIndicator] = []
        all_highlight_spans: List[Tuple[int, int, str]] = []
        all_matched_phrases: List[str] = []

        for rule in self.rules:
            matched_phrases_for_rule: List[str] = []
            spans_for_rule: List[Tuple[int, int]] = []
            seen_phrases_lower: Set[str] = set()

            for pattern in rule.patterns:
                for match in pattern.finditer(text):
                    m_start, m_end = match.start(), match.end()
                    matched_str = match.group(0).strip()

                    # Context filter: Check if this match is inside an educational/negation context
                    if self.is_in_negative_context(rule, text, m_start, m_end):
                        continue

                    # Record span for highlighting
                    spans_for_rule.append((m_start, m_end))
                    all_highlight_spans.append((m_start, m_end, rule.category))

                    # Deduplicate phrases within the rule for clean display
                    if matched_str.lower() not in seen_phrases_lower:
                        seen_phrases_lower.add(matched_str.lower())
                        matched_phrases_for_rule.append(matched_str)

            # Deduplicate phrases within the rule for clean display:
            # Drop substrings if a longer matching phrase exists (e.g. 'Send ₹' inside 'Send ₹10,000')
            cleaned_phrases = [
                p for p in matched_phrases_for_rule
                if not any(p != other and p.lower() in other.lower() for other in matched_phrases_for_rule)
            ]

            # Step 4: Category Deduplication
            # If the category had at least one valid match, trigger the category ONCE with its full score
            if cleaned_phrases:
                indicator = DetectedIndicator(
                    rule_id=rule.rule_id,
                    category_id=rule.category_id,
                    category=rule.category,
                    score=rule.score,
                    severity=rule.severity,
                    matched_phrases=cleaned_phrases,
                    matched_spans=spans_for_rule,
                    why_it_matters_en=rule.explanation_en,
                    why_it_matters_hi=rule.explanation_hi,
                )
                detected_indicators.append(indicator)
                all_matched_phrases.extend(cleaned_phrases)

        # Step 5: Score & Risk Level Calculation
        total_score, risk_level = compute_deterministic_score(detected_indicators)

        # Step 6: Exact Text Highlighting (Safe HTML)
        highlighted_html = highlight_risk_evidence(text, all_highlight_spans)

        # Step 7: Dual-Language Explanations
        explanation_en, explanation_hi = self._build_explanations(detected_indicators, risk_level, total_score)

        # Step 8: Safe Next Steps
        safe_next_steps = self._build_safe_next_steps(detected_indicators, risk_level)

        return AnalysisResult(
            original_text=text,
            is_advice_request=False,
            advice_refusal_message=None,
            risk_level=risk_level,
            risk_score=total_score,
            indicators=detected_indicators,
            all_matched_phrases=all_matched_phrases,
            highlighted_html=highlighted_html,
            explanation_en=explanation_en,
            explanation_hi=explanation_hi,
            safe_next_steps=safe_next_steps,
        )

    def _build_explanations(
        self, indicators: List[DetectedIndicator], risk_level: str, total_score: int
    ) -> Tuple[str, str]:
        """
        Build deterministic explanations strictly based on detected evidence.
        Never fabricates facts, company names, or scam certainty.
        """
        if not indicators:
            en = (
                "No predefined high-risk indicators were detected in this message. "
                "However, always exercise vigilance and independently verify any investment or financial opportunity."
            )
            hi = (
                "Is message mein koi predefined risk indicator nahi mila. "
                "Phir bhi hamesha satark rahein aur kisi bhi financial opportunity ko independently verify karein."
            )
            return en, hi

        # English explanation
        en_intro = (
            f"Analysis identified {len(indicators)} risk category indicator(s) "
            f"resulting in a deterministic risk score of {total_score} ({risk_level} Risk). "
        )
        en_points = []
        for ind in indicators:
            phrases_repr = ", ".join(f'"{p}"' for p in ind.matched_phrases[:3])
            en_points.append(f"{ind.category} ({phrases_repr}): {ind.why_it_matters_en}")
        en = en_intro + " " + " ".join(en_points)

        # Hindi / Hinglish explanation
        categories_hi = [ind.category for ind in indicators]
        cat_str = ", ".join(categories_hi)
        hi_intro = (
            f"Is message mein {len(indicators)} risk indicators ({cat_str}) paye gaye hain, "
            f"jiska risk score {total_score} ({risk_level} Risk) hai. "
        )
        hi_points = []
        for ind in indicators:
            hi_points.append(f"{ind.category}: {ind.why_it_matters_hi}")
        hi = hi_intro + " " + " ".join(hi_points)

        return en, hi

    def _build_safe_next_steps(
        self, indicators: List[DetectedIndicator], risk_level: str
    ) -> List[str]:
        """
        Generate actionable safety guidance tailored to the triggered indicators.
        """
        steps: List[str] = []
        cat_ids = {ind.category_id for ind in indicators}

        # Payment guidance
        if "PAYMENT_REQUEST" in cat_ids:
            steps.append(
                "Do not transfer money to personal accounts or informal UPI handles. Verify the recipient identity first."
            )
            steps.append("Never share your OTP, UPI PIN, password, or debit/credit card details.")

        # Guaranteed return guidance
        if "GUARANTEED_RETURN" in cat_ids:
            steps.append(
                "Remember that returns in financial and stock markets are never guaranteed; legitimate advisers do not promise fixed profits."
            )

        # Authority claim guidance
        if "AUTHORITY_IMPERSONATION" in cat_ids:
            steps.append(
                "Verify registration status directly on the official SEBI portal (sebi.gov.in) under 'Recognized Intermediaries'."
            )

        # Suspicious link guidance
        if "SUSPICIOUS_LINK" in cat_ids:
            steps.append(
                "Avoid opening shortened or unfamiliar links. Do not download unauthorized APKs or enter personal credentials."
            )

        # Urgency / FOMO guidance
        if "URGENCY_FOMO" in cat_ids:
            steps.append(
                "Take time to pause and reflect. Legitimate financial investments never require hasty, high-pressure decisions."
            )

        # Manipulation guidance
        if "MANIPULATIVE_TRADING" in cat_ids:
            steps.append(
                "Never trade on speculative 'insider tips' or social media group calls. Such messages are often part of pump-and-dump schemes."
            )

        # Fallback / baseline safety step if none triggered
        if not steps:
            steps.append("Always verify claims and credentials with SEBI-registered entities.")
            steps.append("Never send funds or sensitive details based solely on unverified digital messages.")

        # Universal grievance reporting step for medium/high risk
        if risk_level in ("MEDIUM", "HIGH"):
            steps.append(
                "If you believe you encountered fraud or financial crime, report it to the National Cyber Crime Reporting Portal at cybercrime.gov.in or call 1930."
            )

        return steps
