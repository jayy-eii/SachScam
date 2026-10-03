"""
Chat Journey and Scam Progression Mapper for SachCheck.
Evaluates multi-screenshot conversations across 8 structured progression stages:
1. Initial contact
2. Trust building
3. Investment opportunity
4. Group/app invitation
5. Deposit request
6. Profit claim
7. Additional payment
8. Withdrawal problem

Strictly evidence-based: Only displays stages supported by actual extracted text.
Never forces or fabricates a scam journey when evidence is insufficient.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class JourneyStage:
    """Represents a validated stage in a scam journey detected in screenshot evidence."""
    stage_number: int  # 1 to 8
    stage_id: str
    stage_title: str
    stage_badge: str
    screenshot_index: int  # 1-indexed (which screenshot triggered it)
    evidence_snippet: str
    explanation_en: str
    explanation_hi: str


@dataclass
class ConversationRiskProfile:
    """Consolidated profile representing conversation progression across screenshots."""
    is_multi_stage_journey: bool
    total_stages_found: int
    stages_detected: List[JourneyStage] = field(default_factory=list)
    progression_summary: str = ""
    evidence_strength: str = "INSUFFICIENT"  # "STRONG", "MODERATE", "INSUFFICIENT"
    disclaimer: str = (
        "Progression stages are mapped strictly from detected message characteristics. "
        "They do not establish criminal intent or replace official law-enforcement investigation."
    )


class ScamJourneyMapper:
    """Maps conversation screenshots to evidence-based scam journey stages."""

    _FLAGS = re.IGNORECASE | re.UNICODE

    # Patterns for each of the 8 stages
    STAGE_DEFINITIONS = [
        # Stage 1: Initial contact
        (
            1,
            "INITIAL_CONTACT",
            "Initial Contact",
            "🎣 Step 1: Hook",
            [
                re.compile(r"\b(?:hello|hi|dear\s+investor|hey)\b", _FLAGS),
                re.compile(r"\b(?:got\s+your\s+number|found\s+your\s+profile|from\s+trading\s+group)\b", _FLAGS),
                re.compile(r"\bpart[- ]time\s+(?:job|earning|income)\b", _FLAGS),
                re.compile(r"\bghar\s+baithe\s+(?:paise|kamaye)\b", _FLAGS),
            ],
            "Unsolicited outreach from unknown numbers or cold social media contacts.",
            "Anjan number ya group se bina maange contact kiya gaya.",
        ),
        # Stage 2: Trust building
        (
            2,
            "TRUST_BUILDING",
            "Trust Building",
            "🏛️ Step 2: Credibility",
            [
                re.compile(r"\b(?:sebi|rbi|government)\s+(?:approved|certified|registered|official)\b", _FLAGS),
                re.compile(r"\b(?:iso\s+certified|authorized\s+partner|verified\s+broker)\b", _FLAGS),
                re.compile(r"\b(?:expert\s+team|senior\s+analyst|experienced\s+mentor)\b", _FLAGS),
                re.compile(r"\bsebi\s+se\s+approved\b", _FLAGS),
            ],
            "Claims of regulatory certification or official endorsements to establish false credibility.",
            "SEBI ya authority ke naam par fake credibility banane ki koshish.",
        ),
        # Stage 3: Investment opportunity
        (
            3,
            "INVESTMENT_OPPORTUNITY",
            "Investment Opportunity",
            "💡 Step 3: Opportunity",
            [
                re.compile(r"\b(?:guaranteed|fixed|assured|sure|100%)\s+(?:returns?|profits?|gains?)\b", _FLAGS),
                re.compile(r"\b(?:double|triple)\s+your\s+money\b", _FLAGS),
                re.compile(r"\b\d+%\s+(?:daily|weekly|monthly)\s+returns?\b", _FLAGS),
                re.compile(r"\bpaise\s+double\b", _FLAGS),
                re.compile(r"\bjackpot\s+(?:calls?|shares?)\b", _FLAGS),
            ],
            "Promises of high, fixed, or risk-free returns that contradict financial market realities.",
            "Asamanya unche aur bina kisi risk ke return ka vada.",
        ),
        # Stage 4: Group/app invitation
        (
            4,
            "GROUP_APP_INVITATION",
            "Group / Custom App Invitation",
            "📲 Step 4: Isolation",
            [
                re.compile(r"\b(?:join\s+our\s+vip|join\s+telegram|join\s+whatsapp\s+group)\b", _FLAGS),
                re.compile(r"\b(?:download|install)\s+(?:our\s+)?(?:apk|app|platform)\b", _FLAGS),
                re.compile(r"\b(?:t\.me|telegram\.me|chat\.whatsapp\.com)\/[a-zA-Z0-9_\-\.\/]+\b", _FLAGS),
                re.compile(r"\bcustom\s+trading\s+software\b", _FLAGS),
            ],
            "Moving the victim away from public platforms into closed groups or proprietary APKs.",
            "Private Telegram group ya custom APK download karwake victim ko isolate karna.",
        ),
        # Stage 5: Deposit request
        (
            5,
            "DEPOSIT_REQUEST",
            "Deposit Request",
            "💳 Step 5: Initial Payment",
            [
                re.compile(r"\b(?:send|deposit|transfer|pay)\s*(?:to\s+)?(?:₹|rs\.?|inr)?\s*[\d,]+\b", _FLAGS),
                re.compile(r"\b(?:registration|activation|joining|entry)\s+fees?\b", _FLAGS),
                re.compile(r"\bupi\s+pe\s+(?:bhejo|payment\s+karo)\b", _FLAGS),
                re.compile(r"\bminimum\s+deposit\b", _FLAGS),
            ],
            "Soliciting the initial monetary commitment, often framed as a small trial deposit or activation fee.",
            "Initial chhota amount ya activation fee jama karne ki maang.",
        ),
        # Stage 6: Profit claim
        (
            6,
            "PROFIT_CLAIM",
            "Profit Claim / Paper Gain",
            "📈 Step 6: Fake Gains",
            [
                re.compile(r"\b(?:today'?s?\s+profit|daily\s+profit|total\s+profit)\s*[:=]?\s*(?:₹|rs\.?|\$)?\s*[\d,]+\b", _FLAGS),
                re.compile(r"\b(?:congratulations|profit\s+generated|balance\s+updated)\b", _FLAGS),
                re.compile(r"\bprofit\s+proof\b", _FLAGS),
                re.compile(r"\byour\s+profit\s+is\s+ready\b", _FLAGS),
            ],
            "Showing fake dashboard profits or balance screenshots to give the illusion of successful trades.",
            "Fake screenshots ya fabricated balance dikha kar vishwas jeetna.",
        ),
        # Stage 7: Additional payment
        (
            7,
            "ADDITIONAL_PAYMENT",
            "Additional Payment Pressure",
            "🔄 Step 7: Escalation",
            [
                re.compile(r"\b(?:invest|deposit)\s+more\s+to\s+(?:earn|double|upgrade)\b", _FLAGS),
                re.compile(r"\bupgrade\s+to\s+(?:vip|diamond|gold|premium)\b", _FLAGS),
                re.compile(r"\bhigher\s+tier\s+investment\b", _FLAGS),
                re.compile(r"\baur\s+paise\s+(?:dalo|invest\s+karo)\b", _FLAGS),
            ],
            "Pressuring the victim to deposit larger sums before allowing profit realization.",
            "Zyada munafa paane ke liye aur badi rakam jama karne ka dabav.",
        ),
        # Stage 8: Withdrawal problem
        (
            8,
            "WITHDRAWAL_PROBLEM",
            "Withdrawal Problem / Extortion",
            "🛑 Step 8: Exit Barrier",
            [
                re.compile(r"\b(?:withdrawal|clearance|tax|penalty|processing)\s+fees?\b", _FLAGS),
                re.compile(r"\bpay\s+(?:tax|fee|charge)\s+to\s+withdraw\b", _FLAGS),
                re.compile(r"\baccount\s+(?:frozen|blocked|suspended|under\s+verification)\b", _FLAGS),
                re.compile(r"\bdeposit\s+₹?[\d,]+\s+to\s+(?:unfreeze|release)\b", _FLAGS),
                re.compile(r"\bwithdrawal\s+requires?\b", _FLAGS),
            ],
            "Inventing arbitrary fees (tax, AML clearance, release charge) when the victim attempts to withdraw funds.",
            "Paise nikalne par tax ya penalty ke naam par aur paise mangna.",
        ),
    ]

    @classmethod
    def evaluate_screenshots(
        cls, screenshot_texts: List[str]
    ) -> ConversationRiskProfile:
        """
        Maps a sequence of extracted screenshot texts to journey progression stages.
        """
        if not screenshot_texts:
            return ConversationRiskProfile(
                is_multi_stage_journey=False,
                total_stages_found=0,
                progression_summary="No screenshot text provided.",
                evidence_strength="INSUFFICIENT",
            )

        detected_stages: List[JourneyStage] = []
        found_stage_nums = set()

        for shot_idx, raw_text in enumerate(screenshot_texts, 1):
            if not raw_text or not raw_text.strip():
                continue

            for (
                stage_num,
                stage_id,
                stage_title,
                stage_badge,
                patterns,
                exp_en,
                exp_hi,
            ) in cls.STAGE_DEFINITIONS:
                if stage_num in found_stage_nums:
                    continue  # Deduplicate stages across conversation

                for pat in patterns:
                    m = pat.search(raw_text)
                    if m:
                        snippet = m.group(0).strip()
                        detected_stages.append(
                            JourneyStage(
                                stage_number=stage_num,
                                stage_id=stage_id,
                                stage_title=stage_title,
                                stage_badge=stage_badge,
                                screenshot_index=shot_idx,
                                evidence_snippet=snippet,
                                explanation_en=exp_en,
                                explanation_hi=exp_hi,
                            )
                        )
                        found_stage_nums.add(stage_num)
                        break

        # Sort detected stages by chronological stage number
        detected_stages.sort(key=lambda s: s.stage_number)

        num_stages = len(detected_stages)

        if num_stages >= 3:
            strength = "STRONG"
            is_journey = True
            stages_list_str = " → ".join(f"[{s.stage_title}]" for s in detected_stages)
            summary = (
                f"Multi-stage scam progression detected across {num_stages} distinct phases: "
                f"{stages_list_str}. This pattern closely matches documented financial fraud funnels."
            )
        elif num_stages == 2:
            strength = "MODERATE"
            is_journey = True
            stages_list_str = " → ".join(f"[{s.stage_title}]" for s in detected_stages)
            summary = (
                f"Partial journey detected across 2 phases: {stages_list_str}. "
                "Exercise high caution before responding or transferring funds."
            )
        elif num_stages == 1:
            strength = "INSUFFICIENT"
            is_journey = False
            summary = (
                f"Only a single isolated phase ({detected_stages[0].stage_title}) was detected. "
                "Insufficient evidence to establish a multi-stage conversation progression."
            )
        else:
            strength = "INSUFFICIENT"
            is_journey = False
            summary = "No structured scam journey detected from available screenshot text."

        return ConversationRiskProfile(
            is_multi_stage_journey=is_journey,
            total_stages_found=num_stages,
            stages_detected=detected_stages,
            progression_summary=summary,
            evidence_strength=strength,
        )
