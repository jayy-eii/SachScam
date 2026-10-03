"""
Predefined detection rules and patterns for the SachCheck Rule Engine.
These rules act as the deterministic source of truth for all risk evaluations.
No LLM is used to modify or determine these rules or their scores.
"""

import re
from typing import List, Pattern
from dataclasses import dataclass, field


@dataclass
class RuleDefinition:
    rule_id: str
    category_id: str
    category: str
    score: int
    severity: str  # 'high', 'medium', 'low'
    patterns: List[Pattern] = field(default_factory=list)
    negative_contexts: List[Pattern] = field(default_factory=list)
    explanation_en: str = ""
    explanation_hi: str = ""
    safe_next_step: str = ""


# Compile regex flags: case-insensitive, multiline, unicode
_FLAGS = re.IGNORECASE | re.UNICODE | re.MULTILINE


def _compile(pattern_str: str) -> Pattern:
    return re.compile(pattern_str, _FLAGS)


# 1. GUARANTEED / CERTAIN RETURNS (Score: +30)
# Matches claims of guaranteed, fixed, or risk-free returns in English and Hindi/Hinglish
GUARANTEED_RETURN_RULE = RuleDefinition(
    rule_id="GUARANTEED_RETURN",
    category_id="GUARANTEED_RETURN",
    category="Guaranteed Return",
    score=30,
    severity="high",
    patterns=[
        # English patterns
        _compile(r"\bguaranteed\s+(?:\d+%(?!\w)\s+)?(?:returns?|profits?|gains?|income|yields?|breakouts?)\b"),
        _compile(r"\b(?:fixed|assured|sure|100%(?!\w)|hundred\s+percent)\s+(?:returns?|profits?|gains?|income)\b"),
        _compile(r"\b(?:no\s+loss|zero\s+loss|loss\s+free)\b"),
        _compile(r"\brisk[- ]free\b"),
        _compile(r"\b(?:double|triple)\s+your\s+money\b"),
        _compile(r"\bmoney\s+will\s+(?:double|triple)\b"),
        _compile(r"\bguaranteed\s+\d+%(?!\w)"),
        _compile(r"\b\d+%(?!\w)\s+(?:guaranteed|fixed|assured|pakka)\s*(?:returns?|profits?)?\b"),
        _compile(r"\b(?:sure|assured)\s+profits?\b"),
        _compile(r"\bcapital\s+protection\s+guaranteed\b"),
        _compile(r"\b100%(?!\w)\s+profits?\b"),
        # Hindi / Hinglish patterns
        _compile(r"\bguaranteed\s+profit\s+hai\b"),
        _compile(r"\bloss\s+bilkul\s+nah[i|ee]n?\s+hoga\b"),
        _compile(r"\bpaise\s+double\s+ho\s+ja(?:yenge|enge)\b"),
        _compile(r"\bpakka\s+profit\b"),
        _compile(r"\bpakka\s+return\b"),
        _compile(r"\b(?:fixed|guaranteed)\s+return\s+mileg[a|i]\b"),
        _compile(r"\b100%(?!\w)\s+pakka\s+profit\b"),
        _compile(r"\bbilkul\s+risk\s+nah[i|ee]n?\b"),
        _compile(r"\bpakka\s+fayda\b"),
    ],
    negative_contexts=[
        # Educational warnings or scam alerts talking about guaranteed returns
        _compile(r"(?:careful\s+about|beware\s+of|caution\s+against|warn(?:s|ing)?\s+against|alert\s+on)\s+[^.!?\n]{0,60}\b(?:guaranteed|fixed|assured|no\s+loss|risk[- ]free)"),
        _compile(r"\b(?:guaranteed|fixed|assured|no\s+loss|risk[- ]free)[^.!?\n]{0,40}\b(?:scams?|frauds?|traps?|tricks?|claims?|schemes?)\b"),
    ],
    explanation_en="The message contains a guaranteed or unusually certain return claim. Legitimate financial markets inherently involve risk, and no genuine investment entity can promise fixed or risk-free returns.",
    explanation_hi="Is message mein guaranteed ya fixed profit ka claim kiya gaya hai. Financial market mein risk hamesha hota hai aur koi bhi legitimate entity bina risk ke return ka vada nahi kar sakti.",
    safe_next_step="Remember that stock and financial market returns can never be guaranteed. Be deeply skeptical of any claim promising zero loss or fixed double-digit returns."
)


# 2. PAYMENT REQUEST (Score: +25)
# Matches explicit requests to send funds, deposit to personal accounts or unverified UPI IDs
PAYMENT_REQUEST_RULE = RuleDefinition(
    rule_id="PAYMENT_REQUEST",
    category_id="PAYMENT_REQUEST",
    category="Payment Request",
    score=25,
    severity="high",
    patterns=[
        # English patterns
        _compile(r"\b(?:send|transfer|deposit|pay)\s+(?:money|cash|funds|amount)\b"),
        _compile(r"\b(?:transfer|pay|deposit)\s+now\b"),
        _compile(r"\b(?:send|pay|transfer|deposit)\s*(?:to\s+)?(?:₹|rs\.?|inr)?\s*[\d,]+\b"),
        _compile(r"\b(?:send|pay|transfer)\s+(?:₹|rs\.?|inr)\b"),
        _compile(r"\b(?:transfer\s+to|pay\s+to|deposit\s+in)\s+(?:my|this|personal|given)\s+account\b"),
        _compile(r"\bpersonal\s+account\b"),
        _compile(r"\bupi\s*id\b"),
        _compile(r"\bupi\s+pe\b"),
        _compile(r"\bvia\s+upi\b"),
        _compile(r"\bupi\s+number\b"),
        _compile(r"\bupi\b"),
        _compile(r"\b(?:registration|processing|joining|membership|entry|activation)\s+fees?\b"),
        _compile(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b"),  # UPI handle pattern (e.g. user@okhdfcbank)
        # Hindi / Hinglish patterns
        _compile(r"\bupi\s+pe\s+payment\s+(?:bhejo|karo)\b"),
        _compile(r"\bpaise\s+(?:transfer|bhejo|jama)\s+karo\b"),
        _compile(r"\bmere\s+account\s+me(?:in)?\s+bhejo\b"),
        _compile(r"\babhi\s+payment\s+(?:karo|bhejo)\b"),
        _compile(r"\bregistration\s+ke\s+liye\s+(?:₹|rs\.?|inr)?\s*[\d,]*\s*bhejo\b"),
        _compile(r"\bturant\s+payment\s+(?:karo|bhejo)\b"),
        _compile(r"\bpaise\s+(?:dalo|transfer\s+karo)\b"),
    ],
    negative_contexts=[
        # Warning NOT to send money or share credentials
        _compile(r"\b(?:never|do\s+not|don'?t|avoid)\s+(?:share|send|transfer|pay)[^.!?\n]{0,60}\b(?:money|otp|pin|credentials|password|upi)\b"),
        _compile(r"\bnever\s+share\s+your\s+(?:otp|pin|password)\b"),
        _compile(r"\bnever\s+share\b"),
    ],
    explanation_en="Payment request detected — verify the recipient and purpose before transferring money. Genuine SEBI-registered entities never request transfers into individual private accounts or informal UPI handles.",
    explanation_hi="Payment request payi gayi hai — paise transfer karne se pehle recipient aur purpose ko verify karein. Koi bhi genuine SEBI-registered entity personal account ya unverified UPI par payment nahi mangti.",
    safe_next_step="Do not transfer money to personal UPI IDs or private accounts. Never share your OTP, PIN, password, or bank credentials with anyone."
)


# 3. AUTHORITY / IMPERSONATION CLAIMS (Score: +20)
# Matches deceptive claims of regulator endorsement or official affiliation.
# NOTE: The word 'SEBI' or 'RBI' by itself does NOT trigger this rule.
AUTHORITY_IMPERSONATION_RULE = RuleDefinition(
    rule_id="AUTHORITY_IMPERSONATION",
    category_id="AUTHORITY_IMPERSONATION",
    category="Authority Claim",
    score=20,
    severity="medium",
    patterns=[
        # English patterns
        _compile(r"\bsebi\s+(?:approved|certified|registered\s+officer|endorsed|guaranteed)\b"),
        _compile(r"\bsebi\s+certified\s+tip\b"),
        _compile(r"\brbi\s+(?:approved|certified|endorsed)(?:\s+investment|\s+scheme|\s+plan)?\b"),
        _compile(r"\bgovernment\s+(?:approved|backed)\s+(?:investment|scheme|crypto|plan|profit)\b"),
        _compile(r"\bofficial\s+broker\s+team\b"),
        _compile(r"\binsider\s+(?:information|secret|data|intel)\b"),
        _compile(r"\binstitutional\s+(?:secret|intel|channel)\b"),
        _compile(r"\bgovernment\s+backed\s+investment\b"),
        _compile(r"\bsebi\s+registered\s+(?:officer|analyst\s+guaranteed)\b"),
        # Hindi / Hinglish patterns
        _compile(r"\bsebi\s+se\s+approved\s+hai\b"),
        _compile(r"\bsebi\s+ka\s+official\s+tip\s+hai\b"),
        _compile(r"\bgovernment\s+ka\s+approved\s+plan\s+hai\b"),
        _compile(r"\binsider\s+information\s+hai\b"),
        _compile(r"\bsarkari\s+approved\s+hai\b"),
    ],
    negative_contexts=[
        # Legitimate educational or advisory mentions of SEBI/RBI
        _compile(r"\bsebi\s+(?:investor\s+education|guidelines|warnings?|circular|website|portal|regulations?|disclaimer|resources?)\b"),
        _compile(r"\bverify\s+(?:on|with)\s+sebi\b"),
    ],
    explanation_en="Authority claim detected — verify independently through an official source. Bad actors frequently misuse names of regulators like SEBI, RBI, or government bodies to gain unwarranted trust.",
    explanation_hi="Regulator ya authority claim detect hua hai — official source ke zariye iski satyata jaanchein. Scammers aksar SEBI ya RBI jaise shabdon ka galat istemal karke vishwas jeetne ki koshish karte hain.",
    safe_next_step="Verify any claims of SEBI or regulatory registration directly on the official SEBI portal (sebi.gov.in) under 'Recognized Intermediaries'. Never rely on screenshots or verbal claims."
)


# 4. SUSPICIOUS LINK PATTERNS (Score: +20)
# Matches shortened URLs, hidden redirection domains, or unverified chat group links
SUSPICIOUS_LINK_RULE = RuleDefinition(
    rule_id="SUSPICIOUS_LINK",
    category_id="SUSPICIOUS_LINK",
    category="Suspicious Link",
    score=20,
    severity="medium",
    patterns=[
        # Shortened URL services
        _compile(r"\b(?:https?:\/\/)?(?:www\.)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|cutt\.ly|rb\.gy|tiny\.cc|goo\.gl)\/[a-zA-Z0-9_\-\.\/]+\b"),
        # Direct Telegram / WhatsApp group invitations used as trading syndicates
        _compile(r"\b(?:https?:\/\/)?(?:www\.)?(?:t\.me|telegram\.me)\/(?:joinchat\/|[a-zA-Z0-9_+-]+)\b"),
        _compile(r"\b(?:https?:\/\/)?(?:chat\.whatsapp\.com)\/[a-zA-Z0-9_-]+\b"),
        # IP address URLs
        _compile(r"\bhttps?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/[^\s]*)?\b"),
    ],
    negative_contexts=[],
    explanation_en="Potentially suspicious or shortened link detected. Verify the destination independently before opening. Shortened or obfuscated links are often used to conceal deceptive phishing or illicit trading channels.",
    explanation_hi="Potentially suspicious ya shortened link detect hua hai. Kholne se pehle destination ko independently verify karein. Short links aksar phishing websites ya unauthorized groups ko chhipane ke liye use hoti hain.",
    safe_next_step="Avoid opening unknown or shortened links. Do not enter credentials, download APKs, or register sensitive personal information on unverified domains."
)


# 5. URGENCY / FOMO (Score: +15)
# Matches high-pressure tactics forcing immediate action before victim can reflect
URGENCY_FOMO_RULE = RuleDefinition(
    rule_id="URGENCY_FOMO",
    category_id="URGENCY_FOMO",
    category="Urgency / FOMO",
    score=15,
    severity="medium",
    patterns=[
        # English patterns
        _compile(r"\b(?:urgent|urgently)\b"),
        _compile(r"\bact\s+now\b"),
        _compile(r"\bjoin\s+now\b"),
        _compile(r"\bonly\s+today\b"),
        _compile(r"\blimited\s+(?:slots?|seats?|offers?|access)\b"),
        _compile(r"\blast\s+chance\b"),
        _compile(r"\bdon'?t\s+miss(?:\s+this\s+opportunity)?\b"),
        _compile(r"\boffer\s+expires\b"),
        _compile(r"\bjoin\s+immediately\b"),
        _compile(r"\bbefore\s+market\s+opens?\b"),
        _compile(r"\bonly\s+\d+\s+slots?\b"),
        _compile(r"\bhurry(?:\s+up)?\b"),
        _compile(r"\bvalid\s+(?:only\s+)?for\s+(?:today|\d+\s+(?:hours?|minutes?))\b"),
        _compile(r"\bclosing\s+soon\b"),
        # Hindi / Hinglish patterns
        _compile(r"\bsirf\s+aaj\b"),
        _compile(r"\babhi\s+join\s+karo\b"),
        _compile(r"\bjaldi\s+karo\b"),
        _compile(r"\bmauka\s+mat\s+chhodo\b"),
        _compile(r"\bturant\s+(?:join|karo|bhejo)\b"),
        _compile(r"\baakhri\s+mauka\b"),
        _compile(r"\btime\s+khatam\s+hone\s+wala\s+hai\b"),
    ],
    negative_contexts=[],
    explanation_en="Urgency or FOMO (fear of missing out) indicators detected. High-pressure deadlines are psychological tactics engineered to prevent careful verification.",
    explanation_hi="Urgency aur FOMO (mauka chhootne ka dar) create karne ki koshish payi gayi hai. Jaldi baazi me log bina research aur verification ke galat kadam utha lete hain.",
    safe_next_step="Take time to pause and reflect. Legitimate investments never require instant decisions under artificial urgency."
)


# 6. MANIPULATIVE TRADING LANGUAGE (Score: +15)
# Matches promises of insider secrets, jackpot calls, or pump-and-dump signals
MANIPULATIVE_TRADING_RULE = RuleDefinition(
    rule_id="MANIPULATIVE_TRADING",
    category_id="MANIPULATIVE_TRADING",
    category="Manipulative Trading Language",
    score=15,
    severity="medium",
    patterns=[
        # English patterns
        _compile(r"\binsider\s+tips?\b"),
        _compile(r"\boperator\s+tips?\b"),
        _compile(r"\bpump(?:\s+and\s+dump)?\b"),
        _compile(r"\bsure\s+shot\b"),
        _compile(r"\bmultibagger\s+guaranteed\b"),
        _compile(r"\bsecret\s+stocks?\b"),
        _compile(r"\bvip\s+(?:tips?|signals?|group|channel|club)\b"),
        _compile(r"\bpremium\s+(?:signals?|tips?|calls?)\b"),
        _compile(r"\bguaranteed\s+breakout\b"),
        _compile(r"\bbuy\s+immediately\s+before\s+market\s+opens\b"),
        _compile(r"\bjackpot\s+(?:calls?|shares?|stocks?|tips?)\b"),
        _compile(r"\b100%(?!\w)\s+accurate\s+calls?\b"),
        _compile(r"\brocket\s+(?:share|stock|call)\b"),
        # Hindi / Hinglish patterns
        _compile(r"\bjackpot\s+tip\b"),
        _compile(r"\boperator\s+game\b"),
        _compile(r"\bpakka\s+breakout\b"),
        _compile(r"\bsecret\s+share\b"),
        _compile(r"\bcrorepati\s+banne\s+ka\s+mauka\b"),
    ],
    negative_contexts=[],
    explanation_en="Manipulative trading language or unverified 'insider tips' detected. This is a common pattern in pump-and-dump operations and unauthorized advisory services.",
    explanation_hi="Manipulative trading language jaise 'insider tip' ya 'jackpot call' detect hui hai. Yeh aksar unauthorized tipsters ya pump-and-dump schemes dwara use hoti hai.",
    safe_next_step="Never trade based on unsolicited tips, secret breakout alerts, or social media recommendations. Consult a registered investment adviser (SEBI RIA)."
)


# 7. APP INSTALLATION REQUEST (Score: +20)
APP_INSTALLATION_RULE = RuleDefinition(
    rule_id="APP_INSTALLATION",
    category_id="APP_INSTALLATION",
    category="App Installation Request",
    score=20,
    severity="high",
    patterns=[
        _compile(r"\b(?:download|install)\s+(?:this\s+)?(?:apk|app|application|software)\b"),
        _compile(r"\b(?:custom|trading)\s+app\s+(?:download|install)\b"),
        _compile(r"\bapk\s+(?:link|download|file)\b"),
        _compile(r"\bapp\s+(?:download|install)\s+(?:karo|kijiye)\b"),
        _compile(r"\b(?:install|download)\s+our\s+trading\s+app\b"),
    ],
    negative_contexts=[],
    explanation_en="Third-party application or APK installation request detected. Unofficial APKs bypass app store security controls and can contain malicious surveillance or banking trojans.",
    explanation_hi="Third-party app ya APK download karne ki request detect hui hai. Unofficial APKs phone ka security bypass karke unauthorized access le sakte hain.",
    safe_next_step="Never install unverified APK files from WhatsApp, Telegram, or external links. Only download apps from official app stores like Google Play or Apple App Store."
)


# 8. CREDENTIAL REQUEST (Score: +25)
CREDENTIAL_REQUEST_RULE = RuleDefinition(
    rule_id="CREDENTIAL_REQUEST",
    category_id="CREDENTIAL_REQUEST",
    category="Credential Request",
    score=25,
    severity="high",
    patterns=[
        _compile(r"\b(?:share|send|provide|give|tell)\s+(?:your\s+)?(?:otp|pin|password|passcode|secret\s+code)\b"),
        _compile(r"\botp\s+(?:bhejo|share\s+karo|batao|send\s+karo)\b"),
        _compile(r"\benter\s+(?:your\s+)?(?:otp|mpin|upi\s+pin)\b"),
        _compile(r"\bshare\s+(?:your\s+)?otp\b"),
    ],
    negative_contexts=[
        _compile(r"\bnever\s+share\s+your\s+(?:otp|pin|password)\b"),
        _compile(r"\bnever\s+share\b"),
        _compile(r"\b(?:never|do\s+not|don'?t|avoid)\s+(?:share|send|transfer|pay)[^.!?\n]{0,60}\b(?:money|otp|pin|credentials|password|upi)\b"),
        _compile(r"(?:careful\s+about|beware\s+of|caution\s+against|warn(?:s|ing)?\s+against|alert\s+on)\s+[^.!?\n]{0,60}\b(?:otp|pin|credentials)"),
    ],
    explanation_en="Request for private authentication credentials (OTP, PIN, password) detected. Legitimate financial institutions and SEBI intermediaries never solicit these credentials.",
    explanation_hi="OTP, PIN ya password mangne ki request detect hui hai. Koi bhi legitimate bank ya broker chat par aapse OTP ya PIN nahi mangta.",
    safe_next_step="Never share your OTP, UPI PIN, or passwords with anyone. Sharing an OTP allows unauthorized access to your funds."
)


# 9. WITHDRAWAL FEE / EXTORTION (Score: +25)
WITHDRAWAL_FEE_RULE = RuleDefinition(
    rule_id="WITHDRAWAL_FEE",
    category_id="WITHDRAWAL_FEE",
    category="Withdrawal Fee / Extortion",
    score=25,
    severity="high",
    patterns=[
        _compile(r"\b(?:withdrawal|clearance|tax|unfreez(?:e|ing)|release)\s+fees?\b"),
        _compile(r"\bpay\s+(?:tax|fee|charge|processing\s+fee)\s+to\s+withdraw\b"),
        _compile(r"\bwithdrawal\s+requires?\s+(?:₹|rs\.?|inr)?\s*[\d,]*\b"),
        _compile(r"\bdeposit\s+(?:₹|rs\.?|inr)?\s*[\d,]+\s+to\s+(?:withdraw|unfreeze|release)\b"),
        _compile(r"\baccount\s+frozen\s+deposit\b"),
        _compile(r"\bpay\s+₹?[\d,]+\s+processing\s+fee\s+for\s+withdrawal\b"),
    ],
    negative_contexts=[],
    explanation_en="Advance fee or tax demanded to release or withdraw funds detected. Demanding advance payments to release alleged profits is a universal scam extortion pattern.",
    explanation_hi="Withdrawal ke liye advance fee ya tax mangne ka pattern paya gaya hai. Munafa nikalne ke liye aur paise mangna ek scam signal hai.",
    safe_next_step="Do not pay any fee or tax to withdraw funds. Legitimate brokers deduct applicable taxes directly at source, never demanding upfront deposits to unfreeze accounts."
)


# 10. EXTERNAL GROUP INVITATION (Score: +10)
EXTERNAL_GROUP_RULE = RuleDefinition(
    rule_id="EXTERNAL_GROUP",
    category_id="EXTERNAL_GROUP",
    category="External Group Invitation",
    score=10,
    severity="low",
    patterns=[
        _compile(r"\bjoin\s+(?:our\s+)?(?:vip\s+)?(?:telegram|whatsapp\s+group|private\s+channel)\b"),
        _compile(r"\bjoin\s+vip\s+telegram\b"),
        _compile(r"\bmessage\s+on\s+telegram\b"),
        _compile(r"\bjoin\s+our\s+vip\s+telegram\s+group\b"),
    ],
    negative_contexts=[],
    explanation_en="Invitation to join an unregulated private Telegram or WhatsApp group detected. Scammers isolate investors in private groups to execute coordinated pump-and-dump operations.",
    explanation_hi="Private Telegram ya WhatsApp group join karne ki request mili hai. Aise groups mein orchestrated fake profits dikha kar investors ko mislead kiya jata hai.",
    safe_next_step="Avoid joining unsolicited investment groups or private VIP trading syndicates."
)


# 11. FAKE PROFIT / PROOF (Score: +15)
FAKE_PROFIT_RULE = RuleDefinition(
    rule_id="FAKE_PROFIT",
    category_id="FAKE_PROFIT",
    category="Fake Profit Claim",
    score=15,
    severity="medium",
    patterns=[
        _compile(r"\b(?:today'?s?\s+profit|daily\s+profit|total\s+profit)\s*[:=]?\s*(?:₹|rs\.?|\$)\s*[\d,]+\b"),
        _compile(r"\bprofit\s+proof\b"),
        _compile(r"\baccount\s+balance\s*[:=]?\s*(?:₹|rs\.?|\$)\s*[\d,]+\b"),
        _compile(r"\bprofit\s+withdrawal\s+proof\b"),
    ],
    negative_contexts=[],
    explanation_en="Claims of quick fabricated profits or account balance proof detected. Scammers display synthetic profits to induce victims to deposit larger amounts.",
    explanation_hi="Fake daily profit ya balance proof ka claim detect hua hai. Scammers fake screenshots dikha kar aur paise invest karne ka lalach dete hain.",
    safe_next_step="Do not trust screenshots of account balances or trading profits. These are trivial to fabricate or simulate with demo accounts."
)


# 12. REFERRAL PRESSURE (Score: +10)
REFERRAL_PRESSURE_RULE = RuleDefinition(
    rule_id="REFERRAL_PRESSURE",
    category_id="REFERRAL_PRESSURE",
    category="Referral Pressure",
    score=10,
    severity="low",
    patterns=[
        _compile(r"\brefer\s+(?:\d+|friends?)\s+to\s+(?:earn|get\s+bonus)\b"),
        _compile(r"\binvite\s+(?:friends?|members?)\s+to\s+(?:earn|join)\b"),
        _compile(r"\breferral\s+bonus\s+of\b"),
    ],
    negative_contexts=[],
    explanation_en="Referral or recruitment incentives detected. Schemes emphasizing member recruitment over real underlying economic activity often function as Ponzi or pyramid schemes.",
    explanation_hi="Friends ko refer karke bonus paane ka offer detect hua hai. Naye logon ko jodkar paise dene wali schemes aksar Ponzi schemes hoti hain.",
    safe_next_step="Avoid schemes that reward member recruitment or multi-level commissions rather than verified investment yields."
)


# List of all active detection rules in deterministic priority order
ALL_RULES: List[RuleDefinition] = [
    GUARANTEED_RETURN_RULE,
    PAYMENT_REQUEST_RULE,
    AUTHORITY_IMPERSONATION_RULE,
    SUSPICIOUS_LINK_RULE,
    URGENCY_FOMO_RULE,
    MANIPULATIVE_TRADING_RULE,
    APP_INSTALLATION_RULE,
    CREDENTIAL_REQUEST_RULE,
    WITHDRAWAL_FEE_RULE,
    EXTERNAL_GROUP_RULE,
    FAKE_PROFIT_RULE,
    REFERRAL_PRESSURE_RULE,
]


# BUY/SELL/HOLD INVESTMENT ADVICE GUARDRAIL PATTERNS
# Questions asking for stock recommendations, predictions, or tips that MUST be refused.
ADVICE_REQUEST_PATTERNS: List[Pattern] = [
    _compile(r"\b(?:should\s+i|can\s+i|shall\s+i)\s+(?:buy|sell|hold|invest\s+in)\b"),
    _compile(r"\bwhich\s+(?:stock|share|crypto|fund|coin)\s+(?:should\s+i\s+buy|to\s+buy|is\s+best|gives?\s+(?:the\s+)?highest\s+return)\b"),
    _compile(r"\b(?:sell\s+or\s+hold|buy\s+or\s+sell|hold\s+or\s+sell|buy\s+or\s+hold)\b"),
    _compile(r"\bwill\s+(?:this|the|[a-zA-Z]+)\s+stock\s+go\s+up\b"),
    _compile(r"\bwhich\s+share\s+will\s+give\s+(?:the\s+)?highest\s+return\b"),
    _compile(r"\bwhat\s+stocks?\s+should\s+i\s+(?:buy|sell)\b"),
    _compile(r"\b(?:kya\s+mujhe\s+ye\s+stock\s+kharidna\s+chahiye|kaunsa\s+stock\s+kharidu|kisme\s+invest\s+karu)\b"),
]

ADVICE_REFUSAL_MESSAGE = (
    "SachCheck does not provide Buy/Sell/Hold recommendations, stock predictions, "
    "or investment tips. It can instead analyze a message for scam, manipulation, or safety indicators."
)
