"""
Safe Action Gate module for SachCheck.
Identifies high-risk action requests in financial messages (payments, APK downloads,
credential sharing, external group invites) and evaluates defensive investor protection gates.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


class ActionType:
    PAYMENT = "PAYMENT"
    LINK_CLICK = "LINK_CLICK"
    APP_INSTALLATION = "APP_INSTALLATION"
    CREDENTIAL_SHARING = "CREDENTIAL_SHARING"
    PERSONAL_DATA_SHARING = "PERSONAL_DATA_SHARING"
    DOCUMENT_UPLOAD = "DOCUMENT_UPLOAD"
    JOIN_EXTERNAL_GROUP = "JOIN_EXTERNAL_GROUP"
    CONTACT_EXTERNAL_NUMBER = "CONTACT_EXTERNAL_NUMBER"
    INVESTMENT_ACTION = "INVESTMENT_ACTION"
    INSTALL_REMOTE_APP = "INSTALL_REMOTE_APP"
    SHARE_REMOTE_SESSION_CODE = "SHARE_REMOTE_SESSION_CODE"
    GRANT_REMOTE_CONTROL = "GRANT_REMOTE_CONTROL"
    ENABLE_SCREEN_ACCESS = "ENABLE_SCREEN_ACCESS"
    ENABLE_ACCESSIBILITY = "ENABLE_ACCESSIBILITY"


@dataclass
class DetectedAction:
    """An action that the message solicits the user to perform."""
    action_type: str
    label_en: str
    label_hi: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    matched_phrase: str
    why_dangerous_en: str
    why_dangerous_hi: str
    safe_directive: str


@dataclass
class SafeActionGateReport:
    """Consolidated assessment of solicited user actions."""
    has_actions: bool
    actions: List[DetectedAction] = field(default_factory=list)
    critical_actions: List[DetectedAction] = field(default_factory=list)
    guidance: List[str] = field(default_factory=list)
    hinglish_summary: str = ""


class SafeActionGate:
    """Evaluates requested actions and provides investor defense mechanisms."""

    # Compile regex flags
    _FLAGS = re.IGNORECASE | re.UNICODE

    ACTION_RULES = [
        # 0. REMOTE ACCESS SOFTWARE INSTALLATION (CRITICAL)
        (
            ActionType.INSTALL_REMOTE_APP,
            "Install remote-access software",
            "Remote-access software install karna",
            "CRITICAL",
            [
                re.compile(r"\b(?:install|download|use|open)\s+(?:anydesk|teamviewer|rustdesk|quicksupport|ultraviewer|splashtop|zoho\s+assist|airdroid)\b", _FLAGS),
                re.compile(r"\b(?:anydesk|teamviewer|rustdesk|quicksupport|ultraviewer)\s+(?:install|download)\s+(?:karo|kijiye)\b", _FLAGS),
            ],
            "Remote-access software allows another person to view or control your device depending on permissions granted. Scammers abuse this to view OTPs and access financial accounts.",
            "Remote-access software se samne wala aapka phone screen dekh sakta hai aur device control kar sakta hai.",
            "Do NOT install remote-access software on instructions from unverified callers or chat messages.",
        ),
        # 0.1 SHARE REMOTE SESSION CODE (CRITICAL)
        (
            ActionType.SHARE_REMOTE_SESSION_CODE,
            "Share remote-access / session code",
            "Remote-access / session code share karna",
            "CRITICAL",
            [
                re.compile(r"\b(?:send|share|give|tell|provide)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:code|id|session\s+code|anydesk\s+code|anydesk\s+id|teamviewer\s+id|remote\s+id)\b", _FLAGS),
                re.compile(r"\b(?:anydesk|teamviewer|session)\s+(?:code|id)\s+(?:bhejo|share\s+karo|batao)\b", _FLAGS),
                re.compile(r"\bshare\s+(?:the\s+|your\s+)?anydesk\s+(?:code|id)\b", _FLAGS),
                re.compile(r"\bsend\s+(?:the\s+|your\s+)?session\s+code\b", _FLAGS),
            ],
            "Sharing your session code or AnyDesk/TeamViewer ID authorizes the sender to establish a direct remote session to your device.",
            "Session code ya AnyDesk ID share karne se samne wala aapke device se turant connect ho jata hai.",
            "NEVER share session codes or remote connection IDs with anyone requesting it over chat or call.",
        ),
        # 0.2 GRANT REMOTE CONTROL (CRITICAL)
        (
            ActionType.GRANT_REMOTE_CONTROL,
            "Grant remote control access",
            "Remote control access grant karna",
            "CRITICAL",
            [
                re.compile(r"\b(?:give|allow|grant|provide)\s+(?:me\s+)?(?:remote\s+access|remote\s+control|screen\s+access|device\s+access)\b", _FLAGS),
                re.compile(r"\b(?:accept|approve)\s+(?:my\s+)?(?:remote\s+request|connection|incoming\s+request)\b", _FLAGS),
                re.compile(r"\b(?:let|allow)\s+me\s+control\s+your\s+(?:phone|device|screen)\b", _FLAGS),
                re.compile(r"\baccess\s+de\s+do\b", _FLAGS),
            ],
            "Granting remote control allows the operator to execute touch/mouse events, navigate to banking apps, and authorize transactions.",
            "Remote control dene par samne wala aapke phone mein apps open karke unauthorized transactions kar sakta hai.",
            "Decline all incoming connection requests from unknown parties.",
        ),
        # 0.3 SCREEN ACCESS / ACCESSIBILITY (HIGH)
        (
            ActionType.ENABLE_SCREEN_ACCESS,
            "Enable screen sharing / screen viewing",
            "Screen sharing ya viewing enable karna",
            "HIGH",
            [
                re.compile(r"\b(?:share|enable|start)\s+(?:your\s+)?screen(?:\s+sharing)?\b", _FLAGS),
                re.compile(r"\bscreen\s+share\s+(?:karo|kijiye)\b", _FLAGS),
            ],
            "Screen sharing allows another person to observe your screen in real time, including passwords and 2FA tokens.",
            "Screen share karne par aapke screen par aane wale OTP aur passwords samne wale ko dikh jate hain.",
            "Do not share your screen during banking, trading, or payment transactions.",
        ),
        # 1. APP INSTALLATION (CRITICAL)
        (
            ActionType.APP_INSTALLATION,
            "Install external application / APK",
            "External app ya APK install karna",
            "CRITICAL",
            [
                re.compile(r"\b(?:download|install)\s+(?:this\s+)?(?:apk|app|application|software)\b", _FLAGS),
                re.compile(r"\b(?:custom|trading)\s+app\s+(?:download|install)\b", _FLAGS),
                re.compile(r"\bapk\s+(?:link|download|file)\b", _FLAGS),
                re.compile(r"\bapp\s+(?:download|install)\s+(?:karo|kijiye)\b", _FLAGS),
            ],
            "Third-party APKs circumvent official app stores (Google Play, Apple App Store) and frequently carry remote-access trojans or malicious screen-recording malware.",
            "Unknown source se APK install karne par phone ka access chhin sakta hai aur banking fraud ho sakta hai.",
            "NEVER install unverified APK files from WhatsApp, Telegram, or unknown web links. Only install apps from the official Google Play Store or Apple App Store.",
        ),
        # 2. CREDENTIAL SHARING (CRITICAL)
        (
            ActionType.CREDENTIAL_SHARING,
            "Share authentication credentials (OTP / PIN / Password)",
            "OTP, PIN ya password share karna",
            "CRITICAL",
            [
                re.compile(r"\b(?:share|send|provide|give|tell)\s+(?:your\s+)?(?:otp|pin|password|passcode|code)\b", _FLAGS),
                re.compile(r"\botp\s+(?:bhejo|share\s+karo|batao)\b", _FLAGS),
                re.compile(r"\benter\s+(?:your\s+)?(?:otp|mpin|upi\s+pin)\b", _FLAGS),
            ],
            "OTPs and PINs are the final security authorization for financial transactions. No genuine bank or SEBI broker will EVER ask for your OTP or PIN.",
            "Koi bhi bank ya SEBI registered broker aapse phone ya chat par OTP/PIN nahi mangta.",
            "NEVER share your OTP, UPI PIN, or banking passwords with anyone, under any circumstances.",
        ),
        # 3. PAYMENT (HIGH)
        (
            ActionType.PAYMENT,
            "Deposit or transfer money",
            "Paise transfer ya deposit karna",
            "HIGH",
            [
                re.compile(r"\b(?:send|transfer|deposit|pay)\s*(?:to\s+)?(?:₹|rs\.?|inr)?\s*[\d,]+\b", _FLAGS),
                re.compile(r"\b(?:send|transfer|deposit|pay)\s+(?:money|funds|amount|fees?)\b", _FLAGS),
                re.compile(r"\b(?:registration|processing|activation|withdrawal|clearance|tax)\s+fees?\b", _FLAGS),
                re.compile(r"\bupi\s+pe\s+(?:payment|paise)\s+(?:bhejo|karo)\b", _FLAGS),
                re.compile(r"\bmere\s+account\s+me(?:in)?\s+(?:bhejo|dalo)\b", _FLAGS),
                re.compile(r"\bpaise\s+(?:bhejo|jama\s+karo|transfer\s+karo)\b", _FLAGS),
            ],
            "Direct transfers to personal accounts or unverified UPI IDs are irreversible and a hallmark of informal boiler-room syndicates.",
            "Personal account ya informal UPI par paise bhejne ke baad unhe recover karna lagbhag asambhav hota hai.",
            "Do not transfer funds. Verify recipient registration on sebi.gov.in before any financial transaction.",
        ),
        # 4. JOIN EXTERNAL GROUP (MEDIUM)
        (
            ActionType.JOIN_EXTERNAL_GROUP,
            "Join external Telegram / WhatsApp VIP group",
            "External Telegram ya WhatsApp VIP group join karna",
            "MEDIUM",
            [
                re.compile(r"\bjoin\s+(?:our\s+)?(?:vip\s+)?(?:telegram|channel|group|club)\b", _FLAGS),
                re.compile(r"\b(?:t\.me|telegram\.me)\/(?:joinchat\/|[a-zA-Z0-9_+]+)\b", _FLAGS),
                re.compile(r"\bchat\.whatsapp\.com\/[a-zA-Z0-9_-]+\b", _FLAGS),
                re.compile(r"\bgroup\s+join\s+karo\b", _FLAGS),
            ],
            "Unregulated Telegram and WhatsApp groups isolate victims, display coordinated fake member feedback, and execute pump-and-dump operations.",
            "Private groups me orchestrated fake profit screenshots dikha kar logon ko lalach diya jata hai.",
            "Avoid joining unsolicited investment groups or private VIP trading syndicates.",
        ),
        # 5. LINK CLICK (MEDIUM)
        (
            ActionType.LINK_CLICK,
            "Open unverified link / URL",
            "Unverified link ya website kholna",
            "MEDIUM",
            [
                re.compile(r"\b(?:click|open|visit)\s+(?:this\s+)?(?:link|url|website)\b", _FLAGS),
                re.compile(r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_\-\.\/]+\b", _FLAGS),
                re.compile(r"\blink\s+par\s+click\s+karo\b", _FLAGS),
            ],
            "Shortened and obscure links frequently redirect to lookalike phishing portals designed to harvest login credentials.",
            "Short links aksar fake phishing pages par le jati hain.",
            "Do not click shortened or unfamiliar links. Always type official website addresses directly into your browser.",
        ),
        # 6. PERSONAL DATA / KYC SHARING (HIGH)
        (
            ActionType.PERSONAL_DATA_SHARING,
            "Share personal identity or KYC details (PAN / Aadhaar)",
            "Aadhaar, PAN ya personal data share karna",
            "HIGH",
            [
                re.compile(r"\b(?:send|submit|share|upload)\s+(?:your\s+)?(?:pan|aadhaar|id\s+proof|bank\s+statement)\b", _FLAGS),
                re.compile(r"\baadhaar\s+(?:card\s+)?(?:bhejo|photo)\b", _FLAGS),
                re.compile(r"\bpan\s+card\s+(?:bhejo|upload)\b", _FLAGS),
            ],
            "Identity documents can be weaponized for unauthorized SIM issuance, mule account creation, or identity theft.",
            "Informal chats me identity proof share karne se identity theft aur fake accounts banne ka khatra hota hai.",
            "Never send copies of your PAN or Aadhaar over WhatsApp or Telegram.",
        ),
        # 7. CONTACT EXTERNAL NUMBER (LOW)
        (
            ActionType.CONTACT_EXTERNAL_NUMBER,
            "Contact private WhatsApp / Telegram handler",
            "Private number ya admin se contact karna",
            "LOW",
            [
                re.compile(r"\b(?:message|dm|contact|whatsapp|call)\s+(?:me|admin|our\s+team|us)\s+at\b", _FLAGS),
                re.compile(r"\bwa\.me\/\d+\b", _FLAGS),
                re.compile(r"\badmin\s+ko\s+message\s+karo\b", _FLAGS),
            ],
            "Scammers avoid public audit by funneling discussions into private 1-on-1 direct messages.",
            "Private messages me batch-wise target kiya jata hai taaki public scrutiny na ho.",
            "Verify official customer support numbers on official regulator/company websites before initiating contact.",
        ),
        # 8. INVESTMENT ACTION (MEDIUM)
        (
            ActionType.INVESTMENT_ACTION,
            "Execute unsolicited trade or investment",
            "Unsolicited tip par investment karna",
            "MEDIUM",
            [
                re.compile(r"\b(?:buy|invest|trade)\s+(?:now|immediately|today)\b", _FLAGS),
                re.compile(r"\bbuy\s+immediately\s+before\s+market\s+opens\b", _FLAGS),
                re.compile(r"\babhi\s+invest\s+karo\b", _FLAGS),
            ],
            "Unsolicited investment tips frequently manipulate thinly traded stocks or fictitious cryptocurrency tokens.",
            "Unsolicited tips par trading karna risky hota hai aur SEBI regulations ke khilaf hai.",
            "Consult a registered SEBI Investment Adviser (RIA) before committing investment capital.",
        ),
    ]

    @classmethod
    def evaluate(cls, text: str) -> SafeActionGateReport:
        """Evaluates message text for actionable requests and returns structured report."""
        if not text or not text.strip():
            return SafeActionGateReport(has_actions=False)

        detected_actions: List[DetectedAction] = []
        seen_types = set()

        for action_type, label_en, label_hi, severity, patterns, why_en, why_hi, directive in cls.ACTION_RULES:
            if action_type in seen_types:
                continue

            for pat in patterns:
                m = pat.search(text)
                if m:
                    seen_types.add(action_type)
                    matched_str = m.group(0).strip()
                    detected_actions.append(
                        DetectedAction(
                            action_type=action_type,
                            label_en=label_en,
                            label_hi=label_hi,
                            severity=severity,
                            matched_phrase=matched_str,
                            why_dangerous_en=why_en,
                            why_dangerous_hi=why_hi,
                            safe_directive=directive,
                        )
                    )
                    break

        critical_actions = [a for a in detected_actions if a.severity == "CRITICAL"]

        guidance = [a.safe_directive for a in detected_actions]
        if not guidance:
            guidance.append("No high-risk actions requested in this message. Continue to practice normal verification.")

        # Build Hinglish summary
        if detected_actions:
            action_names = [f"'{a.label_hi}'" for a in detected_actions]
            hinglish_summary = f"Message aapse yeh actions lene ke liye keh raha hai: {', '.join(action_names)}. Savdhaan rahein aur kisi bhi unverified request par amal na karein."
        else:
            hinglish_summary = "Is message mein koi immediate harmful action request detect nahi hui."

        return SafeActionGateReport(
            has_actions=len(detected_actions) > 0,
            actions=detected_actions,
            critical_actions=critical_actions,
            guidance=guidance,
            hinglish_summary=hinglish_summary,
        )
