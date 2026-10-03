"""
Remote Access Capability Reference and Context-Aware Analyzer for SachCheck.

MANDATORY DISTINCTION:
This catalog is a "Remote Access Capability Reference", NOT a malware blacklist.
Legitimate remote-access tools (e.g. AnyDesk, TeamViewer, RustDesk) are authentic,
widely used software that can be abused in social-engineering and financial fraud schemes.
SachCheck NEVER classifies an application itself as malware or scam software without
authoritative security evidence. Instead, it analyzes HOW the application is being requested
within the message context (especially financial accounts, credentials, or payments).
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any


class RemoteAccessRiskLevel:
    INFORMATIONAL = "INFORMATIONAL"
    LOW_CAUTION = "LOW_CAUTION"
    MEDIUM_CAUTION = "MEDIUM_CAUTION"
    HIGH_CAUTION = "HIGH_CAUTION"
    STOP_AND_VERIFY = "STOP_AND_VERIFY"


# Known Remote-Access Applications Catalog
# NOTE: This list represents software with remote device viewing/control capabilities.
# These applications are NOT inherently malicious.
REMOTE_ACCESS_APPS_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "anydesk",
        "name": "AnyDesk",
        "category": "Remote Desktop / Support",
        "patterns": [
            r"\banydesk\b",
            r"\bany\s+desk\b",
            r"\banydesk\.com\b",
            r"\banydesk\.exe\b",
            r"\banydesk\.apk\b",
        ],
        "official_url": "https://anydesk.com",
        "description": "Legitimate, widely-used cross-platform remote desktop and support software.",
    },
    {
        "id": "teamviewer",
        "name": "TeamViewer",
        "category": "Remote Desktop / Support",
        "patterns": [
            r"\bteamviewer\b",
            r"\bteam\s+viewer\b",
            r"\bteamviewer\.com\b",
            r"\bteamviewer\.apk\b",
        ],
        "official_url": "https://teamviewer.com",
        "description": "Legitimate enterprise remote access, control, and screen-sharing platform.",
    },
    {
        "id": "rustdesk",
        "name": "RustDesk",
        "category": "Open-Source Remote Desktop",
        "patterns": [
            r"\brustdesk\b",
            r"\brust\s+desk\b",
            r"\brustdesk\.com\b",
        ],
        "official_url": "https://rustdesk.com",
        "description": "Legitimate open-source remote-desktop and virtual support software.",
    },
    {
        "id": "chrome_remote_desktop",
        "name": "Chrome Remote Desktop",
        "category": "Remote Desktop Utility",
        "patterns": [
            r"\bchrome\s+remote\s+desktop\b",
            r"\bremotedesktop\.google\.com\b",
        ],
        "official_url": "https://remotedesktop.google.com",
        "description": "Legitimate remote-desktop tool developed by Google.",
    },
    {
        "id": "quicksupport",
        "name": "QuickSupport",
        "category": "Mobile Remote Support Client",
        "patterns": [
            r"\bquicksupport\b",
            r"\bquick\s+support\b",
            r"\bqs\.apk\b",
        ],
        "official_url": "https://teamviewer.com/en/products/quicksupport",
        "description": "Legitimate mobile remote-support client module by TeamViewer.",
    },
    {
        "id": "ultraviewer",
        "name": "UltraViewer",
        "category": "Remote Support Software",
        "patterns": [
            r"\bultraviewer\b",
            r"\bultra\s+viewer\b",
        ],
        "official_url": "https://ultraviewer.net",
        "description": "Legitimate remote-desktop client used for computer technical support.",
    },
    {
        "id": "splashtop",
        "name": "Splashtop",
        "category": "Remote Access & Support",
        "patterns": [
            r"\bsplashtop\b",
            r"\bsplash\s+top\b",
        ],
        "official_url": "https://splashtop.com",
        "description": "Legitimate business remote access and virtual support solution.",
    },
    {
        "id": "zoho_assist",
        "name": "Zoho Assist",
        "category": "Cloud Remote Support",
        "patterns": [
            r"\bzoho\s+assist\b",
            r"\bassist\.zoho\b",
        ],
        "official_url": "https://zoho.com/assist",
        "description": "Legitimate cloud-based remote-support software by Zoho Corporation.",
    },
    {
        "id": "airdroid",
        "name": "AirDroid",
        "category": "Device Management & Mirroring",
        "patterns": [
            r"\bairdroid\b",
            r"\bair\s+droid\b",
        ],
        "official_url": "https://airdroid.com",
        "description": "Legitimate device management and screen-mirroring tool for mobile devices.",
    },
]


@dataclass
class AppReference:
    """Structured representation of an application detected in text or OCR."""
    name: Optional[str]
    type: str  # REMOTE_ACCESS | UNKNOWN_APP | FINANCIAL_APP | APK | OTHER
    source_text: str
    detected_from: str  # OCR | MESSAGE | URL | FILE
    confidence: float
    evidence: str
    official_url: Optional[str] = None
    app_category: str = "Remote Access / Remote Support"


@dataclass
class RemoteAccessAction:
    """A remote-control or session-granting action requested by the sender."""
    detected: bool
    action_type: str  # INSTALL_REMOTE_APP | SHARE_SESSION_CODE | GRANT_REMOTE_CONTROL | ENABLE_SCREEN_ACCESS | ENABLE_ACCESSIBILITY | UNKNOWN_REMOTE_ACTION
    evidence: str
    confidence: float
    label_en: str = ""
    label_hi: str = ""


@dataclass
class RemoteAccessAnalysisResult:
    """Complete structured assessment of remote access requests and action safety."""
    app_detected: bool
    apps: List[AppReference] = field(default_factory=list)
    remote_access_actions: List[RemoteAccessAction] = field(default_factory=list)
    financial_context: bool = False
    financial_terms: List[str] = field(default_factory=list)
    credential_request: bool = False
    credential_terms: List[str] = field(default_factory=list)
    payment_request: bool = False
    payment_terms: List[str] = field(default_factory=list)
    apk_request: bool = False
    apk_evidence: Optional[str] = None
    urgency_detected: bool = False
    urgency_terms: List[str] = field(default_factory=list)
    account_fix_claim: bool = False
    account_fix_evidence: Optional[str] = None
    unknown_contact_claim: bool = False
    external_url_detected: bool = False
    external_url_evidence: Optional[str] = None

    # Deterministic scoring & action classification
    risk_score: int = 0  # 0 to 100
    risk_level: str = RemoteAccessRiskLevel.INFORMATIONAL
    stop_condition: bool = False
    stop_reason: Optional[str] = None

    # Explanations & Evidence
    evidence: List[str] = field(default_factory=list)
    why_risky_en: List[str] = field(default_factory=list)
    why_risky_hi: List[str] = field(default_factory=list)
    safe_directives: List[str] = field(default_factory=list)
    what_to_do_unauthorized: List[str] = field(default_factory=list)
    what_to_do_already_granted: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_detected": self.app_detected,
            "apps": [
                {
                    "name": a.name,
                    "type": a.type,
                    "category": a.app_category,
                    "evidence": a.evidence,
                    "confidence": a.confidence,
                }
                for a in self.apps
            ],
            "remote_access_actions": [
                {
                    "type": act.action_type,
                    "evidence": act.evidence,
                    "confidence": act.confidence,
                }
                for act in self.remote_access_actions
            ],
            "financial_context": self.financial_context,
            "credential_request": self.credential_request,
            "payment_request": self.payment_request,
            "apk_request": self.apk_request,
            "urgency_detected": self.urgency_detected,
            "account_fix_claim": self.account_fix_claim,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "stop_condition": self.stop_condition,
            "stop_reason": self.stop_reason,
            "evidence": self.evidence,
        }


class RemoteAccessAnalyzer:
    """
    Context-aware analyzer for remote-access software and APK installation solicitations.
    Evaluates combinations of capabilities, actions, financial context, and credentials.
    """

    _FLAGS = re.IGNORECASE | re.UNICODE

    # 1. Remote-control actions
    SESSION_CODE_PATTERNS = [
        re.compile(r"\b(?:send|share|give|tell|provide)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:code|id|session\s+code|anydesk\s+code|anydesk\s+id|teamviewer\s+id|remote\s+id|pin|password|9[- ]digit\s+number)\b", _FLAGS),
        re.compile(r"\b(?:code|id)\s+(?:bhejo|share\s+karo|send\s+karo|batao)\b", _FLAGS),
        re.compile(r"\bshare\s+(?:the\s+|your\s+)?anydesk\s+(?:code|id)\b", _FLAGS),
        re.compile(r"\bsend\s+(?:the\s+|your\s+)?session\s+code\b", _FLAGS),
        re.compile(r"\banydesk\s+code\b", _FLAGS),
    ]

    REMOTE_CONTROL_PATTERNS = [
        re.compile(r"\b(?:give|allow|grant|provide)\s+(?:me\s+)?(?:remote\s+access|remote\s+control|access|screen\s+access|device\s+access)\b", _FLAGS),
        re.compile(r"\b(?:accept|approve)\s+(?:my\s+)?(?:remote\s+request|connection|incoming\s+request)\b", _FLAGS),
        re.compile(r"\b(?:let|allow)\s+me\s+control\s+your\s+(?:phone|device|screen|mobile|computer)\b", _FLAGS),
        re.compile(r"\bremote\s+pe\s+(?:lo|le\s+lo|access\s+do)\b", _FLAGS),
        re.compile(r"\baccess\s+de\s+do\b", _FLAGS),
    ]

    SCREEN_ACCESS_PATTERNS = [
        re.compile(r"\b(?:share|enable|start)\s+(?:your\s+)?screen(?:\s+sharing)?\b", _FLAGS),
        re.compile(r"\bscreen\s+share\s+(?:karo|kijiye)\b", _FLAGS),
    ]

    ACCESSIBILITY_PATTERNS = [
        re.compile(r"\benable\s+(?:accessibility|device\s+admin|unknown\s+sources|special\s+permissions?)\b", _FLAGS),
        re.compile(r"\baccessibility\s+permission\s+(?:enable|allow|on)\s+karo\b", _FLAGS),
        re.compile(r"\bunknown\s+sources\s+(?:enable|allow)\s+karo\b", _FLAGS),
    ]

    # 2. APK installation language
    APK_PATTERNS = [
        re.compile(r"\b(?:download|install)\s+(?:this\s+)?(?:apk|app|application|software)\b", _FLAGS),
        re.compile(r"\bapk\s+(?:download|file|link)\b", _FLAGS),
        re.compile(r"\b(?:install|download)\s+from\s+(?:this\s+)?(?:link|url|website)\b", _FLAGS),
        re.compile(r"\bplay\s+store\s+pe\s+nah[i|ee]n\s+mileg[a|i]\b", _FLAGS),
        re.compile(r"\bplay\s+store\s+ke\s+bahar\b", _FLAGS),
        re.compile(r"\binstall\s+(?:outside|without)\s+play\s+store\b", _FLAGS),
        re.compile(r"\bapk\s+(?:se\s+)?install\s+karo\b", _FLAGS),
        re.compile(r"\bye\s+app\s+install\s+karo\b", _FLAGS),
        re.compile(r"\bhttps?:\/\/[^\s]+\.apk\b", _FLAGS),
    ]

    # 3. Financial Context Terms
    FINANCIAL_TERMS = [
        (re.compile(r"\b(?:trading|demat|brokerage|investment|financial)\s+accounts?\b", _FLAGS), "Trading / Demat Account"),
        (re.compile(r"\b(?:bank|saving|current)\s+accounts?\b", _FLAGS), "Bank Account"),
        (re.compile(r"\b(?:withdrawal|refund|deposit|payout)\b", _FLAGS), "Withdrawal / Refund"),
        (re.compile(r"\b(?:upi|wallet|net\s+banking|credit\s+card|debit\s+card)\b", _FLAGS), "Payment / Banking Channel"),
        (re.compile(r"\b(?:kyc|pan\s+card|aadhaar)\b", _FLAGS), "KYC / Identity"),
        (re.compile(r"\b(?:shares?|stocks?|mutual\s+funds?|crypto|funds)\b", _FLAGS), "Securities / Funds"),
        (re.compile(r"(?:₹|rs\.?|inr|\$)\s*[\d,]+", _FLAGS), "Monetary Amount"),
    ]

    # 4. Account "Fix" / "Unlock" / "Recover" Claims
    ACCOUNT_FIX_PATTERNS = [
        re.compile(r"\b(?:fix|recover|unlock|unfreeze|activate|verify|process|clear|manage)\s+(?:your\s+)?(?:trading|bank|account|withdrawal|money|refund|funds|kyc)\b", _FLAGS),
        re.compile(r"\bi(?:'ll|\s+will)\s+(?:fix|help\s+you\s+recover|activate|process)\s+(?:your\s+)?(?:account|money|funds|withdrawal|profit)\b", _FLAGS),
        re.compile(r"\b(?:trading\s+|bank\s+)?account\s+(?:unlock|unfreeze|verify|activate)\s+(?:karne\s+ke\s+liye|kar\s+(?:dunga|denge|diya\s+jayega|do))\b", _FLAGS),
        re.compile(r"\b(?:withdrawal|funds?|kyc)\s+(?:clear|unlock|verify)\s+karne\s+ke\s+liye\b", _FLAGS),
    ]

    # 5. Credential Requests (OTP, PIN, Password)
    CREDENTIAL_PATTERNS = [
        re.compile(r"\b(?:share|send|provide|give|tell)\s+(?:your\s+)?(?:otp|pin|mpin|upi\s+pin|password|passcode)\b", _FLAGS),
        re.compile(r"\botp\s+(?:bhejo|share\s+karo|batao|send\s+karo)\b", _FLAGS),
        re.compile(r"\benter\s+(?:your\s+)?(?:otp|pin|password)\b", _FLAGS),
        re.compile(r"\bshare\s+otp\b", _FLAGS),
    ]

    # 6. Payment Requests
    PAYMENT_PATTERNS = [
        re.compile(r"\b(?:pay|send|transfer|deposit)\s*(?:to\s+)?(?:₹|rs\.?|inr)?\s*[\d,]+\b", _FLAGS),
        re.compile(r"\b(?:registration|processing|clearance|tax|withdrawal)\s+fees?\b", _FLAGS),
        re.compile(r"\bupi\s+pe\s+(?:payment|paise)\b", _FLAGS),
        re.compile(r"\bpaise\s+(?:transfer|bhejo|jama)\s+karo\b", _FLAGS),
    ]

    # 7. Urgency / High Pressure
    URGENCY_PATTERNS = [
        re.compile(r"\b(?:urgent|urgently|immediately|right\s+now|turant|jaldi|abhi)\b", _FLAGS),
        re.compile(r"\b(?:account\s+will\s+be\s+(?:blocked|suspended|closed)|otherwise\s+funds\s+frozen)\b", _FLAGS),
        re.compile(r"\bwithin\s+\d+\s+(?:minutes|hours)\b", _FLAGS),
    ]

    # 8. Benign IT / Support Context (False Positive mitigation)
    BENIGN_IT_PATTERNS = [
        re.compile(r"\b(?:it\s+department|internal\s+support|company\s+laptop|office\s+it|printer|troubleshoot|setup\s+my\s+monitor|hardware\s+issue)\b", _FLAGS),
        re.compile(r"\bhelp\s+(?:me\s+)?(?:fix\s+)?(?:my\s+)?(?:printer|laptop|pc|computer|monitor|mouse|keyboard|wifi)\b", _FLAGS),
        re.compile(r"\bfix\s+(?:my\s+|the\s+|a\s+)?printer\b", _FLAGS),
        re.compile(r"\bhelp\s+(?:my\s+friend|colleague)\s+troubleshoot\b", _FLAGS),
    ]

    @classmethod
    def analyze(cls, text: str, source: str = "MESSAGE") -> RemoteAccessAnalysisResult:
        """
        Executes context-aware remote access risk evaluation on the provided text.
        """
        if not text or not text.strip():
            return RemoteAccessAnalysisResult(
                app_detected=False,
                risk_score=0,
                risk_level=RemoteAccessRiskLevel.INFORMATIONAL,
            )

        cleaned_text = text.strip()
        evidence_list: List[str] = []
        why_en: List[str] = []
        why_hi: List[str] = []
        safe_directives: List[str] = []

        # -------------------------------------------------------------
        # STEP 1: DETECT RECOGNIZED REMOTE-ACCESS APPS
        # -------------------------------------------------------------
        detected_apps: List[AppReference] = []
        seen_app_names = set()

        for app_info in REMOTE_ACCESS_APPS_CATALOG:
            for pat_str in app_info["patterns"]:
                match = re.search(pat_str, cleaned_text, cls._FLAGS)
                if match:
                    app_name = app_info["name"]
                    if app_name not in seen_app_names:
                        seen_app_names.add(app_name)
                        matched_str = match.group(0).strip()
                        detected_apps.append(
                            AppReference(
                                name=app_name,
                                type="REMOTE_ACCESS",
                                source_text=matched_str,
                                detected_from=source,
                                confidence=0.98,
                                evidence=f"App reference: '{matched_str}'",
                                official_url=app_info["official_url"],
                                app_category=app_info["category"],
                            )
                        )
                    break

        app_detected = len(detected_apps) > 0

        # -------------------------------------------------------------
        # STEP 2: DETECT REMOTE ACTIONS
        # -------------------------------------------------------------
        detected_actions: List[RemoteAccessAction] = []
        seen_action_types = set()

        # Action: Install Remote App
        if app_detected and any(re.search(p, cleaned_text, cls._FLAGS) for p in [r"\b(?:install|download|use|open)\b", r"\b(?:install|download)\s+karo\b"]):
            detected_actions.append(
                RemoteAccessAction(
                    detected=True,
                    action_type="INSTALL_REMOTE_APP",
                    evidence=f"Request to install remote-access software ({', '.join(a.name for a in detected_apps)})",
                    confidence=0.95,
                    label_en="Install remote-access software",
                    label_hi="Remote-access software install karna",
                )
            )
            seen_action_types.add("INSTALL_REMOTE_APP")

        # Action: Share Session Code / ID
        for pat in cls.SESSION_CODE_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                detected_actions.append(
                    RemoteAccessAction(
                        detected=True,
                        action_type="SHARE_SESSION_CODE",
                        evidence=m.group(0).strip(),
                        confidence=0.95,
                        label_en="Share remote session code / ID",
                        label_hi="Remote session code ya ID share karna",
                    )
                )
                seen_action_types.add("SHARE_SESSION_CODE")
                break

        # Action: Grant Remote Control
        for pat in cls.REMOTE_CONTROL_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                detected_actions.append(
                    RemoteAccessAction(
                        detected=True,
                        action_type="GRANT_REMOTE_CONTROL",
                        evidence=m.group(0).strip(),
                        confidence=0.92,
                        label_en="Grant remote control of device",
                        label_hi="Device ka remote control access dena",
                    )
                )
                seen_action_types.add("GRANT_REMOTE_CONTROL")
                break

        # Action: Enable Screen Access
        for pat in cls.SCREEN_ACCESS_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                detected_actions.append(
                    RemoteAccessAction(
                        detected=True,
                        action_type="ENABLE_SCREEN_ACCESS",
                        evidence=m.group(0).strip(),
                        confidence=0.90,
                        label_en="Enable screen sharing / screen viewing",
                        label_hi="Screen sharing ya viewing enable karna",
                    )
                )
                seen_action_types.add("ENABLE_SCREEN_ACCESS")
                break

        # Action: Enable Accessibility / Admin
        for pat in cls.ACCESSIBILITY_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                detected_actions.append(
                    RemoteAccessAction(
                        detected=True,
                        action_type="ENABLE_ACCESSIBILITY",
                        evidence=m.group(0).strip(),
                        confidence=0.92,
                        label_en="Enable accessibility or device permissions",
                        label_hi="Accessibility ya device permissions enable karna",
                    )
                )
                seen_action_types.add("ENABLE_ACCESSIBILITY")
                break

        # -------------------------------------------------------------
        # STEP 3: APK REQUEST DETECTION
        # -------------------------------------------------------------
        apk_request = False
        apk_evidence = None
        for pat in cls.APK_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                apk_request = True
                apk_evidence = m.group(0).strip()
                break

        if apk_request and not app_detected:
            detected_apps.append(
                AppReference(
                    name="External APK / Custom Package",
                    type="APK",
                    source_text=apk_evidence or "APK request",
                    detected_from=source,
                    confidence=0.90,
                    evidence=apk_evidence or "External APK request",
                    app_category="External Package / APK",
                )
            )

        if apk_request and "INSTALL_REMOTE_APP" not in seen_action_types and "INSTALL_APP" not in seen_action_types:
            detected_actions.append(
                RemoteAccessAction(
                    detected=True,
                    action_type="INSTALL_APP",
                    evidence=apk_evidence or "Install external APK",
                    confidence=0.90,
                    label_en="Install external application / APK",
                    label_hi="External app ya APK install karna",
                )
            )
            seen_action_types.add("INSTALL_APP")

        # -------------------------------------------------------------
        # STEP 4: FINANCIAL CONTEXT DETECTION
        # -------------------------------------------------------------
        financial_terms_found: List[str] = []
        for pat, label in cls.FINANCIAL_TERMS:
            m = pat.search(cleaned_text)
            if m:
                financial_terms_found.append(f"{label} ('{m.group(0).strip()}')")

        financial_context = len(financial_terms_found) > 0

        # -------------------------------------------------------------
        # STEP 5: CREDENTIALS, PAYMENTS, ACCOUNT FIX, URGENCY
        # -------------------------------------------------------------
        # Credential requests (OTP/PIN/Password)
        credential_terms: List[str] = []
        for pat in cls.CREDENTIAL_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                credential_terms.append(m.group(0).strip())
        credential_request = len(credential_terms) > 0

        # Payment requests
        payment_terms: List[str] = []
        for pat in cls.PAYMENT_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                payment_terms.append(m.group(0).strip())
        payment_request = len(payment_terms) > 0

        # Account Fix / Recovery claim
        account_fix_claim = False
        account_fix_evidence = None
        for pat in cls.ACCOUNT_FIX_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                account_fix_claim = True
                account_fix_evidence = m.group(0).strip()
                break

        # Urgency / Threats
        urgency_terms: List[str] = []
        for pat in cls.URGENCY_PATTERNS:
            m = pat.search(cleaned_text)
            if m:
                urgency_terms.append(m.group(0).strip())
        urgency_detected = len(urgency_terms) > 0

        # External URLs
        url_match = re.search(r"https?:\/\/[^\s<>\"]+", cleaned_text)
        external_url_detected = bool(url_match)
        external_url_evidence = url_match.group(0) if url_match else None

        # Benign IT context check
        is_benign_it = any(p.search(cleaned_text) for p in cls.BENIGN_IT_PATTERNS)

        # -------------------------------------------------------------
        # STEP 6: DETERMINISTIC EVIDENCE-BASED SCORING (Section 8)
        # -------------------------------------------------------------
        # Base weights per specification:
        # Remote-access app mentioned: +10
        # Remote-control request: +20
        # Unknown/external APK: +20
        # Financial-account context: +15
        # OTP/PIN/password request: +30
        # Payment request: +25
        # Urgency: +15
        # "Fix/recover/unlock your account" claim: +10
        # Unknown person/group claim: +10
        # External download URL: +15
        raw_score = 0

        if app_detected:
            raw_score += 10
            app_names_str = ", ".join(a.name for a in detected_apps)
            evidence_list.append(f"Remote-access capability mentioned: {app_names_str} (+10)")
            why_en.append(f"The message mentions recognized remote-desktop software ({app_names_str}). While legitimate for IT support, this software allows screen-viewing and input control.")
            why_hi.append(f"Message mein remote desktop software ({app_names_str}) ka zikr hai. Yeh software screen dekhne aur device control karne ke liye use hota hai.")

        if detected_actions:
            raw_score += 20
            act_names = ", ".join(a.label_en for a in detected_actions)
            evidence_list.append(f"Remote-control / session action requested: {act_names} (+20)")
            why_en.append(f"The sender solicits active device-control access: {act_names}. Granting this allows remote viewing of open apps and messages.")
            why_hi.append(f"Sender aapse remote access ya code mang raha hai ({act_names}). Isse samne wala aapka phone screen dekh sakta hai.")

        if apk_request:
            raw_score += 20
            evidence_list.append(f"External APK / unverified app installation requested: '{apk_evidence}' (+20)")
            why_en.append("The message asks you to install an application outside official stores (Google Play / App Store).")
            why_hi.append("Message official app store ke bahar se APK download karne ko keh raha hai.")

        if financial_context:
            raw_score += 15
            evidence_list.append(f"Financial context present: {', '.join(financial_terms_found[:3])} (+15)")
            why_en.append("Remote access or app installation is solicited in connection with banking, demat, or financial accounts.")
            why_hi.append("Remote access ya app installation ka request financial ya trading account ke sath joda gaya hai.")

        if credential_request:
            raw_score += 30
            evidence_list.append(f"Authentication credential requested (OTP/PIN/password): '{credential_terms[0]}' (+30)")
            why_en.append("CRITICAL: Message asks for sensitive authentication credentials (OTP/PIN/password). Genuine institutions never request these.")
            why_hi.append("Message aapse OTP, PIN ya password mang raha hai. Koi bhi legitimate sanstha yeh nahi mangti.")

        if payment_request:
            raw_score += 25
            evidence_list.append(f"Payment or fee transfer requested: '{payment_terms[0]}' (+25)")
            why_en.append("Payment or deposit requested alongside remote access or app installation.")
            why_hi.append("Remote access ke sath payment ya advance fee transfer ki maang ki gayi hai.")

        if urgency_detected:
            raw_score += 15
            evidence_list.append(f"Urgency or account threat detected: '{urgency_terms[0]}' (+15)")
            why_en.append("High-pressure urgency or threat of account suspension detected.")
            why_hi.append("Turant faisla lene ya account block hone ka dabav banaya gaya hai.")

        if account_fix_claim:
            raw_score += 10
            evidence_list.append(f"Account 'fix/recover/unlock' claim: '{account_fix_evidence}' (+10)")
            why_en.append("The sender claims remote access is required to 'fix', 'verify', or 'unlock' your financial account.")
            why_hi.append("Sender ka claim hai ki account theek karne ya paise release karne ke liye remote access zaroori hai.")

        if external_url_detected and apk_request:
            raw_score += 15
            evidence_list.append(f"External download URL detected: '{external_url_evidence}' (+15)")

        # False positive mitigation: If benign IT / printer support and NO financial context
        if is_benign_it and not financial_context and not credential_request and not payment_request:
            raw_score = min(raw_score, 10)

        # Normalize/cap score to 0–100
        risk_score = min(100, max(0, raw_score))

        # -------------------------------------------------------------
        # STEP 7: SPECIAL STOP CONDITIONS (Section 9)
        # -------------------------------------------------------------
        stop_condition = False
        stop_reason = None

        has_remote = app_detected or any(a.action_type in ("INSTALL_REMOTE_APP", "SHARE_SESSION_CODE", "GRANT_REMOTE_CONTROL") for a in detected_actions)

        # Condition 1: Remote Access + OTP/PIN/Password
        if has_remote and credential_request:
            stop_condition = True
            stop_reason = "STOP AND VERIFY: Request to grant remote access combined with OTP / PIN / Password solicitations represents an immediate takeover risk."

        # Condition 2: Remote Access + Financial Account + Payment
        elif has_remote and financial_context and payment_request:
            stop_condition = True
            stop_reason = "STOP AND VERIFY: Request to install remote access or grant control while demanding funds/fees for financial accounts matches documented fraud funnels."

        # Condition 3: Unknown APK + Financial Account + Credential Request
        elif apk_request and financial_context and credential_request:
            stop_condition = True
            stop_reason = "STOP AND VERIFY: Installing an external APK combined with sensitive credential solicitations poses critical account-compromise risk."

        # Condition 4: Remote Access + Urgent/Threatening + Financial Action
        elif has_remote and urgency_detected and (financial_context or payment_request):
            stop_condition = True
            stop_reason = "STOP AND VERIFY: High-pressure urgency demanding remote device access in a financial context is a primary coercion indicator."

        # -------------------------------------------------------------
        # STEP 8: RISK LEVEL CLASSIFICATION (Section 7)
        # -------------------------------------------------------------
        if stop_condition:
            risk_level = RemoteAccessRiskLevel.STOP_AND_VERIFY
            risk_score = max(risk_score, 85)
        elif risk_score >= 50:
            risk_level = RemoteAccessRiskLevel.HIGH_CAUTION
        elif risk_score >= 25:
            risk_level = RemoteAccessRiskLevel.MEDIUM_CAUTION
        elif risk_score >= 15:
            risk_level = RemoteAccessRiskLevel.LOW_CAUTION
        else:
            risk_level = RemoteAccessRiskLevel.INFORMATIONAL

        # -------------------------------------------------------------
        # STEP 9: ACTION DIRECTIVES & "WHAT TO DO NOW" (Section 18 & 19)
        # -------------------------------------------------------------
        what_to_do_unauthorized = [
            "Do NOT grant remote control of your phone or computer.",
            "Do NOT share remote session codes, AnyDesk IDs, or TeamViewer passwords.",
            "Do NOT share OTPs, UPI PINs, or banking passwords under any circumstances.",
            "Verify the caller or sender through the organization's official website or customer care number.",
            "Remember that genuine banks, brokers, and SEBI officials NEVER ask to connect via AnyDesk or TeamViewer.",
        ]

        what_to_do_already_granted = [
            "1. End the remote session immediately (close AnyDesk/TeamViewer or turn off Wi-Fi/Mobile Data).",
            "2. Disconnect/uninstall the remote-access software from your device if appropriate.",
            "3. Review recently installed applications and device permissions (Accessibility & Device Admin).",
            "4. Check your bank and demat accounts for unusual or unauthorized activity.",
            "5. Change passwords and UPI PINs from a different, secure device.",
            "6. Contact your bank or broker immediately through verified official emergency helplines to freeze affected accounts.",
            "7. If money was transferred or compromised, dial 1930 or file a report at cybercrime.gov.in.",
        ]

        if stop_condition or risk_level in (RemoteAccessRiskLevel.HIGH_CAUTION, RemoteAccessRiskLevel.STOP_AND_VERIFY):
            safe_directives.append("🛑 STOP BEFORE YOU ACT: Do not share your remote screen or session code.")
            safe_directives.append("Genuine financial institutions resolve account inquiries on their own servers, not through remote phone control.")
        elif risk_level == RemoteAccessRiskLevel.MEDIUM_CAUTION:
            safe_directives.append("⚠️ ACTION CAUTION: Verify who contacted you and why remote access is being requested before proceeding.")
        else:
            safe_directives.append("ℹ️ Remote access software noted. Ensure you only share remote access with authorized, verified IT personnel.")

        return RemoteAccessAnalysisResult(
            app_detected=app_detected,
            apps=detected_apps,
            remote_access_actions=detected_actions,
            financial_context=financial_context,
            financial_terms=financial_terms_found,
            credential_request=credential_request,
            credential_terms=credential_terms,
            payment_request=payment_request,
            payment_terms=payment_terms,
            apk_request=apk_request,
            apk_evidence=apk_evidence,
            urgency_detected=urgency_detected,
            urgency_terms=urgency_terms,
            account_fix_claim=account_fix_claim,
            account_fix_evidence=account_fix_evidence,
            external_url_detected=external_url_detected,
            external_url_evidence=external_url_evidence,
            risk_score=risk_score,
            risk_level=risk_level,
            stop_condition=stop_condition,
            stop_reason=stop_reason,
            evidence=evidence_list,
            why_risky_en=why_en,
            why_risky_hi=why_hi,
            safe_directives=safe_directives,
            what_to_do_unauthorized=what_to_do_unauthorized,
            what_to_do_already_granted=what_to_do_already_granted,
        )
