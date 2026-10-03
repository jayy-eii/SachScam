"""
Privacy and sensitive data audit module for SachCheck.
Detects, warns, and redacts authentication credentials and personal identity tokens
(OTP, PIN, passwords, bank account numbers, card numbers, Aadhaar, PAN, UPI, phones).
Ensures sensitive information is never leaked to external search queries.
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class PrivacyAuditReport:
    """Report detailing detected sensitive tokens and privacy advisories."""
    has_sensitive_data: bool
    detected_types: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    redacted_text: str = ""
    detected_items: Dict[str, List[str]] = field(default_factory=dict)


class PrivacyAuditor:
    """Audits text extracted from chat screenshots for private/credential data."""

    # Explicit regex patterns for private authentication credentials
    PATTERNS: Dict[str, Tuple[re.Pattern, str]] = {
        "OTP": (
            re.compile(r"\b(?:otp|one[- ]time[- ]password|verification\s+code)\s*[:=]?\s*([0-9]{4,8})\b", re.IGNORECASE),
            "[REDACTED_OTP]"
        ),
        "PIN": (
            re.compile(r"\b(?:pin|upi[- ]pin|mpin|security\s+pin)\s*[:=]?\s*([0-9]{4,6})\b", re.IGNORECASE),
            "[REDACTED_PIN]"
        ),
        "PASSWORD": (
            re.compile(r"\b(?:password|passcode|pwd|secret\s+key)\s*[:=]?\s*([^\s]{4,30})\b", re.IGNORECASE),
            "[REDACTED_PASSWORD]"
        ),
        "CARD_NUMBER": (
            re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b|\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
            "[REDACTED_CARD_NUMBER]"
        ),
        "BANK_ACCOUNT": (
            re.compile(r"\b(?:a/c|account\s+no\.?|account\s+number)\s*[:=]?\s*(\d{9,18})\b", re.IGNORECASE),
            "[REDACTED_BANK_ACCOUNT]"
        ),
        "AADHAAR": (
            re.compile(r"\b[2-9]\d{3}[-\s]\d{4}[-\s]\d{4}\b"),
            "[REDACTED_AADHAAR]"
        ),
        "PAN": (
            re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
            "[REDACTED_PAN]"
        ),
        "UPI_ID": (
            re.compile(r"\b[a-zA-Z0-9.\-_]{2,40}@[a-zA-Z]{2,20}\b"),
            "[REDACTED_UPI]"
        ),
        "PHONE_NUMBER": (
            re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"),
            "[REDACTED_PHONE]"
        ),
    }

    PRIVACY_REMINDER = (
        "Privacy reminder: Screenshots may contain sensitive information. "
        "Avoid uploading OTPs, passwords, PINs or unnecessary personal information."
    )

    @classmethod
    def audit_text(cls, text: str) -> PrivacyAuditReport:
        """
        Scans text for sensitive information, generates warnings, and creates sanitized text.
        """
        if not text:
            return PrivacyAuditReport(has_sensitive_data=False, redacted_text="")

        detected_types: List[str] = []
        warnings: List[str] = []
        detected_items: Dict[str, List[str]] = {}
        redacted = text

        for data_type, (pattern, placeholder) in cls.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                # Handle group matches vs full matches
                clean_matches = []
                for m in matches:
                    val = m if isinstance(m, str) else m[0]
                    clean_matches.append(val)

                if clean_matches:
                    detected_types.append(data_type)
                    detected_items[data_type] = clean_matches
                    redacted = pattern.sub(placeholder, redacted)

                    # Generate specific user advisory
                    if data_type in ("OTP", "PIN", "PASSWORD"):
                        warnings.append(
                            f"⚠️ Authentication credential ({data_type}) detected. Never share or upload one-time passwords or security PINs."
                        )
                    elif data_type in ("CARD_NUMBER", "BANK_ACCOUNT"):
                        warnings.append(
                            f"⚠️ Financial account detail ({data_type.replace('_', ' ').title()}) detected. Never share banking credentials in public channels."
                        )
                    elif data_type in ("AADHAAR", "PAN"):
                        warnings.append(
                            f"⚠️ National identity number ({data_type}) detected. Personal identity documents should not be shared in informal chats."
                        )

        has_sensitive = len(detected_types) > 0

        return PrivacyAuditReport(
            has_sensitive_data=has_sensitive,
            detected_types=detected_types,
            warnings=warnings,
            redacted_text=redacted,
            detected_items=detected_items,
        )

    @classmethod
    def redact_for_search(cls, text: str) -> str:
        """Strips credentials so external web search queries are strictly privacy-safe."""
        return cls.audit_text(text).redacted_text
