"""
Comprehensive entity and structural token extraction module for SachCheck.
Extracts company names, SEBI registration references, URLs, domains, Telegram handles,
WhatsApp numbers, phone numbers, email addresses, UPI IDs, amounts, and percentage claims.
Enforces the mandatory ethical rule:
Never claim a phone belongs to a person, UPI belongs to a company, URL is malicious,
or an entity is fraudulent unless authoritative regulatory evidence supports it.
"""

import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from research.models import ExtractedUrlInfo


@dataclass
class ExtractedEntityRecord:
    """Represents an extracted entity or contact token with safety disclaimer."""
    entity_type: str  # COMPANY, SEBI_REG_NO, TELEGRAM, WHATSAPP, PHONE, EMAIL, UPI, AMOUNT, PERCENTAGE
    raw_value: str
    normalized_value: str
    context: str = ""
    verification_note: str = ""


@dataclass
class FullEntityReport:
    """Consolidated report of all extracted entities from the message or OCR text."""
    companies: List[str] = field(default_factory=list)
    sebi_registration_numbers: List[str] = field(default_factory=list)
    urls: List[ExtractedUrlInfo] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    telegram_handles: List[str] = field(default_factory=list)
    whatsapp_numbers: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    upi_ids: List[str] = field(default_factory=list)
    amounts: List[str] = field(default_factory=list)
    percentage_claims: List[str] = field(default_factory=list)
    all_entity_records: List[ExtractedEntityRecord] = field(default_factory=list)


class EntityExtractor:
    """Extracts entities, handles, credentials and financial metrics without biased labeling."""

    _FLAGS = re.IGNORECASE | re.UNICODE

    # Regex definitions
    SEBI_REG_PATTERN = re.compile(
        r"\b(?:INZ|INA|INH|INM|INF|INP|MB\/|CA\/)[0-9A-Z]{6,12}\b", _FLAGS
    )
    COMPANY_PATTERN = re.compile(
        r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?(?:Capital|Advisory|Services|Traders|Investments|Fund|Pvt|Ltd|Brokers|Securities|Wealth|Ventures|Trading))\b"
    )
    PHONE_PATTERN = re.compile(
        r"(?:\+91[-\s]?)?[6-9]\d{9}\b"
    )
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    )
    UPI_PATTERN = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,40}@[a-zA-Z]{2,20}\b"
    )
    TELEGRAM_PATTERN = re.compile(
        r"(?:@([a-zA-Z0-9_]{4,32})|t\.me\/([a-zA-Z0-9_+]{4,32}))", _FLAGS
    )
    WHATSAPP_PATTERN = re.compile(
        r"(?:chat\.whatsapp\.com\/[a-zA-Z0-9_-]{10,30}|wa\.me\/(\d{10,13}))", _FLAGS
    )
    AMOUNT_PATTERN = re.compile(
        r"(?:(?:₹|rs\.?|inr|\$)\s*[\d,]+(?:\.\d{2})?|\b[\d,]+\s*(?:lakh|crore|k)\b)", _FLAGS
    )
    PERCENT_PATTERN = re.compile(
        r"\b\d+(?:\.\d+)?%\b|\b\d+x\b", _FLAGS
    )
    URL_PATTERN = re.compile(
        r"(?:https?:\/\/|www\.)[^\s<>\"]+|(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_\-\.\/]+",
        _FLAGS,
    )

    SHORTENED_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly",
        "ow.ly", "cutt.ly", "rb.gy", "tiny.cc", "goo.gl"
    }

    @classmethod
    def extract_all(cls, text: str) -> FullEntityReport:
        """Extracts complete set of entities from message text."""
        if not text:
            return FullEntityReport()

        report = FullEntityReport()
        records: List[ExtractedEntityRecord] = []

        # 1. Company / Intermediary names
        companies = []
        for m in cls.COMPANY_PATTERN.finditer(text):
            comp = m.group(1).strip()
            if comp.lower() not in {"sebi", "rbi", "government", "official"}:
                companies.append(comp)
                records.append(
                    ExtractedEntityRecord(
                        entity_type="COMPANY",
                        raw_value=comp,
                        normalized_value=comp,
                        verification_note="Extracted entity name. Verify registration on sebi.gov.in."
                    )
                )
        report.companies = list(dict.fromkeys(companies))

        # 2. SEBI Registration numbers
        sebi_nums = []
        for m in cls.SEBI_REG_PATTERN.finditer(text):
            num = m.group(0).strip().upper()
            sebi_nums.append(num)
            records.append(
                ExtractedEntityRecord(
                    entity_type="SEBI_REG_NO",
                    raw_value=num,
                    normalized_value=num,
                    verification_note="SEBI registration format. Must be verified directly in SEBI database."
                )
            )
        report.sebi_registration_numbers = list(dict.fromkeys(sebi_nums))

        # 3. URLs & Domains
        urls: List[ExtractedUrlInfo] = []
        domains: List[str] = []
        for m in cls.URL_PATTERN.finditer(text):
            raw_url = m.group(0).strip(".,;:!?)\"'>")
            full_url = raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}"
            parsed = urlparse(full_url)
            dom = parsed.netloc.lower()
            if dom.startswith("www."):
                dom = dom[4:]

            is_https = full_url.startswith("https://")
            is_short = dom in cls.SHORTENED_DOMAINS
            note = "Shortened URL" if is_short else ("HTTPS Secure" if is_https else "Unencrypted HTTP")

            url_info = ExtractedUrlInfo(
                original_url=raw_url,
                domain=dom,
                is_https=is_https,
                is_shortened=is_short,
                note=note,
            )
            urls.append(url_info)
            if dom:
                domains.append(dom)
            records.append(
                ExtractedEntityRecord(
                    entity_type="URL",
                    raw_value=raw_url,
                    normalized_value=dom,
                    verification_note=f"Domain: {dom}. Verify domain legitimacy before opening."
                )
            )
        report.urls = urls
        report.domains = list(dict.fromkeys(domains))

        # 4. Telegram handles
        tg_handles = []
        for m in cls.TELEGRAM_PATTERN.finditer(text):
            handle = m.group(1) or m.group(2)
            if handle:
                clean_handle = f"@{handle.lstrip('@')}"
                tg_handles.append(clean_handle)
                records.append(
                    ExtractedEntityRecord(
                        entity_type="TELEGRAM",
                        raw_value=m.group(0),
                        normalized_value=clean_handle,
                        verification_note="Informal chat handle. Does not verify identity or legal registration."
                    )
                )
        report.telegram_handles = list(dict.fromkeys(tg_handles))

        # 5. WhatsApp numbers/links
        wa_list = []
        for m in cls.WHATSAPP_PATTERN.finditer(text):
            wa_list.append(m.group(0))
            records.append(
                ExtractedEntityRecord(
                    entity_type="WHATSAPP",
                    raw_value=m.group(0),
                    normalized_value=m.group(0),
                    verification_note="WhatsApp invitation link or direct chat number."
                )
            )
        report.whatsapp_numbers = list(dict.fromkeys(wa_list))

        # 6. Phone numbers
        phones = []
        for m in cls.PHONE_PATTERN.finditer(text):
            phones.append(m.group(0))
            records.append(
                ExtractedEntityRecord(
                    entity_type="PHONE",
                    raw_value=m.group(0),
                    normalized_value=m.group(0),
                    verification_note="Unverified phone number. Cannot assume identity without carrier records."
                )
            )
        report.phone_numbers = list(dict.fromkeys(phones))

        # 7. Emails
        emails = []
        for m in cls.EMAIL_PATTERN.finditer(text):
            e = m.group(0).lower()
            emails.append(e)
            records.append(
                ExtractedEntityRecord(
                    entity_type="EMAIL",
                    raw_value=m.group(0),
                    normalized_value=e,
                    verification_note="Email address detected."
                )
            )
        report.email_addresses = list(dict.fromkeys(emails))

        # 8. UPI IDs (Filter out false-positive emails)
        upis = []
        for m in cls.UPI_PATTERN.finditer(text):
            u = m.group(0).lower()
            # Avoid standard email domains like gmail.com, yahoo.com
            common_email_tlds = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "example.com"}
            domain_part = u.split("@")[-1] if "@" in u else ""
            if domain_part not in common_email_tlds:
                upis.append(u)
                records.append(
                    ExtractedEntityRecord(
                        entity_type="UPI",
                        raw_value=m.group(0),
                        normalized_value=u,
                        verification_note="Informal UPI payment address. Does not prove commercial entity identity."
                    )
                )
        report.upi_ids = list(dict.fromkeys(upis))

        # 9. Amounts & Percentages
        report.amounts = list(dict.fromkeys(cls.AMOUNT_PATTERN.findall(text)))
        report.percentage_claims = list(dict.fromkeys(cls.PERCENT_PATTERN.findall(text)))
        report.all_entity_records = records

        return report
