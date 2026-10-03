"""
Claim and entity extraction module for SachCheck.
Extracts factual claims requiring external research and redacts sensitive credentials.
"""

import re
from typing import List, Tuple, Optional
from urllib.parse import urlparse

from research.models import ExtractedClaim, ExtractedUrlInfo

# Patterns to sanitize and redact sensitive credentials before searching
SENSITIVE_PATTERNS = [
    re.compile(r"\b(?:otp|pin|passcode|code)\s*[:=]?\s*\d{4,8}\b", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]?\s*\S+\b", re.IGNORECASE),
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),  # 16-digit card number
    re.compile(r"\b(?:account|acct|a/c)\s*(?:no\.?|number)?\s*[:=]?\s*\d{9,18}\b", re.IGNORECASE),
]

# Patterns for extracting named entities in financial solicitations
ENTITY_PATTERNS = [
    re.compile(r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?)\s+(?:is|has\s+been|was)?\s*(?:sebi|rbi)\s+(?:approved|registered|certified|authorized)", re.IGNORECASE),
    re.compile(r"(?:from|by|at|with)\s+([A-Z][a-zA-Z0-9&.\s]{1,30}?(?:Capital|Advisory|Services|Traders|Investments|Fund|Pvt|Ltd|Brokers|Securities))", re.IGNORECASE),
    re.compile(r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?(?:Capital|Advisory|Services|Traders|Investments|Fund|Pvt|Ltd|Brokers|Securities))\b", re.IGNORECASE),
]

STOP_WORDS = {"urgent", "sebi", "rbi", "government", "official", "get", "dear", "hello", "hi", "investor"}

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "tiny.cc", "goo.gl"
}


def redact_sensitive_information(text: str) -> str:
    """
    Strips sensitive authentication credentials (OTPs, PINs, Passwords, Account numbers)
    so they are NEVER leaked into external search engine queries.
    """
    sanitized = text
    for pat in SENSITIVE_PATTERNS:
        sanitized = pat.sub("[REDACTED]", sanitized)
    return sanitized


def extract_entity_name(text: str) -> Optional[str]:
    """
    Extracts explicit commercial or advisory entity names mentioned in the message.
    Returns None if no distinct entity name is found (avoids fabricating entities).
    """
    for pat in ENTITY_PATTERNS:
        match = pat.search(text)
        if match:
            candidate = match.group(1).strip()
            if candidate.lower() not in STOP_WORDS and len(candidate) >= 3:
                return candidate
    return None


def extract_urls(text: str) -> List[ExtractedUrlInfo]:
    """
    Extracts and inspects all URLs present in the text.
    Classifies HTTPS status and shortened status without declaring safe/malicious.
    """
    url_pattern = re.compile(r"(?:https?:\/\/|www\.)[^\s<>\"]+|(?:bit\.ly|tinyurl\.com|t\.co|t\.me|chat\.whatsapp\.com)\/[a-zA-Z0-9_\-\.\/]+", re.IGNORECASE)
    matches = url_pattern.findall(text)
    extracted: List[ExtractedUrlInfo] = []
    seen = set()

    for raw_url in matches:
        clean_url = raw_url.strip(".,;:!?)\"'>")
        if clean_url in seen:
            continue
        seen.add(clean_url)

        full_url = clean_url if clean_url.startswith(("http://", "https://")) else f"https://{clean_url}"
        parsed = urlparse(full_url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        is_https = full_url.startswith("https://")
        is_shortened = domain in SHORTENED_DOMAINS

        if is_shortened:
            note = "Shortened URL detected. Short links obscure destination domains and should be verified before opening."
        elif not is_https:
            note = "Unencrypted HTTP link detected. Legitimate financial portals use secure HTTPS encryption."
        else:
            note = "Standard web link. Destination must be verified independently."

        extracted.append(
            ExtractedUrlInfo(
                original_url=clean_url,
                domain=domain,
                is_https=is_https,
                is_shortened=is_shortened,
                resolved_destination=None,
                note=note,
            )
        )

    return extracted


def extract_claims(text: str) -> List[ExtractedClaim]:
    """
    Extracts specific factual claims from the message to generate targeted search queries.
    Never searches the entire user message blindly.
    """
    sanitized_text = redact_sensitive_information(text)
    claims: List[ExtractedClaim] = []
    entity = extract_entity_name(sanitized_text)

    # 1. Check for SEBI regulatory claims
    sebi_match = re.search(r"([^.!?\n]*?\bsebi\s+(?:approved|registered|certified|endorsed|authorized)[^.!?\n]*)", sanitized_text, re.IGNORECASE)
    if sebi_match:
        claim_text = sebi_match.group(1).strip()
        queries = []
        if entity:
            queries.append(f'"{entity}" SEBI registration')
            queries.append(f'site:sebi.gov.in "{entity}"')
        else:
            queries.append('site:sebi.gov.in "recognized intermediaries"')
            queries.append('site:sebi.gov.in "investor alert"')

        claims.append(
            ExtractedClaim(
                claim_id="claim_sebi_reg",
                original_text=claim_text,
                claim_type="REGULATORY_REGISTRATION",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    # 2. Check for RBI regulatory claims
    rbi_match = re.search(r"([^.!?\n]*?\brbi\s+(?:approved|registered|certified|endorsed)[^.!?\n]*)", sanitized_text, re.IGNORECASE)
    if rbi_match:
        claim_text = rbi_match.group(1).strip()
        queries = []
        if entity:
            queries.append(f'"{entity}" RBI registered NBFC bank')
            queries.append(f'site:rbi.org.in "{entity}"')
        else:
            queries.append('site:rbi.org.in sachet unapproved schemes')

        claims.append(
            ExtractedClaim(
                claim_id="claim_rbi_reg",
                original_text=claim_text,
                claim_type="REGULATORY_REGISTRATION",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    # 3. Check for Guaranteed Return claims
    gr_match = re.search(
        r"([^.!?\n]*?\b(?:guaranteed|fixed|100%(?!\w)|sure|assured|pakka)\s+(?:\d+%(?!\w)\s+)?(?:returns?|profits?|income|fayda)[^.!?\n]*)",
        sanitized_text,
        re.IGNORECASE,
    )
    if not gr_match:
        # Check for paise double or loss bilkul nahi
        gr_match = re.search(
            r"([^.!?\n]*?\b(?:paise\s+double|loss\s+bilkul\s+nah[i|ee]n?)[^.!?\n]*)",
            sanitized_text,
            re.IGNORECASE,
        )

    if gr_match:
        claim_text = gr_match.group(1).strip()
        queries = [
            'site:sebi.gov.in "guaranteed returns" prohibited',
            'site:investor.sebi.gov.in "guaranteed return"',
        ]
        claims.append(
            ExtractedClaim(
                claim_id="claim_guaranteed_return",
                original_text=claim_text,
                claim_type="GUARANTEED_RETURN",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    # 4. Check for Government approved claims
    gov_match = re.search(r"([^.!?\n]*?\bgovernment\s+(?:approved|backed)\s+(?:investment|scheme|plan)[^.!?\n]*)", sanitized_text, re.IGNORECASE)
    if gov_match:
        claim_text = gov_match.group(1).strip()
        queries = []
        if entity:
            queries.append(f'site:gov.in "{entity}" approved')
        else:
            queries.append('site:pib.gov.in fact check investment scheme')

        claims.append(
            ExtractedClaim(
                claim_id="claim_gov_approval",
                original_text=claim_text,
                claim_type="GOVERNMENT_APPROVAL",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    # 5. Check for Withdrawal Fee / Tax claims
    wf_match = re.search(
        r"([^.!?\n]*?\b(?:withdrawal\s+requires?|pay\s+(?:tax|fee|charge|processing\s+fee)\s+to\s+withdraw|deposit\s+.*?to\s+(?:withdraw|unfreeze|release))[^.!?\n]*)",
        sanitized_text,
        re.IGNORECASE,
    )
    if wf_match:
        claim_text = wf_match.group(1).strip()
        queries = [
            'site:cybercrime.gov.in "withdrawal fee" scam',
            'site:sebi.gov.in "processing fee" withdrawal caution',
        ]
        claims.append(
            ExtractedClaim(
                claim_id="claim_withdrawal_fee",
                original_text=claim_text,
                claim_type="WITHDRAWAL_FEE",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    # 6. Check for Remote Access Support / Regulatory claims
    ra_match = re.search(
        r"([^.!?\n]*?\b(?:sebi|rbi|bank|support|official|team|broker|platform)\s+[^.!?\n]*?\b(?:anydesk|teamviewer|rustdesk|remote\s+access|remote\s+control|quicksupport)[^.!?\n]*)",
        sanitized_text,
        re.IGNORECASE,
    )
    if not ra_match:
        ra_match = re.search(
            r"([^.!?\n]*?\b(?:anydesk|teamviewer|rustdesk|remote\s+access)\s+[^.!?\n]*?\b(?:sebi|rbi|bank|verify|support|trading\s+account)[^.!?\n]*)",
            sanitized_text,
            re.IGNORECASE,
        )

    if ra_match:
        claim_text = ra_match.group(1).strip()
        queries = [
            'site:cybercrime.gov.in "remote access" "anydesk" advisory',
            'site:sebi.gov.in remote access support caution',
        ]
        claims.append(
            ExtractedClaim(
                claim_id="claim_remote_support",
                original_text=claim_text,
                claim_type="REMOTE_ACCESS_CLAIM",
                extracted_entity=entity,
                search_queries=queries,
                requires_external_search=True,
            )
        )

    return claims
