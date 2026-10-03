"""
Chat and message structure detection for screenshot OCR output.
Parses sender labels, timestamps, message boundaries, and embedded structural tokens
(links, phone numbers, Telegram handles, WhatsApp numbers, UPI IDs, amounts, percentages).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
import re


@dataclass
class ChatMessage:
    """Represents a single message unit parsed from chat screenshot text."""
    message_index: int
    sender: str  # e.g., "Admin", "Unknown", or "+91 98765 43210"
    timestamp: str  # e.g., "10:32 AM", "14:20", ""
    raw_text: str
    cleaned_text: str
    detected_signals: List[str] = field(default_factory=list)
    detected_actions: List[str] = field(default_factory=list)
    extracted_entities: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ChatStructureReport:
    """Full structural breakdown of the screenshot text."""
    messages: List[ChatMessage] = field(default_factory=list)
    total_messages: int = 0
    all_senders: List[str] = field(default_factory=list)
    all_timestamps: List[str] = field(default_factory=list)
    all_links: List[str] = field(default_factory=list)
    all_phone_numbers: List[str] = field(default_factory=list)
    all_telegram_handles: List[str] = field(default_factory=list)
    all_whatsapp_numbers: List[str] = field(default_factory=list)
    all_upi_ids: List[str] = field(default_factory=list)
    all_amounts: List[str] = field(default_factory=list)
    all_percentages: List[str] = field(default_factory=list)


class ChatStructureDetector:
    """Detects chat bubbles, senders, timestamps, and entities in OCR text."""

    # Regex for timestamps in chat UI: 10:32 AM, 10:32, 23:59, 10:32pm, etc.
    TIMESTAMP_PATTERN = re.compile(
        r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s*(?:AM|PM|am|pm))?\b"
    )

    # Regex for common sender patterns in WhatsApp/Telegram:
    # "Admin:", "John:", "+91 9876543210:", "[Admin]"
    SENDER_LINE_PATTERN = re.compile(
        r"^(?:\[?([A-Za-z0-9_\s+]{2,25})\]?\s*:\s*)(.*)$"
    )

    # Entity patterns
    PHONE_PATTERN = re.compile(
        r"(?:\+91[-\s]?)?[6-9]\d{9}\b"
    )
    TELEGRAM_HANDLE_PATTERN = re.compile(
        r"(?:@([a-zA-Z0-9_]{4,32})|t\.me\/([a-zA-Z0-9_+]{4,32}))"
    )
    WHATSAPP_LINK_PATTERN = re.compile(
        r"(?:chat\.whatsapp\.com\/[a-zA-Z0-9_-]{10,30}|wa\.me\/\d{10,13})"
    )
    UPI_PATTERN = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,40}@[a-zA-Z]{2,20}\b"
    )
    AMOUNT_PATTERN = re.compile(
        r"(?:(?:₹|rs\.?|inr|\$)\s*[\d,]+(?:\.\d{2})?|\b[\d,]+\s*(?:lakh|crore|k)\b)",
        re.IGNORECASE,
    )
    PERCENT_PATTERN = re.compile(
        r"\b\d+(?:\.\d+)?%\b|\b\d+x\b",
        re.IGNORECASE,
    )
    URL_PATTERN = re.compile(
        r"(?:https?:\/\/|www\.)[^\s<>\"]+|(?:bit\.ly|tinyurl\.com|t\.co|t\.me)\/[a-zA-Z0-9_\-\.\/]+",
        re.IGNORECASE,
    )

    @classmethod
    def parse_chat_structure(cls, text: str) -> ChatStructureReport:
        """
        Parses OCR text into structured chat messages and extracts all entity tokens.
        """
        if not text or not text.strip():
            return ChatStructureReport()

        lines = [line.strip() for line in text.split("\n") if line.strip()]
        messages: List[ChatMessage] = []

        current_sender = "Unknown"
        current_time = ""
        current_lines: List[str] = []
        msg_idx = 1

        for line in lines:
            # Check for timestamp in line
            ts_match = cls.TIMESTAMP_PATTERN.search(line)
            found_ts = ts_match.group(0) if ts_match else ""

            # Check for sender label pattern: "SenderName: message"
            sender_match = cls.SENDER_LINE_PATTERN.match(line)

            # Heuristic for message boundary: new sender, explicit timestamp, or delimiter
            if sender_match:
                if current_lines:
                    msg_text = "\n".join(current_lines).strip()
                    if msg_text:
                        messages.append(cls._create_message(msg_idx, current_sender, current_time, msg_text))
                        msg_idx += 1
                        current_lines = []

                current_sender = sender_match.group(1).strip()
                rest_of_line = sender_match.group(2).strip()
                current_time = found_ts
                if rest_of_line:
                    current_lines.append(rest_of_line)
            elif found_ts and len(line) < 30 and ("am" in line.lower() or "pm" in line.lower() or ":" in line):
                # Line is predominantly a standalone timestamp or status line
                if current_lines:
                    current_time = found_ts
                    msg_text = "\n".join(current_lines).strip()
                    if msg_text:
                        messages.append(cls._create_message(msg_idx, current_sender, current_time, msg_text))
                        msg_idx += 1
                        current_lines = []
                        current_time = ""
            else:
                current_lines.append(line)
                if found_ts and not current_time:
                    current_time = found_ts

        # Flush remaining message
        if current_lines:
            msg_text = "\n".join(current_lines).strip()
            if msg_text:
                messages.append(cls._create_message(msg_idx, current_sender, current_time, msg_text))

        # Fallback if no boundary was split
        if not messages:
            messages.append(cls._create_message(1, "Unknown", "", text.strip()))

        # Extract all entities across the entire text
        all_links = cls.URL_PATTERN.findall(text)
        all_phones = cls.PHONE_PATTERN.findall(text)
        tg_matches = cls.TELEGRAM_HANDLE_PATTERN.findall(text)
        all_tg = [m[0] or m[1] for m in tg_matches if (m[0] or m[1])]
        all_wa = cls.WHATSAPP_LINK_PATTERN.findall(text)
        all_upi = [u for u in cls.UPI_PATTERN.findall(text) if not u.endswith("@example.com")]
        all_amounts = cls.AMOUNT_PATTERN.findall(text)
        all_percents = cls.PERCENT_PATTERN.findall(text)
        all_senders = list({m.sender for m in messages if m.sender != "Unknown"})
        all_timestamps = [m.timestamp for m in messages if m.timestamp]

        return ChatStructureReport(
            messages=messages,
            total_messages=len(messages),
            all_senders=all_senders,
            all_timestamps=all_timestamps,
            all_links=list(dict.fromkeys(all_links)),
            all_phone_numbers=list(dict.fromkeys(all_phones)),
            all_telegram_handles=list(dict.fromkeys(all_tg)),
            all_whatsapp_numbers=list(dict.fromkeys(all_wa)),
            all_upi_ids=list(dict.fromkeys(all_upi)),
            all_amounts=list(dict.fromkeys(all_amounts)),
            all_percentages=list(dict.fromkeys(all_percents)),
        )

    @classmethod
    def _create_message(
        cls, index: int, sender: str, timestamp: str, text: str
    ) -> ChatMessage:
        """Helper to create a ChatMessage and detect structural signals within it."""
        signals = []
        actions = []
        entities = {}

        # Quick structural signal detection on message slice
        text_lower = text.lower()

        # Returns
        if any(w in text_lower for w in ["guaranteed", "assured", "100%", "double", "pakka profit"]):
            signals.append("guaranteed return claim")
        if any(w in text_lower for w in ["profit", "returns", "gains"]):
            signals.append("investment claim")
        if "%" in text or "x" in text:
            signals.append("percentage return")

        # Exclusivity / Group
        if any(w in text_lower for w in ["vip", "telegram", "channel", "exclusive"]):
            signals.append("external group invitation")
            signals.append("exclusivity language")
            actions.append("JOIN_EXTERNAL_GROUP")

        # Payments
        if any(w in text_lower for w in ["deposit", "pay", "send", "transfer", "upi", "fee", "₹"]):
            signals.append("payment / deposit request")
            actions.append("PAYMENT")

        # Urgency
        if any(w in text_lower for w in ["hurry", "urgent", "only today", "act now", "limited"]):
            signals.append("urgency / fomo tactic")

        # App download
        if any(w in text_lower for w in ["apk", "install", "download app"]):
            signals.append("app download request")
            actions.append("APP_INSTALLATION")

        # OTP / Credentials
        if any(w in text_lower for w in ["otp", "pin", "password"]):
            signals.append("credential request")
            actions.append("CREDENTIAL_SHARING")

        # Entities in this message
        amounts = cls.AMOUNT_PATTERN.findall(text)
        if amounts:
            entities["amounts"] = amounts
        percents = cls.PERCENT_PATTERN.findall(text)
        if percents:
            entities["percentages"] = percents
        links = cls.URL_PATTERN.findall(text)
        if links:
            entities["links"] = links

        return ChatMessage(
            message_index=index,
            sender=sender,
            timestamp=timestamp,
            raw_text=text,
            cleaned_text=text,
            detected_signals=signals,
            detected_actions=actions,
            extracted_entities=entities,
        )
