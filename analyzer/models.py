"""
Data models for the SachCheck financial message analyzer.
All structures are strongly typed dataclasses for deterministic tracking.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class MatchSpan:
    """Represents a character span where an indicator was matched in the input text."""
    start: int
    end: int
    matched_text: str
    category_id: str
    category_name: str
    rule_id: str


@dataclass
class DetectedIndicator:
    """Structured evidence for a detected risk category."""
    rule_id: str
    category_id: str
    category: str
    score: int
    severity: str  # 'low', 'medium', 'high'
    matched_phrases: List[str]
    matched_spans: List[Tuple[int, int]]
    why_it_matters_en: str
    why_it_matters_hi: str


@dataclass
class AnalysisResult:
    """Complete result returned by the deterministic rule engine."""
    original_text: str
    is_advice_request: bool
    advice_refusal_message: Optional[str]
    risk_level: str  # "LOW", "MEDIUM", "HIGH"
    risk_score: int
    indicators: List[DetectedIndicator] = field(default_factory=list)
    all_matched_phrases: List[str] = field(default_factory=list)
    highlighted_html: str = ""
    explanation_en: str = ""
    explanation_hi: str = ""
    safe_next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a clean dictionary."""
        return asdict(self)
