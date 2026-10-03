"""
Deterministic scoring logic and risk level calculation for SachCheck.
Evaluates detected categories without double-counting scores.
"""

from typing import List, Tuple
from analyzer.models import DetectedIndicator

# Score thresholds defined strictly by specification
LOW_RISK_MAX = 19
MEDIUM_RISK_MAX = 44
# 0 - 19: LOW
# 20 - 44: MEDIUM
# 45+: HIGH

RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_HIGH = "HIGH"


def calculate_risk_level(total_score: int) -> str:
    """
    Map deterministic total score to Risk Level.
    0 - 19  -> LOW
    20 - 44 -> MEDIUM
    45+     -> HIGH
    """
    if total_score <= LOW_RISK_MAX:
        return RISK_LEVEL_LOW
    elif total_score <= MEDIUM_RISK_MAX:
        return RISK_LEVEL_MEDIUM
    else:
        return RISK_LEVEL_HIGH


def compute_deterministic_score(indicators: List[DetectedIndicator]) -> Tuple[int, str]:
    """
    Calculates total score from detected indicators and determines risk level.
    Note: Indicators are already deduplicated by category before reaching here.
    The final score is normalized and capped at 100 per specification.
    """
    raw_score = sum(indicator.score for indicator in indicators)
    capped_score = min(100, raw_score)
    risk_level = calculate_risk_level(capped_score)
    return capped_score, risk_level


def get_risk_indicator_label(risk_level: str) -> str:
    """Return standard risk indicator label."""
    if risk_level == RISK_LEVEL_HIGH:
        return "High risk indicators detected"
    elif risk_level == RISK_LEVEL_MEDIUM:
        return "Medium risk indicators detected"
    else:
        return "Low risk indicators detected"



def get_risk_level_color(risk_level: str) -> str:
    """Return styling color for risk level."""
    mapping = {
        RISK_LEVEL_LOW: "#10B981",     # Emerald Green
        RISK_LEVEL_MEDIUM: "#F59E0B",  # Amber
        RISK_LEVEL_HIGH: "#EF4444",    # Crimson Red
    }
    return mapping.get(risk_level, "#6B7280")
