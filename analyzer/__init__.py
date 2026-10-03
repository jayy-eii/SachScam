"""
SachCheck Analyzer Package
Deterministic rule engine for financial message scam and manipulation analysis.
Includes Remote Access / App Analyzer and Safe Action Gate.
"""

from analyzer.analyzer import MessageAnalyzer
from analyzer.models import AnalysisResult, DetectedIndicator, MatchSpan
from analyzer.scoring import calculate_risk_level, compute_deterministic_score
from analyzer.rules import ALL_RULES, ADVICE_REFUSAL_MESSAGE
from analyzer.remote_access_apps import (
    RemoteAccessAnalyzer,
    RemoteAccessRiskLevel,
    RemoteAccessAction,
    AppReference,
    RemoteAccessAnalysisResult,
    REMOTE_ACCESS_APPS_CATALOG,
)
from analyzer.action_gate import SafeActionGate, ActionType, DetectedAction
from analyzer.privacy import PrivacyAuditor
from analyzer.scam_journey import ScamJourneyMapper
from analyzer.apk_analyzer import SafeAPKInspector, APKInspectionResult

__all__ = [
    "MessageAnalyzer",
    "AnalysisResult",
    "DetectedIndicator",
    "MatchSpan",
    "calculate_risk_level",
    "compute_deterministic_score",
    "ALL_RULES",
    "ADVICE_REFUSAL_MESSAGE",
    "RemoteAccessAnalyzer",
    "RemoteAccessRiskLevel",
    "RemoteAccessAction",
    "AppReference",
    "RemoteAccessAnalysisResult",
    "REMOTE_ACCESS_APPS_CATALOG",
    "SafeActionGate",
    "ActionType",
    "DetectedAction",
    "PrivacyAuditor",
    "ScamJourneyMapper",
    "SafeAPKInspector",
    "APKInspectionResult",
]
