"""
Comprehensive unit and integration tests for the Malicious / Remote-Access App Alert feature in SachCheck.
Tests cover:
- Mandatory test scenarios 1-10 (Section 27)
- Distinguishing app capability vs context abuse (AnyDesk / TeamViewer are not classified as malware)
- Context combinations (credentials, payments, financial account fix, urgency)
- Special Stop Conditions (STOP_AND_VERIFY)
- Safe Action Gate remote-access action detections
- Safe APK static inspector (safe read-only ZIP/hash analysis, zero execution)
- Multilingual support (English, Hindi, Hinglish)
"""

import io
import zipfile
import pytest

from analyzer.remote_access_apps import (
    RemoteAccessAnalyzer,
    RemoteAccessRiskLevel,
    REMOTE_ACCESS_APPS_CATALOG,
)
from analyzer.action_gate import SafeActionGate, ActionType
from analyzer.apk_analyzer import SafeAPKInspector, APKInspectionResult
from analyzer.analyzer import MessageAnalyzer


# ==============================================================================
# MANDATORY TESTS FROM SPECIFICATION (SECTION 27)
# ==============================================================================

def test_scenario_1_install_anydesk_and_send_code():
    """
    TEST 1:
    "Install AnyDesk and send me the code."
    Expected:
    - detects AnyDesk
    - detects install action
    - detects session-code request
    - warns of remote access capability
    - does not classify AnyDesk itself as malware
    """
    text = "Install AnyDesk and send me the code."
    result = RemoteAccessAnalyzer.analyze(text)

    # 1. Detects AnyDesk
    assert result.app_detected is True
    assert any(a.name == "AnyDesk" for a in result.apps)
    # Ensure AnyDesk is not labeled as malware
    assert all("malware" not in a.evidence.lower() for a in result.apps)

    # 2. Detects install action
    action_types = [act.action_type for act in result.remote_access_actions]
    assert "INSTALL_REMOTE_APP" in action_types

    # 3. Detects session-code request
    assert "SHARE_SESSION_CODE" in action_types

    # 4. Warns of remote access capability
    assert len(result.why_risky_en) > 0
    assert any("remote" in s.lower() for s in result.why_risky_en)

    # Safe Action Gate detection
    gate_report = SafeActionGate.evaluate(text)
    gate_types = [a.action_type for a in gate_report.actions]
    assert ActionType.INSTALL_REMOTE_APP in gate_types
    assert ActionType.SHARE_REMOTE_SESSION_CODE in gate_types


def test_scenario_2_install_anydesk_trading_account_fix():
    """
    TEST 2:
    "Install AnyDesk and I'll fix your trading account."
    Expected:
    - detects AnyDesk
    - detects financial context
    - detects account-fix claim
    - assigns HIGH_CAUTION or STOP_AND_VERIFY
    """
    text = "Install AnyDesk and I'll fix your trading account."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "AnyDesk" for a in result.apps)
    assert result.financial_context is True
    assert result.account_fix_claim is True
    assert result.risk_level in (RemoteAccessRiskLevel.HIGH_CAUTION, RemoteAccessRiskLevel.STOP_AND_VERIFY)
    assert result.risk_score >= 50


def test_scenario_3_install_anydesk_and_send_otp_pin():
    """
    TEST 3:
    "Install AnyDesk and send OTP/PIN."
    Expected:
    - detects AnyDesk
    - detects OTP/PIN request
    - triggers STOP_AND_VERIFY
    """
    text = "Install AnyDesk and send OTP/PIN."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "AnyDesk" for a in result.apps)
    assert result.credential_request is True
    assert result.stop_condition is True
    assert result.risk_level == RemoteAccessRiskLevel.STOP_AND_VERIFY
    assert "STOP AND VERIFY" in result.stop_reason
    assert result.risk_score >= 85


def test_scenario_4_download_apk_unlock_withdrawal():
    """
    TEST 4:
    "Download this APK to unlock your withdrawal."
    Expected:
    - detects APK request
    - detects financial / withdrawal context
    - warns about unknown app installation
    - assigns HIGH_CAUTION or higher
    """
    text = "Download this APK to unlock your withdrawal."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.apk_request is True
    assert result.financial_context is True
    assert result.account_fix_claim is True
    assert result.risk_level in (RemoteAccessRiskLevel.HIGH_CAUTION, RemoteAccessRiskLevel.STOP_AND_VERIFY)
    assert result.risk_score >= 50
    assert any("apk" in e.lower() for e in result.evidence)


def test_scenario_5_pay_5000_install_teamviewer_refund():
    """
    TEST 5:
    "Pay ₹5,000 and install TeamViewer so I can process your refund."
    Expected:
    - detects payment request
    - detects remote-access app (TeamViewer)
    - detects refund context
    - triggers STOP_AND_VERIFY
    """
    text = "Pay ₹5,000 and install TeamViewer so I can process your refund."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "TeamViewer" for a in result.apps)
    assert result.payment_request is True
    assert result.financial_context is True
    assert result.stop_condition is True
    assert result.risk_level == RemoteAccessRiskLevel.STOP_AND_VERIFY
    assert result.risk_score >= 85


def test_scenario_6_office_uses_teamviewer_internal_it():
    """
    TEST 6:
    "Our office uses TeamViewer for internal IT support."
    Expected:
    - detects TeamViewer
    - does NOT accuse TeamViewer of being a scam
    - distinguishes legitimate IT usage
    - assigns INFORMATIONAL or LOW_CAUTION
    """
    text = "Our office uses TeamViewer for internal IT support."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "TeamViewer" for a in result.apps)
    # Does NOT accuse TeamViewer of being a scam or malware
    for app in result.apps:
        assert "scam" not in app.evidence.lower()
        assert "malware" not in app.evidence.lower()
        assert "legitimate" in app.app_category.lower() or "remote" in app.app_category.lower()

    # Distinguishes legitimate IT context
    assert result.financial_context is False
    assert result.credential_request is False
    assert result.payment_request is False
    assert result.stop_condition is False
    assert result.risk_level in (RemoteAccessRiskLevel.INFORMATIONAL, RemoteAccessRiskLevel.LOW_CAUTION)
    assert result.risk_score <= 15


def test_scenario_7_use_anydesk_to_fix_printer():
    """
    TEST 7:
    "Use AnyDesk to help me fix my printer."
    Expected:
    - detects AnyDesk
    - does NOT accuse sender of financial fraud
    - distinguishes non-financial usage
    - assigns LOW_CAUTION or INFORMATIONAL
    """
    text = "Use AnyDesk to help me fix my printer."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "AnyDesk" for a in result.apps)
    assert result.financial_context is False
    assert result.credential_request is False
    assert result.payment_request is False
    assert result.stop_condition is False
    assert result.risk_level in (RemoteAccessRiskLevel.INFORMATIONAL, RemoteAccessRiskLevel.LOW_CAUTION)
    assert result.risk_score <= 15


def test_scenario_8_hindi_anydesk_install_id_bhejo():
    """
    TEST 8:
    Hindi:
    "AnyDesk install karo aur ID bhejo."
    Expected:
    - detects AnyDesk
    - detects session-code/ID request
    - Hindi/Hinglish detection works
    """
    text = "AnyDesk install karo aur ID bhejo."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "AnyDesk" for a in result.apps)
    action_types = [act.action_type for act in result.remote_access_actions]
    assert "SHARE_SESSION_CODE" in action_types or "INSTALL_REMOTE_APP" in action_types
    # Check that Hindi/Hinglish explanation is generated
    assert len(result.why_risky_hi) > 0
    assert any("remote" in h.lower() or "id" in h.lower() or "screen" in h.lower() for h in result.why_risky_hi)


def test_scenario_9_hinglish_trading_account_unlock_teamviewer():
    """
    TEST 9:
    Hinglish:
    "Sir trading account unlock karne ke liye TeamViewer install karke access de do."
    Expected:
    - detects TeamViewer
    - detects financial context
    - detects account access request
    - assigns HIGH_CAUTION or STOP_AND_VERIFY
    """
    text = "Sir trading account unlock karne ke liye TeamViewer install karke access de do."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert any(a.name == "TeamViewer" for a in result.apps)
    assert result.financial_context is True
    action_types = [act.action_type for act in result.remote_access_actions]
    assert "GRANT_REMOTE_CONTROL" in action_types or "INSTALL_REMOTE_APP" in action_types
    assert result.risk_level in (RemoteAccessRiskLevel.HIGH_CAUTION, RemoteAccessRiskLevel.STOP_AND_VERIFY)
    assert result.risk_score >= 50


def test_scenario_10_safe_apk_inspector_and_blurry_ocr():
    """
    TEST 10:
    Low OCR confidence / blurry screenshot & Safe APK Inspector validation:
    - Test SafeAPKInspector with simulated APK ZIP (manifest, dex, resources)
    - Test SafeAPKInspector with invalid/corrupt input
    - Test that RemoteAccessAnalyzer handles partial/noisy text without crashing or inventing apps
    """
    # 1. Safe APK Inspector with mock valid APK zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.fakeapp'/>")
        zf.writestr("classes.dex", b"DEX_BYTECODE_SIMULATION")
        zf.writestr("resources.arsc", b"RESOURCES_TABLE")
        zf.writestr("lib/arm64-v8a/libnative.so", b"ELF_SIMULATION")
        zf.writestr("META-INF/CERT.RSA", b"CERTIFICATE")

    apk_bytes = zip_buffer.getvalue()
    inspection = SafeAPKInspector.inspect(apk_bytes)

    assert inspection.is_valid_apk is True
    assert inspection.has_manifest is True
    assert inspection.has_dex_code is True
    assert inspection.has_resources is True
    assert inspection.has_signing_cert is True
    assert "arm64-v8a" in inspection.native_lib_architectures
    assert len(inspection.sha256_hash) == 64
    assert "does not establish malware safety" in inspection.security_notice.lower()

    # 2. Safe APK Inspector with corrupt/empty bytes
    corrupt_res = SafeAPKInspector.inspect(b"NOT_A_ZIP_HEADER")
    assert corrupt_res.is_valid_apk is False
    assert "not a valid" in corrupt_res.error_message.lower()

    empty_res = SafeAPKInspector.inspect(b"")
    assert empty_res.is_valid_apk is False
    assert "empty" in empty_res.error_message.lower()

    # 3. RemoteAccessAnalyzer handles noisy/unrecognized text without inventing apps
    noisy_text = "Img blurred text 39824 jsdfk sdkfj 12:30"
    noisy_result = RemoteAccessAnalyzer.analyze(noisy_text, source="OCR")
    assert noisy_result.app_detected is False
    assert len(noisy_result.apps) == 0
    assert noisy_result.risk_level == RemoteAccessRiskLevel.INFORMATIONAL


# ==============================================================================
# ADDITIONAL UNIT TESTS FOR COMPREHENSIVE COVERAGE
# ==============================================================================

def test_catalog_integrity():
    """Verify that catalog apps have required metadata and non-malware descriptions."""
    assert len(REMOTE_ACCESS_APPS_CATALOG) >= 5
    for app in REMOTE_ACCESS_APPS_CATALOG:
        assert "name" in app
        assert "patterns" in app
        assert "official_url" in app
        assert "description" in app
        # Descriptions must refer to software as legitimate/standard, not malware
        assert "legitimate" in app["description"].lower()


def test_special_stop_condition_urgency_financial_remote():
    """
    Test Stop Condition 4: Remote access + urgency/threat + financial context -> STOP_AND_VERIFY
    """
    text = "URGENT: Your bank account will be blocked within 10 minutes. Install AnyDesk immediately."
    result = RemoteAccessAnalyzer.analyze(text)

    assert result.app_detected is True
    assert result.financial_context is True
    assert result.urgency_detected is True
    assert result.stop_condition is True
    assert result.risk_level == RemoteAccessRiskLevel.STOP_AND_VERIFY


def test_safe_action_gate_remote_control_and_screen_sharing():
    """Verify SafeActionGate identifies GRANT_REMOTE_CONTROL and ENABLE_SCREEN_ACCESS."""
    text1 = "Please accept my incoming request and give me remote access to your device."
    report1 = SafeActionGate.evaluate(text1)
    actions1 = [a.action_type for a in report1.actions]
    assert ActionType.GRANT_REMOTE_CONTROL in actions1

    text2 = "Please share your screen so our executive can assist you."
    report2 = SafeActionGate.evaluate(text2)
    actions2 = [a.action_type for a in report2.actions]
    assert ActionType.ENABLE_SCREEN_ACCESS in actions2


def test_incident_response_directives_present():
    """Ensure structured step-by-step incident response directives are included in result."""
    text = "Install AnyDesk and send your session code to verify your demat account."
    result = RemoteAccessAnalyzer.analyze(text)

    assert len(result.what_to_do_unauthorized) >= 4
    assert len(result.what_to_do_already_granted) >= 5
    assert any("1930" in step or "cybercrime" in step for step in result.what_to_do_already_granted)
    assert any("end the remote session" in step.lower() for step in result.what_to_do_already_granted)
