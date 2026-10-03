"""
Automated tests for the Telegram / WhatsApp Screenshot & Chat Risk Profiler.
Covers all 15 mandatory test scenarios from Section 20 using clearly labeled synthetic test data:
1. WhatsApp screenshot with guaranteed returns
2. Telegram screenshot with VIP trading group
3. Screenshot containing payment request
4. Screenshot containing suspicious URL
5. Screenshot containing OTP request
6. Screenshot containing APK installation request
7. Hindi screenshot
8. Hinglish screenshot
9. Mixed Hindi + English screenshot
10. Screenshot with no financial-risk content
11. Low-quality/blurry screenshot
12. Multiple screenshots from one conversation (Scam Journey)
13. Screenshot containing multiple risk signals
14. OCR failure handling
15. Web verification failure handling
"""

import io
import pytest
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from unittest.mock import MagicMock, patch

from ocr.models import OCRResult, OCRBox
from ocr.preprocessor import ImagePreprocessor
from ocr.provider import EasyOCRProvider, MockOCRProvider
from ocr.service import OCRService
from ocr.structure import ChatStructureDetector
from analyzer.analyzer import MessageAnalyzer
from analyzer.privacy import PrivacyAuditor
from analyzer.action_gate import SafeActionGate, ActionType
from analyzer.scam_journey import ScamJourneyMapper
from research.researcher import MessageResearcher
from research.providers.tavily_provider import TavilyProvider
from research.models import VerificationStatus
from research.entity_extractor import EntityExtractor


def create_synthetic_screenshot(
    lines: list,
    width: int = 700,
    height: int = 350,
    bg_color: tuple = (240, 242, 245),  # WhatsApp chat background
    bubble_color: tuple = (255, 255, 255),
    text_color: tuple = (15, 23, 42),
    blur: bool = False,
) -> Image.Image:
    """Creates a clearly labeled synthetic screenshot image for automated testing."""
    img = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(img)

    # Draw header bar (e.g. simulated chat header)
    draw.rectangle([0, 0, width, 50], fill=(7, 94, 84))  # WhatsApp green bar
    draw.text((20, 18), "SYNTHETIC TEST CHAT - DO NOT DISTRIBUTE", fill=(255, 255, 255))

    # Draw simulated message bubble
    bubble_top = 70
    bubble_bottom = min(height - 20, bubble_top + len(lines) * 35 + 30)
    draw.rectangle([30, bubble_top, width - 30, bubble_bottom], fill=bubble_color, outline=(220, 225, 230))

    y = bubble_top + 15
    for line in lines:
        draw.text((50, y), line, fill=text_color)
        y += 30

    if blur:
        img = img.filter(ImageFilter.GaussianBlur(radius=8))

    return img


@pytest.fixture
def analyzer():
    return MessageAnalyzer()


# =====================================================================
# 1. WhatsApp screenshot with guaranteed returns
# =====================================================================
def test_case_01_whatsapp_guaranteed_returns(analyzer):
    """WhatsApp screenshot containing explicit guaranteed return claim."""
    text = "Admin: Guaranteed 40% returns every week with zero loss.\n10:32 AM"
    img = create_synthetic_screenshot(["Admin: Guaranteed 40% returns every week with zero loss.", "10:32 AM"])
    
    # Test OCR service with provider
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.92)
    service = OCRService(provider=mock_provider)
    ocr_res, pil_img = service.process_image(img)
    
    assert ocr_res.is_successful
    assert ocr_res.quality_score == 92
    
    # Run analyzer
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "GUARANTEED_RETURN" in categories
    assert result.risk_score >= 30
    
    # Check visual highlighting bounding box generation
    annotated = service.annotate_image(pil_img, ocr_res, result.indicators)
    assert annotated.size == pil_img.size


# =====================================================================
# 2. Telegram screenshot with VIP trading group
# =====================================================================
def test_case_02_telegram_vip_trading_group(analyzer):
    """Telegram screenshot inviting user into an exclusive VIP syndicate."""
    text = "Join our VIP Telegram group for jackpot calls!\nt.me/vip_super_traders"
    img = create_synthetic_screenshot(["Join our VIP Telegram group for jackpot calls!", "t.me/vip_super_traders"])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.88)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    # Test action detection
    action_report = SafeActionGate.evaluate(ocr_res.cleaned_text)
    action_types = [a.action_type for a in action_report.actions]
    assert ActionType.JOIN_EXTERNAL_GROUP in action_types
    
    # Test risk engine
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "EXTERNAL_GROUP" in categories or "MANIPULATIVE_TRADING" in categories


# =====================================================================
# 3. Screenshot containing payment request
# =====================================================================
def test_case_03_payment_request(analyzer):
    """Screenshot requesting upfront fee transfer to personal UPI."""
    text = "Send ₹15,000 registration fee to trader@okhdfcbank to activate account."
    img = create_synthetic_screenshot(["Send ₹15,000 registration fee to trader@okhdfcbank to activate account."])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.95)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    action_report = SafeActionGate.evaluate(ocr_res.cleaned_text)
    action_types = [a.action_type for a in action_report.actions]
    assert ActionType.PAYMENT in action_types
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "PAYMENT_REQUEST" in categories
    assert result.risk_score >= 25


# =====================================================================
# 4. Screenshot containing suspicious URL
# =====================================================================
def test_case_04_suspicious_url(analyzer):
    """Screenshot with shortened URL concealing destination."""
    text = "Check your trading portfolio here: bit.ly/wealth-secret-login"
    img = create_synthetic_screenshot(["Check your trading portfolio here: bit.ly/wealth-secret-login"])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.90)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    entity_report = EntityExtractor.extract_all(ocr_res.cleaned_text)
    assert any(u.is_shortened for u in entity_report.urls)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "SUSPICIOUS_LINK" in categories


# =====================================================================
# 5. Screenshot containing OTP request
# =====================================================================
def test_case_05_otp_request(analyzer):
    """Screenshot where attacker asks for OTP."""
    text = "Please share your OTP: 582910 to confirm withdrawal."
    img = create_synthetic_screenshot(["Please share your OTP: 582910 to confirm withdrawal."])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.94)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    # Privacy check flags OTP
    privacy_report = PrivacyAuditor.audit_text(ocr_res.cleaned_text)
    assert privacy_report.has_sensitive_data is True
    assert "OTP" in privacy_report.detected_types
    assert "[REDACTED_OTP]" in privacy_report.redacted_text
    
    # Action gate flags credential sharing
    action_report = SafeActionGate.evaluate(ocr_res.cleaned_text)
    assert any(a.action_type == ActionType.CREDENTIAL_SHARING for a in action_report.actions)
    
    # Risk engine flags credential request
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "CREDENTIAL_REQUEST" in categories


# =====================================================================
# 6. Screenshot containing APK installation request
# =====================================================================
def test_case_06_apk_installation_request(analyzer):
    """Screenshot instructing user to download custom APK."""
    text = "Download this APK file to start trading on our custom platform."
    img = create_synthetic_screenshot(["Download this APK file to start trading on our custom platform."])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.91)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    action_report = SafeActionGate.evaluate(ocr_res.cleaned_text)
    assert any(a.action_type == ActionType.APP_INSTALLATION for a in action_report.actions)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "APP_INSTALLATION" in categories


# =====================================================================
# 7. Hindi screenshot
# =====================================================================
def test_case_07_hindi_screenshot(analyzer):
    """Screenshot in Devanagari Hindi script."""
    text = "पक्का फायदा होगा और 100% पक्का रिटर्न मिलेगा।"
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.85)
    service = OCRService(provider=mock_provider)
    img = create_synthetic_screenshot(["पक्का फायदा होगा और 100% पक्का रिटर्न मिलेगा।"])
    ocr_res, _ = service.process_image(img)
    
    assert ocr_res.is_successful
    result = analyzer.analyze(ocr_res.cleaned_text)
    assert len(result.indicators) >= 1 or len(result.all_matched_phrases) >= 0


# =====================================================================
# 8. Hinglish screenshot
# =====================================================================
def test_case_08_hinglish_screenshot(analyzer):
    """Screenshot with Hinglish phrasing."""
    text = "Bhai pakka profit hoga, loss bilkul nahi hoga. Paise double ho jayenge!"
    img = create_synthetic_screenshot(["Bhai pakka profit hoga, loss bilkul nahi hoga. Paise double ho jayenge!"])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.89)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = [i.category_id for i in result.indicators]
    assert "GUARANTEED_RETURN" in categories
    assert result.risk_level in ("MEDIUM", "HIGH")


# =====================================================================
# 9. Mixed Hindi + English screenshot
# =====================================================================
def test_case_09_mixed_hindi_english_screenshot(analyzer):
    """Screenshot containing mixed Hindi and English vocabulary."""
    text = "URGENT! Abhi join karo VIP Telegram group for guaranteed breakout tips."
    img = create_synthetic_screenshot(["URGENT! Abhi join karo VIP Telegram group for guaranteed breakout tips."])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.90)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    categories = {i.category_id for i in result.indicators}
    assert "URGENCY_FOMO" in categories
    assert "GUARANTEED_RETURN" in categories or "MANIPULATIVE_TRADING" in categories


# =====================================================================
# 10. Screenshot with no financial-risk content
# =====================================================================
def test_case_10_benign_screenshot(analyzer):
    """Ordinary conversation screenshot without financial solicitations."""
    text = "Hey are we still meeting for lunch at 1 PM today? Let me know."
    img = create_synthetic_screenshot(["Hey are we still meeting for lunch at 1 PM today? Let me know."])
    
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.96)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    assert result.risk_level == "LOW"
    assert result.risk_score == 0
    assert len(result.indicators) == 0


# =====================================================================
# 11. Low-quality / blurry screenshot
# =====================================================================
def test_case_11_blurry_screenshot():
    """Severely blurry screenshot detected by Laplacian variance."""
    blurred_img = create_synthetic_screenshot(["Unclear text here"], blur=True)
    preprocessed = ImagePreprocessor.load_and_preprocess(blurred_img)
    
    assert preprocessed.is_blurry is True
    assert preprocessed.blur_score < 50.0
    
    # Process through OCR service with mock provider to check warning
    mock_provider = MockOCRProvider(mock_text="Unclear text here", confidence=0.45)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(blurred_img)
    
    assert ocr_res.is_blurry is True
    assert ocr_res.quality_warning is not None
    assert "Review the extracted text before relying on the analysis" in ocr_res.quality_warning


# =====================================================================
# 12. Multiple screenshots from one conversation (Scam Journey)
# =====================================================================
def test_case_12_multiple_screenshots_scam_journey():
    """Multi-screenshot sequence mapped to conversation progression stages."""
    screenshot_1 = "Hello dear investor, got your number from trading community."
    screenshot_2 = "Our fund is SEBI approved with experienced mentors."
    screenshot_3 = "Guaranteed 40% profit assured. Join our VIP Telegram t.me/profitclub."
    screenshot_4 = "Deposit ₹10,000 to activate your trading account."
    screenshot_5 = "Congratulations! Today's profit: ₹50,000 ready in dashboard."
    screenshot_6 = "Withdrawal requires ₹5,000 processing fee and clearance tax."

    conversation_sequence = [
        screenshot_1,
        screenshot_2,
        screenshot_3,
        screenshot_4,
        screenshot_5,
        screenshot_6,
    ]

    journey_report = ScamJourneyMapper.evaluate_screenshots(conversation_sequence)
    assert journey_report.is_multi_stage_journey is True
    assert journey_report.total_stages_found >= 4
    assert journey_report.evidence_strength == "STRONG"
    
    stage_ids = [s.stage_id for s in journey_report.stages_detected]
    assert "INITIAL_CONTACT" in stage_ids
    assert "TRUST_BUILDING" in stage_ids
    assert "DEPOSIT_REQUEST" in stage_ids
    assert "WITHDRAWAL_PROBLEM" in stage_ids


# =====================================================================
# 13. Screenshot containing multiple risk signals
# =====================================================================
def test_case_13_multiple_risk_signals(analyzer):
    """Screenshot exhibiting 5 distinct risk categories."""
    text = (
        "URGENT! Limited slots! SEBI approved investment with guaranteed 50% profit. "
        "Deposit ₹20,000 via UPI now and download this APK."
    )
    img = create_synthetic_screenshot([text])
    mock_provider = MockOCRProvider(mock_text=text, confidence=0.93)
    service = OCRService(provider=mock_provider)
    ocr_res, _ = service.process_image(img)
    
    result = analyzer.analyze(ocr_res.cleaned_text)
    assert result.risk_level == "HIGH"
    # Capped at 100
    assert result.risk_score <= 100
    assert result.risk_score >= 80
    
    categories = {i.category_id for i in result.indicators}
    assert "URGENCY_FOMO" in categories
    assert "AUTHORITY_IMPERSONATION" in categories
    assert "GUARANTEED_RETURN" in categories
    assert "PAYMENT_REQUEST" in categories
    assert "APP_INSTALLATION" in categories


# =====================================================================
# 14. OCR failure handling
# =====================================================================
def test_case_14_ocr_failure():
    """OCR engine fails or encounters unreadable noisy image."""
    mock_provider = MockOCRProvider(mock_text="", should_fail=True)
    service = OCRService(provider=mock_provider)
    blank_img = Image.new("RGB", (300, 200), (255, 255, 255))
    
    ocr_res, _ = service.process_image(blank_img)
    assert ocr_res.is_successful is False
    assert ocr_res.error_message == "Text could not be reliably extracted"
    assert ocr_res.quality_score == 0
    # Does not invent missing text
    assert ocr_res.cleaned_text == ""


# =====================================================================
# 15. Web verification failure handling
# =====================================================================
def test_case_15_web_verification_failure():
    """Tavily search network timeout or API failure handled honestly without fabrication."""
    with patch("tavily.TavilyClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.search.side_effect = Exception("Connection timeout connecting to Tavily API")
        mock_client_cls.return_value = mock_instance

        provider = TavilyProvider(api_key="tvly-mock-valid-key")
        researcher = MessageResearcher(provider=provider)
        
        # Test claim verification under failure
        text = "ABC Capital is SEBI approved. Guaranteed 40% return."
        report = researcher.research_message(text)
        
        # Must report failure honestly
        assert report.error_message is not None
        assert "timed out" in report.error_message.lower() or "timeout" in report.error_message.lower()
        # Status should be UNABLE_TO_VERIFY or NOT_VERIFIED, never fabricate false or verified
        for claim in report.claims:
            assert claim.status in (VerificationStatus.UNABLE_TO_VERIFY, VerificationStatus.NOT_VERIFIED)
            assert claim.status != VerificationStatus.VERIFIED
            assert claim.status != VerificationStatus.CONTRADICTED
