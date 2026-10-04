"""
SachCheck - Investor Safety Platform
Presentation Layer Redesign (Streamlit, app.py)
===================================================
A polished, trustworthy fintech & cyber-safety presentation layer.
All analysis logic, scoring, research, OCR, action gate, function signatures,
session state keys, and tests are 100% preserved.
"""

import os
import time
import datetime
import io
from typing import List, Dict, Optional, Tuple, Any
from PIL import Image
import streamlit as st

from config import Config
from analyzer.analyzer import MessageAnalyzer
from analyzer.scoring import get_risk_indicator_label
from analyzer.action_gate import SafeActionGate, ActionType
from analyzer.privacy import PrivacyAuditor
from analyzer.scam_journey import ScamJourneyMapper
from analyzer.remote_access_apps import (
    RemoteAccessAnalyzer,
    RemoteAccessRiskLevel,
    RemoteAccessAnalysisResult,
)
from analyzer.apk_analyzer import SafeAPKInspector
from evaluate import run_evaluation
from research.researcher import MessageResearcher
from research.providers.tavily_provider import TavilyProvider
from research.models import VerificationStatus, SourceType
from research.entity_extractor import EntityExtractor
from ocr.service import OCRService, CATEGORY_COLOR_MAP
from ocr.structure import ChatStructureDetector
from utils.highlighting import highlight_risk_evidence
from data.sample_messages import SYNTHETIC_TEST_SAMPLES

# Central Design System & UI Theme
from utils.ui_theme import (
    inject_custom_theme,
    render_html_block,
    render_hero_banner,
    render_empty_state_card,
    render_trust_footer,
    render_score_ring_svg,
)

# Helper function to reliably render HTML without markdown code-block triggers
def render_html(html_content: str):
    render_html_block(html_content)

# =============================================================================
# PAGE CONFIGURATION
# =============================================================================
st.set_page_config(
    page_title="SachCheck | Verify Before You Trust",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

# Inject unified design system CSS (Inter font, WCAG AA contrast, light theme)
inject_custom_theme()

# =============================================================================
# RESOURCE INITIALIZATION & SESSION STATE
# =============================================================================
@st.cache_resource
def get_analyzer():
    return MessageAnalyzer()

@st.cache_resource
def get_ocr_service():
    return OCRService()

analyzer = get_analyzer()
ocr_service = get_ocr_service()

# Initialize session state stores (strictly preserving all keys)
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "stats" not in st.session_state:
    st.session_state.stats = {
        "analyzed": 0,
        "high_risk": 0,
        "suspicious": 0,
        "low_risk": 0,
    }
if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None
if "input_message" not in st.session_state:
    st.session_state.input_message = ""
if "ocr_extracted_text" not in st.session_state:
    st.session_state.ocr_extracted_text = ""
if "ocr_processed_key" not in st.session_state:
    st.session_state.ocr_processed_key = ""
if "ocr_rerun_requested" not in st.session_state:
    st.session_state.ocr_rerun_requested = False
if "sample_screenshot_bytes" not in st.session_state:
    st.session_state.sample_screenshot_bytes = None
if "sample_screenshot_name" not in st.session_state:
    st.session_state.sample_screenshot_name = None
if "ocr_edit_area" not in st.session_state:
    st.session_state.ocr_edit_area = ""
if "input_mode_selector" not in st.session_state:
    st.session_state.input_mode_selector = "Paste Message"
if "selected_input_mode" not in st.session_state:
    st.session_state.selected_input_mode = "Paste Message"
if "tavily_api_override" not in st.session_state:
    st.session_state.tavily_api_override = ""

# Active API Key resolution
configured_in_env = Config.is_tavily_configured()
effective_api_key = st.session_state.tavily_api_override.strip() if st.session_state.tavily_api_override.strip() else Config.TAVILY_API_KEY
is_live_ready = bool(effective_api_key and len(effective_api_key) > 5)

# =============================================================================
# COMPACT SIDEBAR
# =============================================================================
with st.sidebar:
    st.markdown("### 🛡️ SachCheck")
    st.caption("Investor Resilience & Verification Engine")

    # Status Pill
    if is_live_ready:
        render_html('<div style="margin-bottom: 1rem;"><span class="sc-trust-chip" style="background:#ECFDF5; color:#065F46; border-color:#A7F3D0; font-weight:600;">● Live Research Ready</span></div>')
    else:
        render_html('<div style="margin-bottom: 1rem;"><span class="sc-trust-chip" style="background:#F8FAFC; color:#64748B; border-color:#CBD5E1; font-weight:600;">○ Offline Evaluation Mode</span></div>')

    st.markdown("#### Session Metrics")
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        render_html(
            f"""
            <div class="sc-sidebar-tile">
                <div class="sc-sidebar-tile-num">{st.session_state.stats['analyzed']}</div>
                <div class="sc-sidebar-tile-label">Scans</div>
            </div>
            """
        )
    with col_sb2:
        render_html(
            f"""
            <div class="sc-sidebar-tile">
                <div class="sc-sidebar-tile-num" style="color: #DC2626;">{st.session_state.stats['high_risk']}</div>
                <div class="sc-sidebar-tile-label">High Risk</div>
            </div>
            """
        )

    render_html(
        f"""
        <div class="sc-sidebar-tile" style="margin-top: -2px;">
            <div class="sc-sidebar-tile-num" style="color: #16A34A;">{st.session_state.stats['low_risk']}</div>
            <div class="sc-sidebar-tile-label">Verified / Low Risk</div>
        </div>
        """
    )

    st.markdown("---")

    # Advanced Settings Expander (hiding API key cleanly)
    with st.expander("⚙️ Advanced Settings", expanded=False):
        st.caption("Configure optional search API credentials for live web verification.")
        override_val = st.text_input(
            "Tavily API Key:",
            type="password",
            value=st.session_state.tavily_api_override,
            placeholder="tvly-••••••••••••",
            help="Leave blank to use the environment key from .env",
        )
        if override_val != st.session_state.tavily_api_override:
            st.session_state.tavily_api_override = override_val
            st.rerun()

        if is_live_ready:
            st.caption(f"Active Key: `{effective_api_key[:4]}••••{effective_api_key[-4:]}`")

    st.caption("Built for SANGYAN Investor Resilience Hackathon. All data processed in-memory.")

# =============================================================================
# HERO SECTION
# =============================================================================
render_hero_banner(is_live=is_live_ready)

# =============================================================================
# MAIN NAVIGATION TABS (Analyze, Evidence, History, How it Works, Settings)
# =============================================================================
tab_analyze, tab_evidence, tab_history, tab_how, tab_settings = st.tabs([
    "🔍 Analyze",
    "📑 Evidence",
    "📜 History",
    "⚙️ How it Works",
    "🛠️ Settings",
])

# -----------------------------------------------------------------------------
# SAFE WIDGET STATE MUTATION CALLBACKS
# (Executed BEFORE widget instantiation during Streamlit rerun cycle)
# -----------------------------------------------------------------------------
def _cb_switch_mode(target_mode: str):
    st.session_state.input_mode_selector = target_mode

def _cb_set_sample_message(sample_text: str):
    st.session_state.input_message = sample_text
    st.session_state.user_text_area = sample_text

def _cb_clear_paste_message():
    st.session_state.input_message = ""
    st.session_state.user_text_area = ""
    st.session_state.current_analysis = None

def _cb_load_sample_screenshot(filename: str):
    sample_path = os.path.join("data/sample_screenshots", filename)
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            st.session_state.sample_screenshot_bytes = f.read()
            st.session_state.sample_screenshot_name = filename
            st.session_state.ocr_rerun_requested = True

def _cb_rerun_ocr():
    st.session_state.ocr_rerun_requested = True

def _cb_clear_screenshot():
    st.session_state.sample_screenshot_bytes = None
    st.session_state.sample_screenshot_name = None
    st.session_state.ocr_extracted_text = ""
    st.session_state.ocr_edit_area = ""
    st.session_state.ocr_processed_key = ""
    st.session_state.ocr_results = []
    st.session_state.pil_images = []
    st.session_state.current_analysis = None

# =============================================================================
# TAB 1: ANALYZE (MAIN USER JOURNEY)
# =============================================================================
with tab_analyze:
    # CENTRAL INPUT CARD
    with st.container(border=True):
        input_mode = st.radio(
            "Select Input Mode:",
            ["Paste Message", "Upload Screenshot", "Safe APK Inspector"],
            horizontal=True,
            key="input_mode_selector",
            label_visibility="collapsed",
        )

        text_to_analyze = ""
        current_ocr_results = []
        current_pil_images = []
        ocr_quality_score = 0
        analyze_clicked = False

        # ---------------------------------------------------------------------
        # MODE A: PASTE MESSAGE
        # ---------------------------------------------------------------------
        if input_mode == "Paste Message":
            st.markdown('<div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-bottom: 6px;">Paste Financial Message</div>', unsafe_allow_html=True)

            # Quick Test Sample Buttons in a horizontal row
            st.caption("Quick test examples:")
            SAMPLE_TEXT_1 = (
                "Invest in our VIP scheme with 100% profit and zero loss guaranteed. "
                "Double your money in 30 days! Send ₹10,000 to UPI profit@paytm."
            )
            SAMPLE_TEXT_2 = (
                "URGENT: Your trading account withdrawal is blocked. "
                "Install AnyDesk, send 9-digit code and provide your OTP to release funds immediately."
            )
            SAMPLE_TEXT_3 = (
                "Kotak Securities Limited is a SEBI registered stock broker with registration INZ000200137. "
                "Visit official site https://www.kotaksecurities.com for research reports."
            )

            col_s1, col_s2, col_s3 = st.columns(3)
            with col_s1:
                st.button("💡 100% Guaranteed Profit", on_click=_cb_set_sample_message, args=(SAMPLE_TEXT_1,), use_container_width=True)
            with col_s2:
                st.button("💡 AnyDesk Remote Support", on_click=_cb_set_sample_message, args=(SAMPLE_TEXT_2,), use_container_width=True)
            with col_s3:
                st.button("💡 SEBI Advisory Claim", on_click=_cb_set_sample_message, args=(SAMPLE_TEXT_3,), use_container_width=True)

            user_input = st.text_area(
                label="Suspicious Message Text Area",
                label_visibility="collapsed",
                value=st.session_state.get("user_text_area", st.session_state.input_message),
                height=140,
                placeholder="Paste a WhatsApp, Telegram, SMS, or social-media financial message here...\n\nExample: URGENT! SEBI approved opportunity. Guaranteed 40% return in 7 days. Send ₹10,000 to this UPI now.",
                key="user_text_area",
            )

            st.caption("🔒 In-memory analysis. Passwords, OTPs, PINs, and personal account numbers are never stored or logged.")

            col_btn, col_upload_switch, col_clear, _ = st.columns([2.5, 2.1, 1.1, 2.3])
            with col_btn:
                analyze_clicked = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
            with col_upload_switch:
                st.button("📸 Upload Screenshot", on_click=_cb_switch_mode, args=("Upload Screenshot",), use_container_width=True)
            with col_clear:
                st.button("🗑️ Clear", on_click=_cb_clear_paste_message, use_container_width=True)

            text_to_analyze = user_input.strip()

        # ---------------------------------------------------------------------
        # MODE B: UPLOAD SCREENSHOT
        # ---------------------------------------------------------------------
        elif input_mode == "Upload Screenshot":
            st.caption("🔒 Screenshots are processed locally in memory. Redact any personal credentials before uploading.")

            # Quick Test Sample Buttons for Screenshots
            st.caption("Quick test sample screenshots:")
            col_img_s1, col_img_s2 = st.columns(2)
            with col_img_s1:
                st.button(
                    "🖼️ Sample: Guaranteed Profit Chat",
                    on_click=_cb_load_sample_screenshot,
                    args=("sample_guaranteed_profit.png",),
                    use_container_width=True,
                )
            with col_img_s2:
                st.button(
                    "🖼️ Sample: AnyDesk Remote Access Alert",
                    on_click=_cb_load_sample_screenshot,
                    args=("sample_anydesk_fraud.png",),
                    use_container_width=True,
                )

            uploaded_files = st.file_uploader(
                "Upload WhatsApp, Telegram, or social media financial screenshot(s):",
                type=["png", "jpg", "jpeg", "webp"],
                accept_multiple_files=True,
                help="Supports single or multiple screenshots from the same conversation.",
                key="screenshot_file_uploader",
            )

            # Determine files to process (either from uploader or sample button)
            active_files_payload = []
            if uploaded_files:
                for uf in uploaded_files:
                    b = uf.read()
                    uf.seek(0)
                    active_files_payload.append((uf.name, len(b), b))
            elif st.session_state.get("sample_screenshot_bytes"):
                s_name = st.session_state.get("sample_screenshot_name", "sample_screenshot.png")
                s_bytes = st.session_state.get("sample_screenshot_bytes")
                active_files_payload.append((s_name, len(s_bytes), s_bytes))

            if active_files_payload:
                upload_signature = "_".join(f"{name}_{size}" for name, size, _ in active_files_payload)

                if st.session_state.ocr_processed_key != upload_signature or st.session_state.ocr_rerun_requested:
                    with st.spinner("Extracting text and layout with EasyOCR..."):
                        combined_texts = []
                        ocr_results_list = []
                        pil_images_list = []
                        confidences = []

                        for name, size, file_bytes in active_files_payload:
                            ocr_res, pil_img = ocr_service.process_image(file_bytes)
                            ocr_results_list.append(ocr_res)
                            pil_images_list.append(pil_img)
                            if ocr_res.is_successful and ocr_res.cleaned_text:
                                combined_texts.append(ocr_res.cleaned_text)
                                confidences.append(ocr_res.quality_score)

                        st.session_state.ocr_extracted_text = "\n\n".join(combined_texts)
                        st.session_state.ocr_processed_key = upload_signature
                        st.session_state.ocr_results = ocr_results_list
                        st.session_state.pil_images = pil_images_list
                        st.session_state.ocr_rerun_requested = False
                        st.session_state.ocr_quality_score = int(sum(confidences) / len(confidences)) if confidences else 0
                        # Synchronize text area state with fresh OCR extraction
                        st.session_state.ocr_edit_area = st.session_state.ocr_extracted_text

                current_ocr_results = st.session_state.get("ocr_results", [])
                current_pil_images = st.session_state.get("pil_images", [])
                ocr_quality_score = st.session_state.get("ocr_quality_score", 0)

                # Visual Image Preview
                if current_pil_images:
                    with st.expander(f"🖼️ Screenshot Preview ({len(current_pil_images)} image{'s' if len(current_pil_images) > 1 else ''})", expanded=True):
                        col_prev = st.columns(min(len(current_pil_images), 2))
                        for idx, p_img in enumerate(current_pil_images):
                            with col_prev[idx % len(col_prev)]:
                                st.image(p_img, caption=f"Screenshot {idx + 1}", use_container_width=True)

                col_q1, col_q2 = st.columns([1.5, 2.5])
                with col_q1:
                    render_html(
                        f"""
                        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 10px; padding: 12px 16px;">
                            <span style="font-size: 0.72rem; font-weight: 700; color: #64748B; text-transform: uppercase;">
                                OCR CLARITY METER
                            </span>
                            <div style="font-size: 1.6rem; font-weight: 800; color: {'#16A34A' if ocr_quality_score >= 60 else '#D97706'};">
                                {ocr_quality_score}%
                            </div>
                            <div style="font-size: 0.75rem; color: #64748B; margin-top: 2px;">
                                Optical clarity score (separated from scam risk score).
                            </div>
                        </div>
                        """
                    )
                with col_q2:
                    if ocr_quality_score < 60 and ocr_quality_score > 0:
                        st.warning("⚠️ Some text in this screenshot may be blurry. Review and correct extracted text below.")
                    elif ocr_quality_score == 0 and not st.session_state.ocr_extracted_text:
                        st.error("⚠️ Text could not be reliably extracted. You can type or paste the message text into the box below.")
                    else:
                        st.success("✅ Optical character recognition completed. Review or edit text below before analysis.")

                st.markdown("#### Review & Edit Extracted Text")
                edited_text = st.text_area(
                    label="Extracted Text (Editable):",
                    label_visibility="collapsed",
                    value=st.session_state.get("ocr_edit_area", st.session_state.ocr_extracted_text),
                    height=130,
                    key="ocr_edit_area",
                    placeholder="Extracted text from your screenshot will appear here. You can edit or add details before analyzing.",
                )

                col_run, col_rerun, col_clear, _ = st.columns([2.5, 1.8, 1.2, 2.5])
                with col_run:
                    analyze_clicked = st.button("🔍 Analyze Screenshot", type="primary", use_container_width=True)
                with col_rerun:
                    st.button("↻ Re-run OCR", on_click=_cb_rerun_ocr, use_container_width=True)
                with col_clear:
                    st.button("🗑️ Clear", key="clear_screenshot_btn", on_click=_cb_clear_screenshot, use_container_width=True)

                text_to_analyze = edited_text.strip()
            else:
                st.info("👆 Upload one or more conversation screenshots to begin OCR extraction, or click a quick sample above.")

        # ---------------------------------------------------------------------
        # MODE C: SAFE APK INSPECTOR
        # ---------------------------------------------------------------------
        else:
            render_html(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; padding: 12px 16px; margin-bottom: 12px; font-size: 0.875rem; color: #334155;">
                    <strong>Safe Static Inspection:</strong> Inspects archive structure and cryptographic hash without executing code.<br>
                    🔒 <strong>Zero Execution Guarantee:</strong> SachCheck NEVER installs or executes uploaded binaries.
                </div>
                """
            )

            uploaded_apk = st.file_uploader(
                "Upload an Android application package (.apk):",
                type=["apk", "zip"],
                help="Inspects package structure safely in memory without running it.",
                key="apk_inspector_uploader",
            )

            if uploaded_apk:
                apk_bytes = uploaded_apk.read()
                inspection = SafeAPKInspector.inspect(apk_bytes)

                col1, col2 = st.columns(2)
                with col1:
                    st.metric("File Size", f"{round(inspection.file_size_bytes / (1024 * 1024), 2)} MB")
                    st.metric("Valid Android Package", "✅ YES" if inspection.is_valid_apk else "❌ NO")
                    st.metric("DEX Executable Files", inspection.dex_count)
                with col2:
                    st.metric("Manifest Present", "✅ YES" if inspection.has_manifest else "❌ NO")
                    st.metric("Signing Cert Present", "✅ YES" if inspection.has_signing_cert else "❌ NO")
                    st.metric("Archive Entries", inspection.archive_entries_count)

                render_html(f"<div style='margin-top: 8px;'><strong>SHA-256 Hash:</strong> <code>{inspection.sha256_hash}</code></div>")
                if inspection.native_lib_architectures:
                    st.caption(f"Native Architectures: `{', '.join(inspection.native_lib_architectures)}`")

                st.warning(f"⚠️ **Security Notice:** {inspection.security_notice}")

    # =========================================================================
    # PIPELINE EXECUTION (Transparent Multi-Step Progress)
    # =========================================================================
    if analyze_clicked:
        if not text_to_analyze:
            st.warning("Please provide a message or screenshot text to analyze.")
        else:
            # 1. Privacy Audit
            privacy_report = PrivacyAuditor.audit_text(text_to_analyze)
            if privacy_report.has_sensitive_data:
                for w in privacy_report.warnings:
                    st.warning(w)

            # 2. Remote Access App Analyzer
            remote_access_result = RemoteAccessAnalyzer.analyze(
                text_to_analyze, source="SCREENSHOT" if input_mode == "Upload Screenshot" else "MESSAGE"
            )

            # 3. Phase 1: Deterministic Rule Analysis
            phase1_result = analyzer.analyze(text_to_analyze)

            # 4. Safe Action Gate
            action_report = SafeActionGate.evaluate(text_to_analyze)

            # 5. Entity Extraction
            entity_report = EntityExtractor.extract_all(text_to_analyze)

            # 6. Chat Structure Detection
            chat_structure = ChatStructureDetector.parse_chat_structure(text_to_analyze)

            # 7. Financial Advice Guardrail Check
            if phase1_result.is_advice_request:
                st.session_state.current_analysis = {
                    "is_advice": True,
                    "text": text_to_analyze,
                    "phase1": phase1_result,
                    "mode": input_mode,
                }
            else:
                # Progress state with clear loading feedback
                with st.status("Analyzing message and verifying claims...", expanded=True) as status_box:
                    st.write("✓ Extracted factual claims & entities")
                    st.write("✓ Detected predefined risk signals & action solicitations")
                    st.write("● Checking official sources via Tavily (SEBI, RBI, Gov)...")

                    provider = TavilyProvider(api_key=effective_api_key)
                    researcher = MessageResearcher(provider=provider)
                    research_report = researcher.research_message(text_to_analyze)

                    st.write("✓ Matched authentic evidence & evaluated claims")
                    status_box.update(label="Safety analysis complete", state="complete", expanded=False)

                # Multi-screenshot scam journey evaluation
                screenshot_texts_list = [r.cleaned_text for r in current_ocr_results if r.is_successful]
                sources_to_eval = (
                    screenshot_texts_list
                    if len(screenshot_texts_list) >= 2
                    else [m.raw_text for m in chat_structure.messages]
                )
                journey_profile = (
                    ScamJourneyMapper.evaluate_screenshots(sources_to_eval)
                    if len(sources_to_eval) >= 2
                    else None
                )

                # Store analysis bundle in session state
                st.session_state.current_analysis = {
                    "is_advice": False,
                    "text": text_to_analyze,
                    "mode": input_mode,
                    "phase1": phase1_result,
                    "remote_access": remote_access_result,
                    "action_report": action_report,
                    "entity_report": entity_report,
                    "chat_structure": chat_structure,
                    "research_report": research_report,
                    "journey_profile": journey_profile,
                    "pil_images": current_pil_images,
                    "ocr_results": current_ocr_results,
                    "ocr_quality_score": ocr_quality_score,
                }

                # Update Session Statistics
                st.session_state.stats["analyzed"] += 1
                if phase1_result.risk_level == "HIGH":
                    st.session_state.stats["high_risk"] += 1
                elif phase1_result.risk_level == "MEDIUM":
                    st.session_state.stats["suspicious"] += 1
                else:
                    st.session_state.stats["low_risk"] += 1

                # Append to Scan History
                st.session_state.scan_history.insert(
                    0,
                    {
                        "id": len(st.session_state.scan_history) + 1,
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "snippet": (text_to_analyze[:65] + "...") if len(text_to_analyze) > 65 else text_to_analyze,
                        "full_text": text_to_analyze,
                        "mode": input_mode,
                        "risk_level": phase1_result.risk_level,
                        "risk_score": phase1_result.risk_score,
                        "indicators_count": len(phase1_result.indicators),
                    },
                )

    # =========================================================================
    # RENDER ANALYSIS RESULT
    # =========================================================================
    current = st.session_state.current_analysis

    if current is None:
        # CLEAN EMPTY STATE
        render_empty_state_card()

    elif current.get("is_advice"):
        # Financial Advice Guardrail
        p1 = current["phase1"]
        st.error("### ⚠️ Financial Advice Guardrail Triggered")
        render_html(
            f"""
            <div style="background-color: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 12px; padding: 1.25rem; color: #991B1B;">
                <strong>Policy Notice:</strong> {p1.advice_refusal_message}
            </div>
            """
        )
        st.markdown("#### Safe Guidance")
        for step in p1.safe_next_steps:
            render_html(f'<div class="sc-safe-step-box">🛡️ {step}</div>')

    else:
        p1 = current["phase1"]
        ra = current["remote_access"]
        actions = current["action_report"]
        entities = current["entity_report"]
        research = current["research_report"]
        journey = current["journey_profile"]

        # ---------------------------------------------------------------------
        # RESULT HERO: SCORE RING GAUGE + RISK BADGE + DETECTED CHIPS
        # ---------------------------------------------------------------------
        risk_badge_class = (
            "sc-risk-high" if p1.risk_level == "HIGH"
            else "sc-risk-medium" if p1.risk_level == "MEDIUM"
            else "sc-risk-low"
        )
        risk_icon = "🛑" if p1.risk_level == "HIGH" else "⚠️" if p1.risk_level == "MEDIUM" else "✅"
        risk_label_text = (
            "HIGH RISK" if p1.risk_level == "HIGH"
            else "SUSPICIOUS" if p1.risk_level == "MEDIUM"
            else "LOW RISK"
        )

        detected_chips_html = []
        if p1.indicators:
            for ind in p1.indicators:
                chip_class = "sc-signal-high" if ind.score >= 25 else "sc-signal-medium"
                detected_chips_html.append(f'<span class="sc-chip {chip_class}">{ind.category} (+{ind.score})</span>')
        if ra.app_detected or ra.remote_access_actions:
            detected_chips_html.append('<span class="sc-chip sc-signal-high">🚨 Remote Access Detected</span>')
        if actions.has_actions:
            for a in actions.actions:
                detected_chips_html.append(f'<span class="sc-chip sc-signal-action">Action: {a.label_en}</span>')

        chips_markup = " ".join(detected_chips_html) if detected_chips_html else '<span style="color: #64748B; font-size: 0.875rem;">No high-risk manipulation patterns detected.</span>'

        gauge_svg = render_score_ring_svg(p1.risk_score, p1.risk_level)

        render_html(
            f"""
            <div class="sc-result-hero">
                <div class="sc-gauge-wrap">
                    {gauge_svg}
                </div>
                <div style="flex: 1; min-width: 260px;">
                    <div style="font-size: 0.75rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px;">
                        EVALUATION RESULT
                    </div>
                    <div style="margin-top: 4px; margin-bottom: 8px;">
                        <span class="sc-risk-badge {risk_badge_class}">{risk_icon} {risk_label_text}</span>
                    </div>
                    <div style="font-size: 0.875rem; color: #475569; margin-bottom: 8px;">
                        Deterministic score reflects the number and strength of predefined risk indicators.
                    </div>
                    <div style="margin-top: 6px;">
                        {chips_markup}
                    </div>
                </div>
            </div>
            """
        )

        # ---------------------------------------------------------------------
        # 4-STEP READING ORDER
        # ---------------------------------------------------------------------

        # STEP 1: WHY FLAGGED
        with st.container(border=True):
            render_html(
                """
                <div class="sc-step-header">
                    <span class="sc-step-num">1</span>
                    <span>Why This Was Flagged</span>
                </div>
                <p class="sc-caption" style="margin-bottom: 12px;">Matched phrases and patterns identified in the message.</p>
                """
            )

            # Prominently display annotated screenshot if a screenshot was analyzed
            if current.get("pil_images") and current.get("ocr_results"):
                st.markdown("##### 📸 Visual Evidence Detected on Screenshot")
                st.caption("Red flag bounding boxes mapped directly onto the uploaded conversation:")
                col_annotated = st.columns(min(len(current["pil_images"]), 2))
                for idx, (pil_img, ocr_res) in enumerate(zip(current["pil_images"], current["ocr_results"])):
                    with col_annotated[idx % len(col_annotated)]:
                        annotated_img = ocr_service.annotate_image(pil_img, ocr_res, p1.indicators)
                        st.image(annotated_img, caption=f"Screenshot {idx + 1} (Annotated Red Flags)", use_container_width=True)

            # Highlighted Message Box
            render_html(f'<div class="message-container">{p1.highlighted_html}</div>')

            # Indicators breakdown
            if p1.indicators:
                # Show first 2 directly, collapse rest in expander if many
                for ind in p1.indicators[:2]:
                    phrases_display = ", ".join(f'"{p}"' for p in ind.matched_phrases)
                    render_html(
                        f"""
                        <div class="sc-indicator-box">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <strong style="color: #0F172A; font-size: 0.9375rem;">🚩 {ind.category}</strong>
                                <span style="background: #EFF6FF; color: #1D4ED8; font-weight: 700; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem;">
                                    +{ind.score} pts
                                </span>
                            </div>
                            <div style="font-size: 0.875rem; color: #475569; margin-bottom: 4px;">
                                Matched: <code>{phrases_display}</code>
                            </div>
                            <div style="font-size: 0.875rem; color: #1E293B;">
                                <strong>Why it matters:</strong> {ind.why_it_matters_en}
                            </div>
                        </div>
                        """
                    )

                if len(p1.indicators) > 2:
                    with st.expander(f"View {len(p1.indicators) - 2} more detected indicator(s)", expanded=False):
                        for ind in p1.indicators[2:]:
                            phrases_display = ", ".join(f'"{p}"' for p in ind.matched_phrases)
                            render_html(
                                f"""
                                <div class="sc-indicator-box">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                        <strong style="color: #0F172A; font-size: 0.9375rem;">🚩 {ind.category}</strong>
                                        <span style="background: #EFF6FF; color: #1D4ED8; font-weight: 700; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem;">
                                            +{ind.score} pts
                                        </span>
                                    </div>
                                    <div style="font-size: 0.875rem; color: #475569; margin-bottom: 4px;">
                                        Matched: <code>{phrases_display}</code>
                                    </div>
                                    <div style="font-size: 0.875rem; color: #1E293B;">
                                        <strong>Why it matters:</strong> {ind.why_it_matters_en}
                                    </div>
                                </div>
                                """
                            )

            # Plain-Language Explanation Tabs
            tab_en, tab_hi = st.tabs(["🇬🇧 English Explanation", "🇮🇳 Hindi / Hinglish Explanation"])
            with tab_en:
                st.info(p1.explanation_en)
            with tab_hi:
                st.info(p1.explanation_hi)

        # STEP 2: CLAIM VERIFICATION (TAVILY LIVE RESEARCH)
        with st.container(border=True):
            col_c_hdr, col_c_mode = st.columns([3, 1.4])
            with col_c_hdr:
                render_html(
                    """
                    <div class="sc-step-header">
                        <span class="sc-step-num">2</span>
                        <span>Claim Verification</span>
                    </div>
                    <p class="sc-caption" style="margin-bottom: 12px;">Factual claims checked against official regulatory registries.</p>
                    """
                )
            with col_c_mode:
                st.markdown("<div style='text-align: right;'>", unsafe_allow_html=True)
                if research.is_live:
                    render_html('<span class="sc-trust-chip" style="background:#ECFDF5; color:#065F46; border-color:#A7F3D0; font-weight:600;">● Live Web Verified</span>')
                else:
                    render_html('<span class="sc-trust-chip" style="background:#F8FAFC; color:#64748B; border-color:#CBD5E1; font-weight:600;">○ Offline Mode</span>')
                st.markdown("</div>", unsafe_allow_html=True)

            if not research.claims:
                st.info("ℹ️ No specific regulatory or verifiable factual claims were detected in this message.")
            else:
                for claim_res in research.claims:
                    status_class = f"sc-status-{claim_res.status}"
                    source_link_html = ""
                    if claim_res.source_url:
                        source_link_html = f'<div style="margin-top: 8px; font-size: 0.8125rem; color: #475569;">Source: <strong>{claim_res.source_title}</strong> (<code>{claim_res.source_domain}</code>) &bull; <a href="{claim_res.source_url}" target="_blank" style="color: #2563EB; font-weight: 600; text-decoration: none;">View Official Registry ↗</a></div>'

                    render_html(
                        f"""
                        <div class="sc-claim-card">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                <div>
                                    <span style="font-size: 0.6875rem; color: #64748B; font-weight: 700; text-transform: uppercase;">
                                        CLAIM DETECTED
                                    </span>
                                    <div style="font-size: 1rem; font-weight: 700; color: #0F172A; margin-top: 2px;">
                                        "{claim_res.original_claim}"
                                    </div>
                                </div>
                                <span class="sc-claim-status-badge {status_class}">
                                    {claim_res.status.replace('_', ' ')}
                                </span>
                            </div>
                            <div class="sc-claim-grid">
                                <div>
                                    <div class="sc-claim-col-title">What the source establishes</div>
                                    <div class="sc-claim-col-establishes">
                                        {claim_res.what_source_establishes}
                                    </div>
                                </div>
                                <div>
                                    <div class="sc-claim-col-title">What it does NOT establish</div>
                                    <div class="sc-claim-col-limitations">
                                        {claim_res.what_source_does_not_establish}
                                    </div>
                                </div>
                            </div>
                            {source_link_html}
                        </div>
                        """
                    )

                    if claim_res.relevant_text:
                        with st.expander("📄 View Retrieved Source Evidence", expanded=False):
                            st.code(claim_res.relevant_text, language="text")

        # STEP 3: SAFE ACTION GATE
        with st.container(border=True):
            render_html(
                """
                <div class="sc-step-header">
                    <span class="sc-step-num">3</span>
                    <span>Safe Action Gate</span>
                </div>
                <p class="sc-caption" style="margin-bottom: 12px;">Sensitive actions requested by this message and defensive controls.</p>
                """
            )

            if actions.has_actions or ra.remote_access_actions:
                actions_items_html = []
                for a in actions.actions:
                    actions_items_html.append(
                        f'<div style="margin-top: 6px; font-size: 0.875rem; color: #991B1B;"><strong>🛑 {a.label_en}</strong>: <code>{a.matched_phrase}</code><div style="font-size: 0.8125rem; color: #475569; margin-top: 2px;">{a.why_dangerous_en}</div></div>'
                    )
                if ra.remote_access_actions:
                    for ra_act in ra.remote_access_actions:
                        actions_items_html.append(
                            f'<div style="margin-top: 6px; font-size: 0.875rem; color: #991B1B;"><strong>🚨 Remote Access Request:</strong> {ra_act.action_type.replace("_", " ")}<div style="font-size: 0.8125rem; color: #475569; margin-top: 2px;">Matched: <code>{ra_act.matched_text}</code></div></div>'
                        )

                render_html(
                    f"""
                    <div class="sc-action-alert">
                        <strong style="color: #9F1239; font-size: 0.95rem;">
                            Action Solicitations Detected:
                        </strong>
                        {''.join(actions_items_html)}
                    </div>
                    """
                )

                st.markdown("#### Recommended Defensive Action:")
                st.info("👉 **Pause and verify independently.** Never transfer money, share OTPs, or grant remote device control based solely on digital messages.")

                for g in actions.guidance:
                    render_html(f'<div class="sc-safe-step-box">🛑 {g}</div>')

                # Remote Access Incident Response
                if ra.app_detected or ra.remote_access_actions:
                    st.markdown("---")
                    st.markdown("#### 🚨 Did you already grant remote access or install software?")
                    already_granted = st.radio(
                        "Have you already installed the software or shared the connection code?",
                        ["No", "Yes", "I'm not sure"],
                        horizontal=True,
                        key="already_granted_choice",
                    )

                    if already_granted in ("Yes", "I'm not sure"):
                        containment_steps_html = "".join(f"<div style='margin-top: 4px; font-size: 0.85rem;'>👉 {step}</div>" for step in ra.what_to_do_already_granted)
                        render_html(
                            f"""
                            <div style="background-color: #FEF2F2; border: 1px solid #FCA5A5; border-left: 4px solid #DC2626; border-radius: 8px; padding: 1rem 1.15rem; margin-top: 0.75rem; color: #991B1B;">
                                <h4 style="margin: 0 0 6px 0; color: #991B1B;">🚨 IMMEDIATE INCIDENT RESPONSE</h4>
                                <strong>Take these containment steps immediately:</strong><br>
                                {containment_steps_html}
                            </div>
                            """
                        )
            else:
                st.success("✅ No direct payment, credential transfer, or remote access actions were explicitly solicited.")

        # STEP 4: NEXT STEPS
        with st.container(border=True):
            render_html(
                """
                <div class="sc-step-header">
                    <span class="sc-step-num">4</span>
                    <span>Safe Next Steps</span>
                </div>
                <p class="sc-caption" style="margin-bottom: 12px;">Actionable investor protection directives.</p>
                """
            )

            for step in p1.safe_next_steps:
                render_html(f'<div class="sc-safe-step-box">👉 {step}</div>')

            # Copy Safe Reply
            st.markdown("<div style='margin-top: 12px; margin-bottom: 4px;'><strong>Standard Verification Reply to Sender:</strong></div>", unsafe_allow_html=True)
            st.caption("You can copy and send this standard regulatory verification query to the sender:")
            safe_reply_text = (
                "Please provide your registered SEBI Intermediary Registration Number and the official listing link on sebi.gov.in before we discuss any financial services."
            )
            st.code(safe_reply_text, language="text")

        # DEEP-DIVE EVIDENCE EXPANDERS (Keep first screen scannable)
        with st.expander("🔍 Deep-Dive Evidence & Technical Details", expanded=False):
            # Visual Screenshot Highlighting (if screenshot was analyzed)
            if current.get("pil_images") and current.get("ocr_results"):
                st.markdown("#### 📸 Screenshot Evidence Highlighting")
                st.caption("Visual bounding boxes identify high-risk phrases directly on uploaded screenshots:")

                col_imgs = st.columns(min(len(current["pil_images"]), 2))
                for idx, (pil_img, ocr_res) in enumerate(zip(current["pil_images"], current["ocr_results"])):
                    with col_imgs[idx % len(col_imgs)]:
                        annotated_img = ocr_service.annotate_image(pil_img, ocr_res, p1.indicators)
                        st.image(annotated_img, caption=f"Screenshot {idx + 1} (Annotated Evidence)", use_container_width=True)

            # Multi-stage Scam Journey (if detected)
            if journey and journey.is_multi_stage_journey:
                render_html(
                    f"""
                    <div style="background-color: #FEF3C7; border: 1px solid #F59E0B; border-radius: 8px; padding: 10px 14px; margin-bottom: 10px; color: #92400E; font-size: 0.9rem;">
                        <strong>⚠️ Multi-Stage Progression Detected ({journey.evidence_strength} Evidence):</strong><br>
                        {journey.progression_summary}
                    </div>
                    """
                )
                for stg in journey.stages_detected:
                    render_html(
                        f"""
                        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 3px solid #6366F1; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px;">
                            <div style="font-size: 0.875rem; font-weight: 700; color: #1E293B;">
                                {stg.stage_badge} {stg.stage_title}
                            </div>
                            <div style="font-size: 0.8125rem; color: #64748B; margin-top: 2px;">
                                Snippet: <code>"{stg.evidence_snippet}"</code>
                            </div>
                        </div>
                        """
                    )

            # URL Inspection
            if research.extracted_urls or entities.urls:
                urls_to_inspect = research.extracted_urls or entities.urls
                st.markdown("#### 🔗 Extracted URL Inspection")
                for u in urls_to_inspect:
                    render_html(
                        f"""
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 12px; margin-bottom: 6px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 0.875rem; font-weight: 600; color: #0F172A;"><code>{u.original_url}</code></span>
                                <span style="font-size: 0.75rem; font-weight: 700; color: #475569;">
                                    {'🔒 HTTPS' if u.is_https else '⚠️ HTTP (Insecure)'} |
                                    {'⚡ Shortener' if u.is_shortened else '🌐 Direct Domain'}
                                </span>
                            </div>
                            <div style="font-size: 0.8125rem; color: #64748B; margin-top: 4px;">{u.note}</div>
                        </div>
                        """
                    )

            # Full Sources List
            if research.sources:
                st.markdown("#### 📚 Full Consulted Sources")
                for idx, src in enumerate(research.sources, 1):
                    col_src_info, col_src_btn = st.columns([3.5, 1])
                    with col_src_info:
                        st.markdown(f"**{idx}. {src.title}** (`{src.domain}` &bull; `{src.source_type}`)")
                        st.caption(f'"{src.content[:140]}..."')
                    with col_src_btn:
                        st.link_button("Open Source ↗", src.url, use_container_width=True)

            # Traceable Execution Steps
            st.markdown("#### 🛠️ Traceable Execution Steps")
            for idx, step in enumerate(research.steps_performed, 1):
                st.markdown(f"**{idx}.** {step}")

    # Mandatory Trust Footer
    render_trust_footer()

# =============================================================================
# TAB 2: EVIDENCE (DEEP INSPECTION)
# =============================================================================
with tab_evidence:
    st.markdown("### 📑 Evidence & Verification Details")
    st.caption("Deep-dive inspection of claims, retrieved regulatory excerpts, and domain classifications.")

    current = st.session_state.current_analysis
    if current is None or current.get("is_advice"):
        st.info("No active analysis to display. Run an analysis in the Analyze tab to review extracted evidence here.")
    else:
        research = current["research_report"]
        p1 = current["phase1"]

        st.markdown(f"#### Active Message Analyzed ({current['mode']})")
        st.text(current["text"])

        st.markdown("---")
        st.markdown("#### Retrieved Source Evidence Snippets")
        if not research.claims:
            st.caption("No verifiable claims extracted.")
        else:
            for c in research.claims:
                st.markdown(f"**Claim:** *\"{c.original_claim}\"*")
                st.markdown(f"**Status:** `{c.status}` | **Source:** `{c.source_title}` ({c.source_domain})")
                st.markdown(f"- **Establishes:** {c.what_source_establishes}")
                st.markdown(f"- **Does NOT Establish:** {c.what_source_does_not_establish}")
                if c.relevant_text:
                    st.code(c.relevant_text, language="text")
                st.markdown("---")

# =============================================================================
# TAB 3: HISTORY (SESSION AUDIT LOG)
# =============================================================================
with tab_history:
    st.markdown("### 📜 Session Scan History")
    st.caption("Audit trail of messages and screenshots analyzed during this active session.")

    if not st.session_state.scan_history:
        st.info("No scans recorded in this session yet. Run an analysis in the Analyze tab to view past evaluations here.")
    else:
        col_h_stats1, col_h_stats2, col_h_stats3 = st.columns([1, 1, 2])
        with col_h_stats1:
            st.metric("Total Session Scans", len(st.session_state.scan_history))
        with col_h_stats2:
            high_count = sum(1 for s in st.session_state.scan_history if s["risk_level"] == "HIGH")
            st.metric("High Risk Scans", high_count)
        with col_h_stats3:
            st.markdown("<div style='text-align: right; padding-top: 15px;'>", unsafe_allow_html=True)
            if st.button("🗑️ Clear Scan History"):
                st.session_state.scan_history = []
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")

        for scan in st.session_state.scan_history:
            badge_color = "#DC2626" if scan["risk_level"] == "HIGH" else "#D97706" if scan["risk_level"] == "MEDIUM" else "#16A34A"
            render_html(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 14px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 0.8rem; color: #64748B;">🕒 {scan['time']} &bull; Mode: {scan['mode']}</span>
                        <span style="font-size: 0.75rem; font-weight: 800; background: {badge_color}; color: white; padding: 2px 8px; border-radius: 4px;">
                            {scan['risk_level']} ({scan['risk_score']}/100)
                        </span>
                    </div>
                    <div style="font-size: 0.9rem; color: #1E293B; margin-top: 4px;">
                        "{scan['snippet']}"
                    </div>
                </div>
                """
            )

# =============================================================================
# TAB 4: HOW IT WORKS & ARCHITECTURE
# =============================================================================
with tab_how:
    st.markdown("### ⚙️ Architecture & Two-Phase Engine")
    st.markdown(
        """
        SachCheck enforces a strictly **deterministic** classification pipeline paired with authentic OCR, remote-access analysis, and web research:
        
        ```
        SCREENSHOT (PNG / JPG / WEBP) OR PASTED MESSAGE
            ↓
        IMAGE PREPROCESSING & OCR PIPELINE (EasyOCR: English & Hindi)
            ├── Blur Assessment & Quality Scoring (Separated from Risk)
            └── Bounding Box Extraction
            ↓
        EXTRACTED TEXT REVIEW (Editable by User before Analysis)
            ↓
        REMOTE ACCESS & APP ANALYZER (AnyDesk, TeamViewer, RustDesk, APKs)
            ├── Capability Detection vs Message Context
            ├── Remote Actions (Install, Session Code, Remote Control)
            ├── Financial Context & Special Stop Conditions
            └── Action Risk Score (0–100) & "What to Do Now" Guidance
            ↓
        SAFE ACTION GATE & PRIVACY AUDIT
            ├── Sensitive Credential Detection (OTP, PIN, Card, Aadhaar, PAN)
            ├── Action Detection (Payments, APK Downloads, Credentials, Remote Access)
            └── Safe Query Redaction
            ↓
        PHASE 1: DETERMINISTIC RISK ENGINE (Source of Truth for Score)
            ├── Predefined Rules (+30, +25, +20, +15, +10)
            ├── Negative Context & Educational Filtering
            ├── Category Deduplication & Capping at 100
            └── Explainable Breakdown: "Why this risk score?"
            ↓
        VISUAL EVIDENCE HIGHLIGHTING
            ├── Annotated Screenshot with Color-Coded Bounding Boxes
            └── Safe HTML Text Highlighting
            ↓
        MULTI-SCREENSHOT CONVERSATION JOURNEY MAPPER
            ├── 8 Structured Progression Stages (Hook → Credibility → Deposit → Withdrawal)
            └── Strictly Evidence-Based Stage Progression
            ↓
        PHASE 2: TAVILY REAL WEB RESEARCH (Research & Retrieval Layer)
            ├── Factual Claim & Entity Extraction
            ├── Targeted Query Generation (site:sebi.gov.in, etc.)
            ├── Domain Classification & Lookalike Rejection
            ├── Official Regulator & Government Prioritization
            └── Evidence Evaluation (VERIFIED, CONTRADICTED, NOT_VERIFIED)
            ↓
        TRACEABLE EVIDENCE REPORT, INCIDENT RESPONSE & SAFE NEXT STEPS
        ```
        
        #### Core Ethical Principles:
        1. **Source of Truth Separation**: Tavily search results NEVER change the Phase 1 risk score.
        2. **App Itself vs Context**: AnyDesk or TeamViewer are legitimate software tools, NEVER labeled malware without authoritative evidence.
        3. **OCR Quality vs Risk Separation**: OCR confidence is reported separately and NEVER blended into scam risk.
        4. **Honest Uncertainty**: Empty search results return `NOT_VERIFIED`, NEVER `FALSE` or `SCAM`.
        5. **Registration ≠ Endorsement**: Finding an entity in the SEBI directory verifies registration status, but NEVER implies government endorsement or guaranteed safety.
        6. **Zero Fabrication**: If research or OCR is unavailable, SachCheck displays honest status rather than synthetic victim stories.
        7. **Zero Execution**: APK files are inspected for static archive structure only; binaries are NEVER executed or installed.
        """
    )

# =============================================================================
# TAB 5: SETTINGS & BENCHMARK
# =============================================================================
with tab_settings:
    st.markdown("### 🛠️ Settings & System Benchmark")
    st.caption("System configuration, session analytics, and automated test suite evaluation.")

    with st.container(border=True):
        st.markdown("#### 📊 Internal Synthetic Test-Set Benchmark")
        st.caption("Deterministically calculated across 28 labeled synthetic test cases.")

        eval_data = run_evaluation()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Test Cases", eval_data["total_test_cases"])
        with col2:
            st.metric("Correctly Classified", eval_data["correctly_classified"])
        with col3:
            st.metric("Accuracy Rate", f"{eval_data['accuracy_pct']}%")
        with col4:
            st.metric("False Positives", eval_data["false_positive_count"])

        with st.expander("🔍 View Benchmark Case Breakdown", expanded=False):
            table_rows = []
            for c in eval_data["case_details"]:
                status = "✅ PASS" if c["is_correct"] else "❌ FAIL"
                table_rows.append({
                    "Case ID": c["id"],
                    "Category": c["category_focus"],
                    "Language": c["language"],
                    "Expected": c["expected_risk_level"],
                    "Actual": c["actual_risk_level"],
                    "Score": c["actual_score"],
                    "Status": status,
                })
            st.dataframe(table_rows, use_container_width=True)
