"""
SachCheck - Investor Safety Platform
Refined Frontend & UI/UX for Hackathon Presentation
===================================================
A clean, modern, trustworthy cyber-safety dashboard.
All core engines, risk scoring, Tavily research, claim verification,
Safe Action Gate, OCR, APK inspector, and evaluation logic are 100% preserved.
"""

import time
import datetime
import io
import textwrap
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

# Helper function to reliably render HTML without markdown code-block triggers
def render_html(html_content: str):
    st.markdown(textwrap.dedent(html_content).strip(), unsafe_allow_html=True)

# =============================================================================
# PAGE CONFIGURATION
# =============================================================================
st.set_page_config(
    page_title="SachCheck | Verify Before You Trust",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# REFINED PROFESSIONAL STYLING (Fintech / Cyber-Safety Aesthetic)
# =============================================================================
render_html(
    """
    <style>
    /* Global Base Typography & Spacing */
    html, body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif;
        color: #0F172A;
    }
    
    /* Top Header & Navbar */
    .top-navbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.25rem 0 1rem 0;
        border-bottom: 1px solid #E2E8F0;
        margin-bottom: 1rem;
    }
    .nav-brand {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .brand-title {
        font-size: 1.75rem;
        font-weight: 800;
        color: #0F172A;
        letter-spacing: -0.5px;
        margin: 0;
        line-height: 1;
    }
    .brand-tagline {
        font-size: 0.95rem;
        font-weight: 600;
        color: #475569;
        margin: 0;
        border-left: 2px solid #CBD5E1;
        padding-left: 12px;
    }
    .hackathon-pill {
        background-color: #F8FAFC;
        color: #475569;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 9999px;
        border: 1px solid #E2E8F0;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }

    /* Hero Section */
    .hero-container {
        margin-bottom: 1rem;
    }
    .hero-title {
        font-size: 1.55rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0 0 0.2rem 0;
        letter-spacing: -0.3px;
    }
    .hero-subtitle {
        font-size: 0.95rem;
        color: #475569;
        margin: 0;
        line-height: 1.4;
    }

    /* Container border styling */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 10px !important;
        border-color: #E2E8F0 !important;
        background-color: #FFFFFF !important;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03) !important;
        margin-bottom: 1.15rem !important;
    }

    .helper-text {
        font-size: 0.82rem;
        color: #64748B;
        margin-top: 0.35rem;
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* Restrained Risk Cards */
    .risk-result-card {
        border-radius: 10px;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.25rem;
        border: 1px solid;
    }
    .risk-high {
        background-color: #FEF2F2;
        border-color: #FECACA;
        color: #991B1B;
    }
    .risk-medium {
        background-color: #FFFBEB;
        border-color: #FDE68A;
        color: #92400E;
    }
    .risk-low {
        background-color: #F0FDF4;
        border-color: #BBF7D0;
        color: #166534;
    }
    .risk-badge {
        font-size: 0.85rem;
        font-weight: 800;
        padding: 4px 10px;
        border-radius: 6px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        display: inline-block;
    }
    .risk-badge-high {
        background-color: #DC2626;
        color: #FFFFFF;
    }
    .risk-badge-medium {
        background-color: #D97706;
        color: #FFFFFF;
    }
    .risk-badge-low {
        background-color: #16A34A;
        color: #FFFFFF;
    }

    /* Detected signals pill list */
    .detected-pill {
        display: inline-block;
        background: rgba(255, 255, 255, 0.85);
        border: 1px solid rgba(0, 0, 0, 0.08);
        padding: 3px 10px;
        border-radius: 6px;
        margin-right: 6px;
        margin-top: 5px;
        font-size: 0.82rem;
        font-weight: 600;
        color: #1E293B;
    }

    /* Section Typography */
    .section-header {
        font-size: 1.15rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0 0 0.15rem 0;
        letter-spacing: -0.2px;
    }
    .section-caption {
        font-size: 0.85rem;
        color: #64748B;
        margin: 0 0 0.75rem 0;
    }

    /* Evidence highlight in text */
    .message-container {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 0.95rem 1.15rem;
        font-size: 0.95rem;
        line-height: 1.65;
        color: #0F172A;
        margin-bottom: 0.85rem;
    }
    mark.risk-highlight {
        background-color: #FEF08A;
        color: #854D0E;
        font-weight: 600;
        padding: 2px 6px;
        border-radius: 4px;
        border-bottom: 2px solid #CA8A04;
    }

    /* Indicator Breakdown Items */
    .indicator-box {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #3B82F6;
        border-radius: 8px;
        padding: 0.85rem 1.1rem;
        margin-bottom: 0.65rem;
    }

    /* Claim Cards */
    .claim-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.85rem;
    }
    .status-badge {
        font-size: 0.75rem;
        font-weight: 800;
        padding: 3px 8px;
        border-radius: 6px;
        text-transform: uppercase;
        display: inline-block;
    }
    .status-VERIFIED {
        background-color: #DEF7EC;
        color: #03543F;
        border: 1px solid #84E1BC;
    }
    .status-CONTRADICTED {
        background-color: #FDE8E8;
        color: #9B1C1C;
        border: 1px solid #F8B4B4;
    }
    .status-NOT_VERIFIED {
        background-color: #F3F4F6;
        color: #374151;
        border: 1px solid #D1D5DB;
    }
    .status-UNABLE_TO_VERIFY {
        background-color: #FEF08A;
        color: #713F12;
        border: 1px solid #FACC15;
    }

    /* Action Gate / Stop Before You Act */
    .action-gate-alert {
        background-color: #FFF1F2;
        border: 1px solid #FECDD3;
        border-left: 4px solid #E11D48;
        border-radius: 8px;
        padding: 0.95rem 1.15rem;
        margin-bottom: 0.85rem;
    }
    .action-badge {
        display: inline-block;
        background-color: #E11D48;
        color: white;
        font-weight: 700;
        padding: 2px 7px;
        border-radius: 5px;
        font-size: 0.75rem;
        margin-right: 6px;
    }

    /* Safe directives */
    .safe-step-box {
        background-color: #F0FDF4;
        border: 1px solid #DCFCE7;
        border-left: 3px solid #16A34A;
        border-radius: 6px;
        padding: 0.65rem 0.95rem;
        margin-bottom: 0.45rem;
        color: #166534;
        font-size: 0.88rem;
    }

    /* Incident Response Box */
    .incident-response-box {
        background-color: #FEF2F2;
        border: 1px solid #FCA5A5;
        border-left: 4px solid #DC2626;
        border-radius: 8px;
        padding: 0.95rem 1.15rem;
        margin-top: 0.75rem;
        margin-bottom: 0.75rem;
        color: #991B1B;
    }

    /* Source Box */
    .source-box {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 0.85rem 1.15rem;
        margin-bottom: 0.65rem;
    }

    /* Empty state card */
    .empty-state-box {
        background-color: #F8FAFC;
        border: 1px dashed #CBD5E1;
        border-radius: 12px;
        padding: 2.25rem 1.5rem;
        text-align: center;
        margin-bottom: 1.25rem;
    }

    /* Trust disclaimer footer */
    .trust-footer {
        text-align: center;
        font-size: 0.82rem;
        color: #64748B;
        border-top: 1px solid #E2E8F0;
        padding-top: 1.25rem;
        margin-top: 2rem;
        margin-bottom: 1.5rem;
        line-height: 1.5;
    }
    
    /* Live/Offline status badge */
    .badge-live {
        background-color: #ECFDF5;
        color: #065F46;
        font-size: 0.8rem;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 9999px;
        border: 1px solid #A7F3D0;
        display: inline-block;
    }
    .badge-offline {
        background-color: #F1F5F9;
        color: #475569;
        font-size: 0.8rem;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 9999px;
        border: 1px solid #CBD5E1;
        display: inline-block;
    }
    </style>
    """
)

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

# Initialize session state stores
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
if "selected_input_mode" not in st.session_state:
    st.session_state.selected_input_mode = "✍️ Paste Message"

# =============================================================================
# SIDEBAR: SETTINGS, LIVE STATUS & REAL DASHBOARD STATS
# =============================================================================
with st.sidebar:
    st.markdown("### 🛡️ SachCheck Settings")
    st.caption("Investor Safety Platform — SANGYAN Hackathon")
    st.markdown("---")

    # Live Research Configuration
    st.markdown("#### 🌐 Live Research Status")
    configured_in_env = Config.is_tavily_configured()

    user_api_key = st.text_input(
        "Tavily API Key (Optional Override):",
        type="password",
        value=Config.TAVILY_API_KEY if configured_in_env else "",
        help="Reads from .env by default. Enter your Tavily key to enable live web research.",
    )
    active_api_key = user_api_key.strip() if user_api_key.strip() else Config.TAVILY_API_KEY

    if active_api_key and len(active_api_key) > 5:
        render_html('<span class="badge-live">🟢 LIVE RESEARCH READY</span>')
        st.caption(f"Active Key: `{active_api_key[:4]}••••{active_api_key[-4:]}`")
    else:
        render_html('<span class="badge-offline">⚪ OFFLINE EVALUATION MODE</span>')

    st.markdown("---")

    # Session Stats (Only real data, no fake stats)
    st.markdown("#### 📊 Session Statistics")
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Analyzed", st.session_state.stats["analyzed"])
        st.metric("High Risk", st.session_state.stats["high_risk"])
    with c2:
        st.metric("Suspicious", st.session_state.stats["suspicious"])
        st.metric("Low Risk", st.session_state.stats["low_risk"])

    st.markdown("---")
    st.markdown("#### 🔒 Privacy & Safety Guarantee")
    st.caption(
        "• In-memory screenshot processing.\n"
        "• Redacts sensitive credentials (OTPs, PINs) before web queries.\n"
        "• Zero execution of uploaded APK files.\n"
        "• No personal data stored externally."
    )
    st.markdown("---")
    st.markdown("#### ⚖️ Regulatory Notice")
    st.caption(
        "SachCheck provides risk indicators, not investment advice. "
        "Verify all financial entities on the official SEBI directory at **sebi.gov.in**."
    )

# =============================================================================
# TOP NAVBAR
# =============================================================================
render_html(
    """
    <div class="top-navbar">
        <div class="nav-brand">
            <h1 class="brand-title">🛡️ SachCheck</h1>
            <p class="brand-tagline">Verify before you trust.</p>
        </div>
        <div>
            <span class="hackathon-pill">SANGYAN Investor Resilience Hackathon</span>
        </div>
    </div>
    """
)

# Navigation Tabs (Analyze, Evidence, History, How it Works, Evaluation)
tab_analyze, tab_evidence, tab_history, tab_how, tab_eval = st.tabs([
    "🔍 Analyze",
    "📑 Evidence & Claims",
    "📜 Scan History",
    "⚙️ How It Works",
    "📊 Evaluation",
])

# =============================================================================
# TAB 1: 🔍 ANALYZE (MAIN USER JOURNEY)
# =============================================================================
with tab_analyze:
    # HERO SECTION
    render_html(
        """
        <div class="hero-container">
            <h2 class="hero-title">Check suspicious financial messages before you act.</h2>
            <p class="hero-subtitle">Analyze messages, claims and links using risk signals and real evidence.</p>
        </div>
        """
    )

    # CENTRAL INPUT CARD (Native Streamlit Container)
    with st.container(border=True):
        input_mode = st.radio(
            "Select Input Mode:",
            ["✍️ Paste Message", "📸 Upload Screenshot", "📦 Safe APK Inspector (Read-Only)"],
            horizontal=True,
            key="selected_input_mode_radio",
        )

        text_to_analyze = ""
        current_ocr_results = []
        current_pil_images = []
        ocr_quality_score = 0
        ocr_quality_warning = None
        analyze_clicked = False

        # -------------------------------------------------------------------------
        # MODE A: ✍️ PASTE MESSAGE
        # -------------------------------------------------------------------------
        if input_mode == "✍️ Paste Message":
            render_html('<div style="font-size: 0.9rem; font-weight: 600; color: #1E293B; margin-top: 6px; margin-bottom: 4px;">Paste suspicious message</div>')

            # Quick Test Samples
            st.caption("Quick test examples:")
            col_s1, col_s2, col_s3 = st.columns(3)
            with col_s1:
                if st.button("💡 100% Guaranteed Profit", use_container_width=True):
                    sample_text = (
                        "Invest in our VIP scheme with 100% profit and zero loss guaranteed. "
                        "Double your money in 30 days! Send ₹10,000 to UPI profit@paytm."
                    )
                    st.session_state.input_message = sample_text
                    st.session_state.user_text_area = sample_text
                    st.rerun()
            with col_s2:
                if st.button("💡 AnyDesk Remote Support", use_container_width=True):
                    sample_text = (
                        "URGENT: Your trading account withdrawal is blocked. "
                        "Install AnyDesk, send 9-digit code and provide your OTP to release funds immediately."
                    )
                    st.session_state.input_message = sample_text
                    st.session_state.user_text_area = sample_text
                    st.rerun()
            with col_s3:
                if st.button("💡 SEBI Advisory Claim", use_container_width=True):
                    sample_text = (
                        "Kotak Securities Limited is a SEBI registered stock broker with registration INZ000200137. "
                        "Visit official site https://www.kotaksecurities.com for research reports."
                    )
                    st.session_state.input_message = sample_text
                    st.session_state.user_text_area = sample_text
                    st.rerun()

            user_input = st.text_area(
                label="Suspicious Message Text Area",
                label_visibility="collapsed",
                value=st.session_state.get("user_text_area", st.session_state.input_message),
                height=130,
                placeholder="Paste a WhatsApp, Telegram, SMS, or social-media financial message here...",
                key="user_text_area",
            )

            render_html('<div class="helper-text">🔒 Do not share OTPs, passwords, PINs or other sensitive credentials.</div>')

            col_btn, col_clear, _ = st.columns([1.5, 1, 4])
            with col_btn:
                analyze_clicked = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
            with col_clear:
                if st.button("🗑️ Clear", use_container_width=True):
                    st.session_state.input_message = ""
                    st.session_state.user_text_area = ""
                    st.session_state.current_analysis = None
                    st.rerun()

            text_to_analyze = user_input.strip()

        # -------------------------------------------------------------------------
        # MODE B: 📸 UPLOAD SCREENSHOT
        # -------------------------------------------------------------------------
        elif input_mode == "📸 Upload Screenshot":
            render_html('<div class="helper-text">🔒 Screenshots are processed locally in memory. Redact any personal credentials before uploading.</div>')

            uploaded_files = st.file_uploader(
                "Upload WhatsApp, Telegram, or social media financial screenshot(s):",
                type=["png", "jpg", "jpeg", "webp"],
                accept_multiple_files=True,
                help="Supports single or multiple screenshots from the same conversation.",
                key="screenshot_file_uploader",
            )

            if uploaded_files:
                upload_signature = "_".join(f"{f.name}_{f.size}" for f in uploaded_files)

                if st.session_state.ocr_processed_key != upload_signature or st.session_state.ocr_rerun_requested:
                    with st.spinner("Extracting text and layout with EasyOCR..."):
                        combined_texts = []
                        ocr_results_list = []
                        pil_images_list = []
                        confidences = []

                        for uploaded_file in uploaded_files:
                            file_bytes = uploaded_file.read()
                            uploaded_file.seek(0)
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

                current_ocr_results = st.session_state.get("ocr_results", [])
                current_pil_images = st.session_state.get("pil_images", [])
                ocr_quality_score = st.session_state.get("ocr_quality_score", 0)

                # OCR Quality Meter (Separated from risk score)
                col_q1, col_q2 = st.columns([1.5, 2.5])
                with col_q1:
                    render_html(
                        f"""
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 14px;">
                            <span style="font-size: 0.75rem; font-weight: 700; color: #64748B; text-transform: uppercase;">
                                OCR CLARITY METER
                            </span>
                            <div style="font-size: 1.6rem; font-weight: 800; color: {'#059669' if ocr_quality_score >= 65 else '#D97706'};">
                                {ocr_quality_score}%
                            </div>
                            <progress value="{ocr_quality_score}" max="100" style="width: 100%; height: 6px;"></progress>
                            <div style="font-size: 0.72rem; color: #64748B; margin-top: 2px;">
                                Optical quality score. Kept strictly separate from scam risk score.
                            </div>
                        </div>
                        """
                    )
                with col_q2:
                    if ocr_quality_score < 60 and ocr_quality_score > 0:
                        st.warning("⚠️ Some text in this screenshot may be blurry. Review and correct extracted text below.")
                    elif ocr_quality_score == 0:
                        st.error("⚠️ Text could not be reliably extracted. Please manually edit the text below.")
                    else:
                        st.success("✅ Optical character recognition completed. Review or edit text below before analysis.")

                st.markdown("#### Review & Edit Extracted Text")
                edited_text = st.text_area(
                    label="Extracted Text (Editable):",
                    label_visibility="collapsed",
                    value=st.session_state.ocr_extracted_text,
                    height=130,
                    key="ocr_edit_area",
                )

                col_run, col_rerun, _ = st.columns([1.5, 1.2, 4])
                with col_run:
                    analyze_clicked = st.button("🔍 Analyze Screenshot Text", type="primary", use_container_width=True)
                with col_rerun:
                    if st.button("↻ Re-run OCR", use_container_width=True):
                        st.session_state.ocr_rerun_requested = True
                        st.rerun()

                text_to_analyze = edited_text.strip()
            else:
                st.info("👆 Upload one or more conversation screenshots to begin OCR extraction.")

        # -------------------------------------------------------------------------
        # MODE C: 📦 SAFE APK INSPECTOR (READ-ONLY)
        # -------------------------------------------------------------------------
        else:
            render_html(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 14px; margin-bottom: 12px; font-size: 0.85rem; color: #334155;">
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

                render_html(f"<div><strong>SHA-256 Hash:</strong> <code>{inspection.sha256_hash}</code></div>")
                if inspection.native_lib_architectures:
                    st.caption(f"Native Architectures: `{', '.join(inspection.native_lib_architectures)}`")

                st.warning(f"⚠️ **Security Notice:** {inspection.security_notice}")

    # =========================================================================
    # PIPELINE EXECUTION
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
                text_to_analyze, source="SCREENSHOT" if input_mode == "📸 Upload Screenshot" else "MESSAGE"
            )

            # 3. Phase 1: Deterministic Rule Analysis
            phase1_result = analyzer.analyze(text_to_analyze)

            # 4. Safe Action Gate
            action_report = SafeActionGate.evaluate(text_to_analyze)

            # 5. Entity Extraction
            entity_report = EntityExtractor.extract_all(text_to_analyze)

            # 6. Chat Structure Detection
            chat_structure = ChatStructureDetector.parse_chat_structure(text_to_analyze)

            # 7. Advice Guardrail Check
            if phase1_result.is_advice_request:
                st.session_state.current_analysis = {
                    "is_advice": True,
                    "text": text_to_analyze,
                    "phase1": phase1_result,
                    "mode": input_mode,
                }
            else:
                # Progress state
                progress_placeholder = st.empty()
                with progress_placeholder.container():
                    prog_bar = st.progress(0, text="Analyzing message: Extracting claims & entities...")
                    time.sleep(0.04)
                    prog_bar.progress(30, text="Analyzing message: Detecting risk signals & action requests...")
                    time.sleep(0.04)
                    prog_bar.progress(60, text="Analyzing message: Researching official sources via Tavily...")

                    provider = TavilyProvider(api_key=active_api_key)
                    researcher = MessageResearcher(provider=provider)
                    research_report = researcher.research_message(text_to_analyze)

                    prog_bar.progress(85, text="Analyzing message: Matching evidence & verifying claims...")
                    time.sleep(0.04)
                    prog_bar.progress(100, text="Analyzing message: Safety evaluation ready.")
                    time.sleep(0.05)
                progress_placeholder.empty()

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
                        "snippet": (text_to_analyze[:60] + "...") if len(text_to_analyze) > 60 else text_to_analyze,
                        "full_text": text_to_analyze,
                        "mode": input_mode,
                        "risk_level": phase1_result.risk_level,
                        "risk_score": phase1_result.risk_score,
                        "indicators_count": len(phase1_result.indicators),
                    },
                )

    # =========================================================================
    # RENDER ANALYSIS RESULT HIERARCHY
    # RISK RESULT -> WHY -> CLAIM VERIFICATION -> EVIDENCE -> ACTION SAFETY -> SOURCES
    # =========================================================================
    current = st.session_state.current_analysis

    if current is None:
        # CLEAN EMPTY STATE
        render_html(
            """
            <div class="empty-state-box">
                <div style="font-size: 2rem; margin-bottom: 6px;">🛡️</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #1E293B; margin-bottom: 4px;">
                    No analysis yet.
                </div>
                <div style="font-size: 0.9rem; color: #64748B; max-width: 520px; margin: 0 auto 12px auto;">
                    Paste a suspicious message or upload a chat screenshot above to begin evaluation.
                </div>
            </div>
            """
        )

    elif current.get("is_advice"):
        # Financial Advice Guardrail
        p1 = current["phase1"]
        st.error("### ⚠️ Financial Advice Guardrail Triggered")
        render_html(
            f"""
            <div style="background-color: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 8px; padding: 1.15rem; color: #991B1B;">
                <strong>Policy Notice:</strong> {p1.advice_refusal_message}
            </div>
            """
        )
        st.markdown("#### Safe Guidance")
        for step in p1.safe_next_steps:
            render_html(f'<div class="safe-step-box">🛡️ {step}</div>')

    else:
        p1 = current["phase1"]
        ra = current["remote_access"]
        actions = current["action_report"]
        entities = current["entity_report"]
        research = current["research_report"]
        journey = current["journey_profile"]

        # ---------------------------------------------------------------------
        # 1. RISK RESULT CARD (Restrained visual indicators, no harsh backgrounds)
        # ---------------------------------------------------------------------
        risk_class = (
            "risk-high" if p1.risk_level == "HIGH"
            else "risk-medium" if p1.risk_level == "MEDIUM"
            else "risk-low"
        )
        badge_class = (
            "risk-badge-high" if p1.risk_level == "HIGH"
            else "risk-badge-medium" if p1.risk_level == "MEDIUM"
            else "risk-badge-low"
        )
        risk_label_text = (
            "HIGH RISK" if p1.risk_level == "HIGH"
            else "SUSPICIOUS" if p1.risk_level == "MEDIUM"
            else "NO SIGNIFICANT RISK SIGNALS"
        )

        detected_pills = []
        if p1.indicators:
            for ind in p1.indicators:
                detected_pills.append(f'<span class="detected-pill">• {ind.category} (+{ind.score})</span>')
        if ra.app_detected or ra.remote_access_actions:
            detected_pills.append('<span class="detected-pill" style="border-color: #F87171; color: #991B1B;">• Remote-Access Solicitation</span>')
        if actions.has_actions:
            for a in actions.actions:
                detected_pills.append(f'<span class="detected-pill">• Action: {a.label_en}</span>')

        pills_markup = " ".join(detected_pills)
        detected_pills_section = ""
        if detected_pills:
            detected_pills_section = f'<div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(0,0,0,0.08);"><div style="font-size: 0.8rem; font-weight: 700; color: #475569; text-transform: uppercase;">Detected Signals:</div>{pills_markup}</div>'

        stop_banner_section = ""
        if ra.stop_condition:
            stop_banner_section = f'<div style="background-color: #FEE2E2; border: 1px solid #F87171; border-radius: 6px; padding: 8px 12px; margin-top: 10px; color: #991B1B; font-size: 0.88rem;"><strong>🛑 STOP AND VERIFY:</strong> {ra.stop_reason}</div>'

        risk_card_html = f"""
        <div class="risk-result-card {risk_class}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <span style="font-size: 0.75rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px;">
                        RISK LEVEL
                    </span>
                    <div style="margin-top: 4px; margin-bottom: 6px;">
                        <span class="risk-badge {badge_class}">{risk_label_text}</span>
                    </div>
                    <div style="font-size: 0.88rem; font-weight: 600; opacity: 0.95;">
                        Deterministic Risk Score: <strong>{p1.risk_score} / 100</strong>
                    </div>
                </div>
                <div style="text-align: right; background: rgba(255,255,255,0.7); padding: 8px 16px; border-radius: 8px; border: 1px solid rgba(0,0,0,0.06);">
                    <div style="font-size: 0.75rem; color: #64748B; font-weight: 700;">SCORE</div>
                    <div style="font-size: 1.8rem; font-weight: 900; line-height: 1;">{p1.risk_score}</div>
                </div>
            </div>
            {detected_pills_section}
            {stop_banner_section}
        </div>
        """
        render_html(risk_card_html)

        # ---------------------------------------------------------------------
        # 2. WHY THIS WAS FLAGGED ("WHY")
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">WHY THIS WAS FLAGGED</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Predefined deterministic risk patterns matching message content.</p>', unsafe_allow_html=True)

            # Highlighted Extracted Text
            render_html(f'<div class="message-container">{p1.highlighted_html}</div>')

            # Detailed breakdown of detected indicators
            if p1.indicators:
                for ind in p1.indicators:
                    color_info = CATEGORY_COLOR_MAP.get(ind.category_id, ((100, 116, 139), "#3B82F6", "⚪"))
                    phrases_display = ", ".join(f'"{p}"' for p in ind.matched_phrases)

                    render_html(
                        f"""
                        <div class="indicator-box" style="border-left-color: {color_info[1]};">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <strong style="color: #0F172A; font-size: 0.95rem;">{color_info[2]} {ind.category}</strong>
                                <span style="background: #F1F5F9; color: #334155; font-weight: 700; padding: 2px 8px; border-radius: 6px; font-size: 0.8rem;">
                                    +{ind.score} pts
                                </span>
                            </div>
                            <div style="font-size: 0.88rem; color: #475569; margin-bottom: 4px;">
                                Matched phrase: <code>{phrases_display}</code>
                            </div>
                            <div style="font-size: 0.85rem; color: #1E293B; margin-bottom: 2px;">
                                <strong>Why it matters:</strong> {ind.why_it_matters_en}
                            </div>
                            <div style="font-size: 0.85rem; color: #64748B;">
                                <em>{ind.why_it_matters_hi}</em>
                            </div>
                        </div>
                        """
                    )
            else:
                st.info("No predefined scam or manipulation patterns were matched in this message.")

            # Plain-Language Explanation Tabs
            st.markdown("<div style='margin-top: 10px; margin-bottom: 4px;'><strong>Plain-Language Explanation:</strong></div>", unsafe_allow_html=True)
            tab_en, tab_hi = st.tabs(["🇬🇧 English", "🇮🇳 Hindi / Hinglish"])
            with tab_en:
                st.info(p1.explanation_en)
            with tab_hi:
                st.info(p1.explanation_hi)

        # ---------------------------------------------------------------------
        # 3. CLAIM VERIFICATION
        # ---------------------------------------------------------------------
        with st.container(border=True):
            col_c_hdr, col_c_mode = st.columns([3, 1.2])
            with col_c_hdr:
                st.markdown('<h3 class="section-header">CLAIM VERIFICATION</h3>', unsafe_allow_html=True)
                st.markdown('<p class="section-caption">Factual claims checked against authentic public & regulatory sources.</p>', unsafe_allow_html=True)
            with col_c_mode:
                st.markdown("<div style='text-align: right;'>", unsafe_allow_html=True)
                if research.is_live:
                    render_html(f'<span class="badge-live">🌐 {research.mode_label}</span>')
                else:
                    render_html(f'<span class="badge-offline">⚪ {research.mode_label}</span>')
                st.markdown("</div>", unsafe_allow_html=True)

            if not research.claims:
                st.info("ℹ️ No specific regulatory or verifiable factual claims were detected in this message.")
            else:
                for claim_res in research.claims:
                    status_class = f"status-{claim_res.status}"
                    source_link_html = ""
                    if claim_res.source_url:
                        source_link_html = f'<div style="margin-top: 6px; font-size: 0.82rem; color: #475569;">Source: <strong>{claim_res.source_title}</strong> (<code>{claim_res.source_domain}</code>) &bull; <a href="{claim_res.source_url}" target="_blank" style="color: #2563EB; font-weight: 600;">View Official Source ↗</a></div>'

                    render_html(
                        f"""
                        <div class="claim-card">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                <div>
                                    <span style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">
                                        CLAIM DETECTED
                                    </span>
                                    <div style="font-size: 1.05rem; font-weight: 700; color: #0F172A; margin-top: 2px;">
                                        "{claim_res.original_claim}"
                                    </div>
                                </div>
                                <span class="status-badge {status_class}">
                                    {claim_res.status.replace('_', ' ')}
                                </span>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 8px; background: #F8FAFC; border: 1px solid #F1F5F9; padding: 10px 12px; border-radius: 6px;">
                                <div>
                                    <span style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">WHAT THIS ESTABLISHES</span>
                                    <div style="font-size: 0.88rem; color: #1E293B; margin-top: 2px;">
                                        {claim_res.what_source_establishes}
                                    </div>
                                </div>
                                <div>
                                    <span style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">WHAT THIS DOES NOT ESTABLISH</span>
                                    <div style="font-size: 0.88rem; color: #991B1B; margin-top: 2px;">
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

        # ---------------------------------------------------------------------
        # 4. EVIDENCE & VISUAL PROOF
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">EVIDENCE</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Retrieved evidence snippets, screenshot bounding boxes, and journey progression.</p>', unsafe_allow_html=True)

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
                    <div style="background-color: #FEF3C7; border: 1px solid #F59E0B; border-radius: 8px; padding: 10px 12px; margin-bottom: 10px; color: #92400E; font-size: 0.9rem;">
                        <strong>⚠️ Multi-Stage Progression Detected ({journey.evidence_strength} Evidence):</strong><br>
                        {journey.progression_summary}
                    </div>
                    """
                )
                for stg in journey.stages_detected:
                    render_html(
                        f"""
                        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 3px solid #6366F1; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px;">
                            <div style="font-size: 0.85rem; font-weight: 700; color: #1E293B;">
                                {stg.stage_badge} {stg.stage_title}
                            </div>
                            <div style="font-size: 0.82rem; color: #64748B; margin-top: 2px;">
                                Snippet: <code>"{stg.evidence_snippet}"</code>
                            </div>
                            <div style="font-size: 0.82rem; color: #334155; margin-top: 2px;">
                                {stg.explanation_en}
                            </div>
                        </div>
                        """
                    )

            # URL Inspection
            if research.extracted_urls or entities.urls:
                urls_to_inspect = research.extracted_urls or entities.urls
                st.markdown("#### 🔗 URL Inspection")
                for u in urls_to_inspect:
                    render_html(
                        f"""
                        <div class="source-box">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 0.9rem; font-weight: 600; color: #0F172A;"><code>{u.original_url}</code></span>
                                <span style="font-size: 0.78rem; font-weight: 700; color: #475569;">
                                    {'🔒 HTTPS' if u.is_https else '⚠️ HTTP (Insecure)'} |
                                    {'⚡ Shortener' if u.is_shortened else '🌐 Direct Domain'}
                                </span>
                            </div>
                            <div style="font-size: 0.82rem; color: #64748B; margin-top: 4px;">{u.note}</div>
                        </div>
                        """
                    )

        # ---------------------------------------------------------------------
        # 5. SAFE ACTION GATE ("STOP BEFORE YOU ACT")
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">STOP BEFORE YOU ACT</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Action solicitations detected in the message and defensive directives.</p>', unsafe_allow_html=True)

            if actions.has_actions or ra.remote_access_actions:
                actions_items_html = []
                for a in actions.actions:
                    actions_items_html.append(
                        f'<div style="margin-top: 6px; font-size: 0.88rem; color: #4C0519;"><span class="action-badge">{a.severity}</span><strong>{a.label_en}</strong>: <code>{a.matched_phrase}</code><div style="font-size: 0.82rem; margin-top: 2px;">{a.why_dangerous_en}</div></div>'
                    )
                if ra.remote_access_actions:
                    for ra_act in ra.remote_access_actions:
                        actions_items_html.append(
                            f'<div style="margin-top: 6px; font-size: 0.88rem; color: #4C0519;"><span class="action-badge">CRITICAL</span><strong>Remote Access Action:</strong> {ra_act.action_type.replace("_", " ")}<div style="font-size: 0.82rem; margin-top: 2px;">Matched: <code>{ra_act.matched_text}</code></div></div>'
                        )

                action_alert_full = f"""
                <div class="action-gate-alert">
                    <strong style="color: #9F1239; font-size: 0.95rem;">
                        This message is asking you to take one or more sensitive actions:
                    </strong>
                    {''.join(actions_items_html)}
                </div>
                """
                render_html(action_alert_full)

                # Recommended action
                st.markdown("#### Recommended Action:")
                st.info("👉 **Verify independently before taking any action.** Do not transfer funds or grant device control.")

                for g in actions.guidance:
                    render_html(f'<div class="safe-step-box">🛑 {g}</div>')

                # Remote Access Incident Response
                if ra.app_detected or ra.remote_access_actions:
                    st.markdown("---")
                    st.markdown("#### 🚨 Did you already grant remote access or install software?")
                    already_granted = st.radio(
                        "Have you already installed the software or shared the connection code?",
                        ["No", "Yes", "I'm not sure"],
                        horizontal=True,
                        key="already_granted_radio_choice",
                    )

                    if already_granted in ("Yes", "I'm not sure"):
                        containment_steps_html = "".join(f"<div style='margin-top: 4px; font-size: 0.85rem;'>{step}</div>" for step in ra.what_to_do_already_granted)
                        incident_box_html = f"""
                        <div class="incident-response-box">
                            <h4 style="margin: 0 0 6px 0; color: #991B1B;">🚨 IMMEDIATE INCIDENT RESPONSE</h4>
                            <strong>Take these containment steps immediately:</strong><br>
                            {containment_steps_html}
                        </div>
                        """
                        render_html(incident_box_html)

            else:
                st.success("✅ No direct payment, credential, or device-takeover actions were explicitly solicited.")

        # ---------------------------------------------------------------------
        # 6. ENTITIES & LINKS
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">ENTITIES & LINKS</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Entities and tokens detected directly from the message text.</p>', unsafe_allow_html=True)

            has_any_entity = False
            col_e1, col_e2 = st.columns(2)

            with col_e1:
                if entities.companies:
                    has_any_entity = True
                    st.markdown(f"**🏢 Companies / Advisories:** `{', '.join(entities.companies)}`")
                if entities.sebi_registration_numbers:
                    has_any_entity = True
                    st.markdown(f"**🏛️ SEBI Reg. Numbers:** `{', '.join(entities.sebi_registration_numbers)}`")
                if entities.upi_ids:
                    has_any_entity = True
                    st.markdown(f"**💳 UPI Handles:** `{', '.join(entities.upi_ids)}`")
                if entities.amounts:
                    has_any_entity = True
                    st.markdown(f"**💰 Amounts Claimed:** `{', '.join(entities.amounts)}`")

            with col_e2:
                if entities.whatsapp_numbers:
                    has_any_entity = True
                    st.markdown(f"**📱 WhatsApp:** `{', '.join(entities.whatsapp_numbers)}`")
                if entities.telegram_handles:
                    has_any_entity = True
                    st.markdown(f"**💬 Telegram Handles:** `{', '.join(entities.telegram_handles)}`")
                if entities.phone_numbers:
                    has_any_entity = True
                    st.markdown(f"**📞 Phone Numbers:** `{', '.join(entities.phone_numbers)}`")
                if entities.percentage_claims:
                    has_any_entity = True
                    st.markdown(f"**📊 Return Claims:** `{', '.join(entities.percentage_claims)}`")

            if not has_any_entity:
                st.caption("No corporate entities, registration identifiers, or payment handles detected.")

        # ---------------------------------------------------------------------
        # 7. SOURCES
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">SOURCES</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Official and public sources consulted during analysis.</p>', unsafe_allow_html=True)

            if not research.sources:
                st.caption("No external sources were retrieved for this query.")
            else:
                for idx, src in enumerate(research.sources, 1):
                    col_src_info, col_src_btn = st.columns([3.5, 1])
                    with col_src_info:
                        render_html(
                            f"""
                            <div style="font-size: 0.9rem; font-weight: 700; color: #0F172A;">
                                {idx}. {src.title}
                            </div>
                            <div style="font-size: 0.8rem; color: #475569;">
                                Domain: <code>{src.domain}</code> | Classification: <code>{src.source_type}</code>
                            </div>
                            <div style="font-size: 0.82rem; color: #334155; margin-top: 4px; max-height: 48px; overflow: hidden;">
                                "{src.content[:160]}..."
                            </div>
                            """
                        )
                    with col_src_btn:
                        st.link_button("Open Source ↗", src.url, use_container_width=True)
                    render_html("<hr style='margin: 8px 0; border: none; border-top: 1px solid #F1F5F9;'>")

        # ---------------------------------------------------------------------
        # 8. SAFE NEXT STEPS & TRUST MESSAGE
        # ---------------------------------------------------------------------
        with st.container(border=True):
            st.markdown('<h3 class="section-header">RECOMMENDED SAFE NEXT STEPS</h3>', unsafe_allow_html=True)
            st.markdown('<p class="section-caption">Actionable investor protection directives.</p>', unsafe_allow_html=True)

            for step in p1.safe_next_steps:
                render_html(f'<div class="safe-step-box">👉 {step}</div>')

            # Copy Safe Reply feature
            st.markdown("<div style='margin-top: 10px; margin-bottom: 4px;'><strong>Copy Safe Reply to Sender:</strong></div>", unsafe_allow_html=True)
            st.caption("You can copy and send this standard verification query to the sender:")
            safe_reply_text = (
                "Please provide your registered SEBI Intermediary Registration Number and the official listing link on sebi.gov.in before we discuss any financial services."
            )
            st.code(safe_reply_text, language="text")

            # Traceable Execution Steps (Expandable)
            with st.expander("🛠️ How We Verified This (Traceable Execution Steps)", expanded=False):
                for idx, step in enumerate(research.steps_performed, 1):
                    st.markdown(f"**{idx}.** {step}")

    # MANDATORY TRUST & SAFETY FOOTER
    render_html(
        """
        <div class="trust-footer">
            Risk results are indicators, not proof of fraud. Always verify important financial claims through official sources.<br>
            Official directory: <a href="https://www.sebi.gov.in" target="_blank" style="color: #2563EB;">sebi.gov.in</a> &bull; National Cyber Crime Helpline: <strong>1930</strong> (<a href="https://cybercrime.gov.in" target="_blank" style="color: #2563EB;">cybercrime.gov.in</a>)
        </div>
        """
    )

# =============================================================================
# TAB 2: 📑 EVIDENCE & CLAIMS
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
# TAB 3: 📜 SCAN HISTORY (SESSION AUDIT LOG)
# =============================================================================
with tab_history:
    st.markdown("### 📜 Session Scan History")
    st.caption("Record of messages and screenshots analyzed during this active session.")

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
# TAB 4: ⚙️ HOW IT WORKS & ARCHITECTURE
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
# TAB 5: 📊 EVALUATION (INTERNAL SYNTHETIC TEST-SET)
# =============================================================================
with tab_eval:
    st.markdown("### 📊 Internal Synthetic Test-Set Evaluation")
    st.caption(
        "Transparency report: Results calculated deterministically from the 28 labeled synthetic test cases. "
        "This reflects internal synthetic test performance and is NOT claimed as real-world accuracy."
    )

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

    st.markdown("---")
    st.markdown("#### Evaluation Breakdown by Case")

    table_rows = []
    for c in eval_data["case_details"]:
        status = "✅ PASS" if c["is_correct"] else "❌ FAIL"
        table_rows.append({
            "Case ID": c["id"],
            "Category Focus": c["category_focus"],
            "Language": c["language"],
            "Expected Level": c["expected_risk_level"],
            "Actual Level": c["actual_risk_level"],
            "Score": c["actual_score"],
            "Status": status,
        })

    st.dataframe(table_rows, use_container_width=True)
