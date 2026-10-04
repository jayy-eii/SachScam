"""
UI Theme and Design System for SachCheck.
Centralizes all styles, typography (Inter), color tokens, and layout components.
Ensures strict WCAG AA contrast compliance and a polished fintech/cyber-safety aesthetic.
"""

import textwrap
import streamlit as st


# =============================================================================
# DESIGN SYSTEM TOKENS & CSS
# =============================================================================
THEME_CSS = textwrap.dedent("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Global Font & Color Overrides */
html, body, p, label, input, textarea, button, select {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #0F172A;
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Preserve Material Symbols icons - strictly protect glyphs from font overrides */
span[data-testid="stIconMaterial"],
[data-testid="stIconMaterial"],
[data-testid="stIconMaterial"] *,
.material-symbols-rounded,
.material-symbols-outlined,
.material-icons,
[data-testid="stExpanderToggleIcon"] * {
    font-family: 'Material Symbols Rounded' !important;
    font-style: normal !important;
    font-weight: 400 !important;
    letter-spacing: normal !important;
    text-transform: none !important;
    display: inline-block !important;
    white-space: nowrap !important;
    word-wrap: normal !important;
    direction: ltr !important;
    -webkit-font-smoothing: antialiased !important;
}

/* Background & Main App Block */
.stApp {
    background-color: #F6F8FB !important;
}

[data-testid="stAppViewBlockContainer"] {
    max-width: 1100px !important;
    margin: 0 auto !important;
    padding: 1.5rem 1.25rem 3.5rem 1.25rem !important;
}

@media (max-width: 768px) {
    [data-testid="stAppViewBlockContainer"] {
        padding: 1rem 0.75rem 2.5rem 0.75rem !important;
    }
}

/* Hide Streamlit Clutter / Default Header / Footer / Toolbar & Nudges */
#MainMenu, 
header[data-testid="stHeader"], 
footer, 
[data-testid="stToolbar"], 
[data-testid="stDecoration"], 
[data-testid="stStatusWidget"],
[data-testid="stSkillsNudge"],
.stSkillsNudge,
.e982qu80,
.e982qu81,
[class*="e982qu80"],
[class*="e982qu81"],
div:has(> [data-testid="stSkillsNudge"]),
div[class*="stNotification"],
[data-testid="stNotification"] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    pointer-events: none !important;
    height: 0 !important;
    width: 0 !important;
    position: absolute !important;
    top: -9999px !important;
}

/* Sidebar Styling: Clean, White, Compact */
[data-testid="stSidebar"] {
    background-color: #FFFFFF !important;
    border-right: 1px solid #E2E8F0 !important;
    padding-top: 1rem !important;
}

[data-testid="stSidebar"] h1, 
[data-testid="stSidebar"] h2, 
[data-testid="stSidebar"] h3, 
[data-testid="stSidebar"] h4 {
    color: #0F172A !important;
    font-weight: 700 !important;
}

[data-testid="stSidebar"] p, 
[data-testid="stSidebar"] span, 
[data-testid="stSidebar"] label {
    color: #334155 !important;
}

/* Typography Hierarchy (WCAG AA Compliant) */
h1 {
    font-size: 2.25rem !important; /* 36px */
    font-weight: 700 !important;
    color: #0F172A !important;
    line-height: 1.25 !important;
    letter-spacing: -0.5px !important;
}

h2 {
    font-size: 1.5rem !important; /* 24px */
    font-weight: 600 !important;
    color: #0F172A !important;
    line-height: 1.3 !important;
    letter-spacing: -0.3px !important;
}

h3 {
    font-size: 1.15rem !important;
    font-weight: 600 !important;
    color: #0F172A !important;
    letter-spacing: -0.2px !important;
}

p {
    font-size: 1rem !important; /* 16px */
    color: #334155 !important;
    line-height: 1.6 !important;
}

.sc-caption, small, .stCaption {
    font-size: 0.8125rem !important; /* 13px */
    color: #64748B !important;
}

/* Modern Card Container */
.sc-card {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 14px;
    padding: 1.5rem;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(15, 23, 42, 0.02);
    margin-bottom: 1.25rem;
    transition: box-shadow 150ms ease, border-color 150ms ease;
}

.sc-card:hover {
    box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.05), 0 2px 4px -1px rgba(15, 23, 42, 0.03);
}

/* Streamlit Container Border Wrapper Override */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: #FFFFFF !important;
    border: 1px solid #E2E8F0 !important;
    border-radius: 14px !important;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(15, 23, 42, 0.02) !important;
    padding: 1.25rem !important;
    margin-bottom: 1.25rem !important;
}

/* Hero Section */
.sc-hero {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding-bottom: 1.25rem;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid #E2E8F0;
}

.sc-brand-row {
    display: flex;
    align-items: center;
    gap: 12px;
}

.sc-logo-badge {
    font-size: 2.2rem;
    line-height: 1;
}

.sc-brand-title {
    font-size: 2.25rem;
    font-weight: 800;
    color: #0F172A;
    letter-spacing: -0.6px;
    margin: 0;
    line-height: 1.1;
}

.sc-brand-tagline {
    font-size: 1rem;
    color: #475569;
    margin-top: 6px;
    margin-bottom: 0;
}

.sc-trust-chips {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 12px;
    flex-wrap: wrap;
}

.sc-trust-chip {
    background-color: #F8FAFC;
    color: #334155;
    font-size: 0.8125rem;
    font-weight: 500;
    padding: 4px 10px;
    border-radius: 9999px;
    border: 1px solid #E2E8F0;
    display: inline-flex;
    align-items: center;
    gap: 5px;
}

.sc-hackathon-pill {
    background: #EFF6FF;
    color: #1D4ED8;
    font-size: 0.75rem;
    font-weight: 700;
    padding: 5px 12px;
    border-radius: 9999px;
    border: 1px solid #BFDBFE;
    letter-spacing: 0.3px;
    white-space: nowrap;
}

/* Modern Tab Navigation */
div[role="tablist"] {
    gap: 6px !important;
    background-color: #EDF2F7 !important;
    padding: 4px !important;
    border-radius: 12px !important;
    border: 1px solid #E2E8F0 !important;
    margin-bottom: 1.5rem !important;
    display: flex !important;
    align-items: center !important;
}

div[data-testid="stTab"] {
    height: 40px !important;
    border-radius: 9px !important;
    font-size: 0.9375rem !important;
    font-weight: 600 !important;
    color: #64748B !important;
    border: none !important;
    padding: 0 18px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    cursor: pointer !important;
    transition: all 150ms ease !important;
    background: transparent !important;
}

div[data-testid="stTab"]:hover {
    color: #0F172A !important;
    background-color: rgba(255, 255, 255, 0.7) !important;
}

div[data-testid="stTab"][aria-selected="true"] {
    background-color: #FFFFFF !important;
    color: #2563EB !important;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08) !important;
    font-weight: 700 !important;
}

div[role="tablist"]::after,
div[role="tablist"]::before,
div[data-testid="stTab"]::after,
div[data-testid="stTab"]::before {
    display: none !important;
}

/* Form Inputs & Textarea */
.stTextArea textarea {
    font-family: 'Inter', -apple-system, sans-serif !important;
    font-size: 1rem !important;
    border-radius: 12px !important;
    border: 1px solid #CBD5E1 !important;
    background-color: #FFFFFF !important;
    color: #0F172A !important;
    line-height: 1.55 !important;
    padding: 12px 14px !important;
    transition: border-color 150ms ease, box-shadow 150ms ease !important;
}

.stTextArea textarea:focus {
    border-color: #2563EB !important;
    background-color: #FFFFFF !important;
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14) !important;
}

/* Action Buttons */
.stButton button {
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    padding: 0.55rem 1.1rem !important;
    transition: all 150ms ease-in-out !important;
    white-space: nowrap !important;
    border: 1px solid #CBD5E1 !important;
    background-color: #FFFFFF !important;
    color: #1E293B !important;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
}

.stButton button:hover {
    background-color: #F8FAFC !important;
    border-color: #94A3B8 !important;
    color: #0F172A !important;
    transform: translateY(-1px) !important;
}

/* Primary Action Buttons */
.stButton button[kind="primary"],
.stButton button[data-testid="stBaseButton-primary"],
button[kind="primary"] {
    background: #2563EB !important;
    background-color: #2563EB !important;
    color: #FFFFFF !important;
    border: 1px solid #1D4ED8 !important;
    box-shadow: 0 1px 3px 0 rgba(37, 99, 235, 0.25) !important;
    font-size: 0.95rem !important;
    font-weight: 700 !important;
    padding: 0.65rem 1.4rem !important;
}

.stButton button[kind="primary"]:hover,
.stButton button[data-testid="stBaseButton-primary"]:hover,
button[kind="primary"]:hover {
    background: #1D4ED8 !important;
    background-color: #1D4ED8 !important;
    border-color: #1E40AF !important;
    box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.35) !important;
    transform: translateY(-1px) !important;
}

/* Highlighted Message Box */
.message-container {
    background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    padding: 1.15rem 1.25rem;
    font-size: 1rem;
    line-height: 1.7;
    color: #0F172A;
    margin-bottom: 1rem;
    word-break: break-word;
}

mark.risk-highlight {
    background-color: #FEF08A;
    color: #854D0E;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: 4px;
    border-bottom: 2px solid #CA8A04;
}

/* Score Ring & Risk Banner */
.sc-result-hero {
    display: flex;
    align-items: center;
    gap: 24px;
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.sc-gauge-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-width: 120px;
}

.sc-risk-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 0.9375rem;
    font-weight: 700;
    padding: 6px 14px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.sc-risk-high {
    background-color: #FEF2F2;
    color: #DC2626;
    border: 1px solid #FCA5A5;
}

.sc-risk-medium {
    background-color: #FFFBEB;
    color: #D97706;
    border: 1px solid #FCD34D;
}

.sc-risk-low {
    background-color: #F0FDF4;
    color: #16A34A;
    border: 1px solid #86EFAC;
}

/* Detected Signals Chips */
.sc-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 0.8125rem;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 8px;
    margin-right: 6px;
    margin-bottom: 6px;
}

.sc-signal-high {
    background: #FEF2F2;
    color: #991B1B;
    border: 1px solid #FCA5A5;
}

.sc-signal-medium {
    background: #FFFBEB;
    color: #92400E;
    border: 1px solid #FCD34D;
}

.sc-signal-action {
    background: #FDF2F8;
    color: #9D174D;
    border: 1px solid #FBCFE8;
}

/* 4-Step Reading Order Headers */
.sc-step-header {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.15rem;
    font-weight: 700;
    color: #0F172A;
    margin-bottom: 4px;
}

.sc-step-num {
    background-color: #EFF6FF;
    color: #2563EB;
    font-size: 0.8125rem;
    font-weight: 800;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid #BFDBFE;
}

/* Indicator Box */
.sc-indicator-box {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-left: 4px solid #2563EB;
    border-radius: 10px;
    padding: 1rem 1.15rem;
    margin-bottom: 0.75rem;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
}

/* Claim Verification Card */
.sc-claim-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 1.15rem 1.25rem;
    margin-bottom: 0.85rem;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.02);
}

.sc-claim-status-badge {
    font-size: 0.75rem;
    font-weight: 800;
    padding: 3px 8px;
    border-radius: 6px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    display: inline-block;
}

.sc-status-VERIFIED {
    background-color: #DEF7EC;
    color: #03543F;
    border: 1px solid #84E1BC;
}

.sc-status-CONTRADICTED {
    background-color: #FDE8E8;
    color: #9B1C1C;
    border: 1px solid #F8B4B4;
}

.sc-status-NOT_VERIFIED {
    background-color: #F3F4F6;
    color: #374151;
    border: 1px solid #D1D5DB;
}

.sc-status-UNABLE_TO_VERIFY {
    background-color: #FEF08A;
    color: #713F12;
    border: 1px solid #FACC15;
}

/* Claim Comparison Columns */
.sc-claim-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-top: 10px;
    background: #F8FAFC;
    border: 1px solid #F1F5F9;
    padding: 12px 14px;
    border-radius: 8px;
}

@media (max-width: 640px) {
    .sc-claim-grid {
        grid-template-columns: 1fr;
    }
}

.sc-claim-col-title {
    font-size: 0.6875rem;
    color: #64748B;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}

.sc-claim-col-establishes {
    font-size: 0.875rem;
    color: #1E293B;
    margin-top: 2px;
    line-height: 1.45;
}

.sc-claim-col-limitations {
    font-size: 0.875rem;
    color: #991B1B;
    margin-top: 2px;
    line-height: 1.45;
}

/* Safe Action Gate Alert Box */
.sc-action-alert {
    background-color: #FFF1F2;
    border: 1px solid #FECDD3;
    border-left: 4px solid #E11D48;
    border-radius: 10px;
    padding: 1rem 1.15rem;
    margin-bottom: 0.85rem;
}

.sc-safe-step-box {
    background-color: #F0FDF4;
    border: 1px solid #BBF7D0;
    border-radius: 8px;
    padding: 0.65rem 0.95rem;
    margin-bottom: 0.5rem;
    color: #166534;
    font-size: 0.875rem;
    display: flex;
    align-items: flex-start;
    gap: 8px;
}

/* Sidebar Metric Tiles */
.sc-sidebar-tile {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    padding: 10px 12px;
    margin-bottom: 8px;
    text-align: center;
}

.sc-sidebar-tile-num {
    font-size: 1.5rem;
    font-weight: 800;
    color: #0F172A;
    line-height: 1.1;
}

.sc-sidebar-tile-label {
    font-size: 0.75rem;
    color: #64748B;
    font-weight: 600;
    text-transform: uppercase;
    margin-top: 2px;
}

/* Empty State */
.sc-empty-state {
    background-color: #FFFFFF;
    border: 1px dashed #CBD5E1;
    border-radius: 14px;
    padding: 3rem 1.5rem;
    text-align: center;
    margin-bottom: 1.5rem;
}

.sc-empty-icon {
    font-size: 2.25rem;
    margin-bottom: 8px;
}

.sc-empty-title {
    font-size: 1.125rem;
    font-weight: 700;
    color: #0F172A;
    margin-bottom: 4px;
}

.sc-empty-desc {
    font-size: 0.9375rem;
    color: #64748B;
    max-width: 480px;
    margin: 0 auto;
}

/* Footer */
.sc-footer {
    text-align: center;
    font-size: 0.8125rem;
    color: #64748B;
    border-top: 1px solid #E2E8F0;
    padding-top: 1.25rem;
    margin-top: 2.5rem;
    margin-bottom: 1rem;
    line-height: 1.6;
}
</style>
""")


def inject_custom_theme():
    """Injects the unified design system CSS once, along with clutter dismissal scripts."""
    theme_payload = THEME_CSS + "\n<script>try{window.localStorage.setItem('stSkillsNudgeDismissed','true');}catch(e){}</script>"
    if hasattr(st, "html"):
        st.html(theme_payload)
    else:
        st.markdown(theme_payload, unsafe_allow_html=True)


def render_html_block(html_content: str):
    """Safely renders semantic HTML blocks and inline SVGs without markdown code-block triggers."""
    clean_lines = [line.strip() for line in html_content.strip().splitlines() if line.strip()]
    no_indent_html = " ".join(clean_lines)
    st.markdown(no_indent_html, unsafe_allow_html=True)


def render_score_ring_svg(score: int, risk_level: str) -> str:
    """
    Renders an SVG circular score ring / gauge (0–100) with WCAG compliant colors.
    """
    if risk_level == "HIGH":
        ring_color = "#DC2626"  # Red
        bg_ring = "#FEE2E2"
    elif risk_level == "MEDIUM":
        ring_color = "#D97706"  # Amber
        bg_ring = "#FEF3C7"
    else:
        ring_color = "#16A34A"  # Green
        bg_ring = "#DCFCE7"

    clamped_score = max(0, min(100, score))
    # Circumference for radius 42 is 2 * pi * 42 ~= 263.89
    dash_offset = 263.89 * (1 - (clamped_score / 100.0))

    svg = f"""<svg width="104" height="104" viewBox="0 0 100 100" style="display: block;"><circle cx="50" cy="50" r="42" fill="none" stroke="{bg_ring}" stroke-width="8" /><circle cx="50" cy="50" r="42" fill="none" stroke="{ring_color}" stroke-width="8" stroke-dasharray="263.89" stroke-dashoffset="{dash_offset}" stroke-linecap="round" transform="rotate(-90 50 50)" /><text x="50" y="47" text-anchor="middle" font-size="22" font-weight="800" font-family="'Inter', sans-serif" fill="#0F172A">{clamped_score}</text><text x="50" y="63" text-anchor="middle" font-size="9" font-weight="600" font-family="'Inter', sans-serif" fill="#64748B">OUT OF 100</text></svg>"""
    return svg


def render_hero_banner(is_live: bool):
    """Renders the standard top hero with logo, value prop, trust chips, and hackathon pill."""
    status_dot = "🟢" if is_live else "⚪"
    status_text = "Live Research Ready" if is_live else "Offline Mode"

    html_code = f"""
    <div class="sc-hero">
        <div>
            <div class="sc-brand-row">
                <span class="sc-logo-badge">🛡️</span>
                <div>
                    <h1 class="sc-brand-title">SachCheck</h1>
                    <p class="sc-brand-tagline">Verify financial messages, investment claims, and sender credibility before you act.</p>
                </div>
            </div>
            <div class="sc-trust-chips">
                <span class="sc-trust-chip">🛡️ Evidence-based</span>
                <span class="sc-trust-chip">🌐 Live web research</span>
                <span class="sc-trust-chip">🔒 Privacy-first</span>
                <span class="sc-trust-chip">{status_dot} {status_text}</span>
            </div>
        </div>
        <div style="text-align: right;">
            <span class="sc-hackathon-pill">SANGYAN Hackathon</span>
        </div>
    </div>
    """
    render_html_block(html_code)


def render_empty_state_card():
    """Renders clean empty state when no analysis is active."""
    html_code = """
    <div class="sc-empty-state">
        <div class="sc-empty-icon">🛡️</div>
        <div class="sc-empty-title">Ready to verify financial messages</div>
        <p class="sc-empty-desc">
            Paste a suspicious WhatsApp, Telegram, or SMS message above, or upload a screenshot to inspect risk indicators and verify claims against official registries.
        </p>
    </div>
    """
    render_html_block(html_code)


def render_trust_footer():
    """Renders mandatory disclaimer and grievance helpline footer."""
    html_code = """
    <div class="sc-footer">
        <strong>SachCheck Investor Safety Notice:</strong> Risk scores and verification results are indicators based on predefined threat rules and public registry lookups. SachCheck does not provide financial advice, stock predictions, or Buy/Sell/Hold recommendations.<br>
        Official directory: <a href="https://www.sebi.gov.in" target="_blank" style="color: #2563EB; text-decoration: none; font-weight: 600;">sebi.gov.in</a> &bull; National Cyber Crime Helpline: <strong>1930</strong> (<a href="https://cybercrime.gov.in" target="_blank" style="color: #2563EB; text-decoration: none; font-weight: 600;">cybercrime.gov.in</a>)
    </div>
    """
    render_html_block(html_code)
