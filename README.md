# 🛡️ SachCheck — Investor Safety Platform & Evidence-Based Verification Engine
> Built for the **SANGYAN Investor Resilience Hackathon**  
> *A deterministic, evidence-grounded cyber-safety platform protecting retail investors from fraudulent financial solicitations, pump-and-dump syndicates, unauthorized advisory channels, and remote-access takeover fraud.*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-87%20Passed-brightgreen.svg)]()
[![Accuracy](https://img.shields.io/badge/Synthetic%20Benchmark-100%25-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20In--Memory-success.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Deterministic%20Rule%20Engine-purple.svg)]()

---

## 📌 Executive Summary

Retail investors in India are increasingly targeted across WhatsApp, Telegram, Instagram, SMS, and private messaging groups by sophisticated cyber-financial syndicates. These scams leverage high-pressure urgency, fabricated regulatory registrations, fake profit screenshots, unauthorized advisory groups, and remote-access device compromise (e.g. AnyDesk, TeamViewer).

**SachCheck** provides a complete, evidence-based defensive shield. Rather than outsourcing safety decisions to an opaque LLM that can hallucinate or be jailbroken, **SachCheck enforces a 100% deterministic Python rule engine as the sole source of truth for risk assessment**. Real-time internet research (via Tavily) is utilized strictly for factual corroboration against official government registries (SEBI, RBI, Cybercrime, NSE, BSE), while local computer vision (EasyOCR) extracts text and maps visual red-flag bounding boxes onto chat screenshots in memory.

---

## 🌟 Complete Feature Matrix

SachCheck provides 10 integrated defensive capabilities designed for retail investor resilience:

| # | Feature | Description | Mode / Availability |
|---|---|---|:---:|
| 1 | **Deterministic Risk Meter** | Calculates an explainable 0–100 risk score and level (`LOW`, `SUSPICIOUS`, `HIGH`) strictly through transparent Python rules without LLM arbitrariness. | Offline / Online |
| 2 | **Multilingual Linguistic Profiler** | Native pattern recognition for both English and Hindi/Hinglish scam phrases (*"loss bilkul nahi hoga", "paise double ho jayenge", "pakka profit"*). | Offline / Online |
| 3 | **Negative Context & Educational Filtering** | Excludes educational warnings, disclaimer citations, news reporting, and regulatory advisories from triggering false-positive risk scores. | Offline / Online |
| 4 | **Vision OCR & Image Evidence Mapper** | Local in-memory EasyOCR pipeline that extracts text from chat screenshots and overlays color-coded bounding boxes directly onto matched scam phrases. | Offline / Online |
| 5 | **OCR Quality vs. Risk Separation** | OCR clarity score (0–100%) is strictly separated from threat severity—blurry text never artificially elevates scam risk. | Offline / Online |
| 6 | **Malicious / Remote-Access App Alert** | Context-aware detection of remote desktop software (AnyDesk, TeamViewer, RustDesk) distinguishing legitimate IT support from financial coercion and takeover vectors. | Offline / Online |
| 7 | **Interactive Incident Response Mode** | Emergency 7-step remediation protocol for victims who already shared AnyDesk codes or transferred funds, with one-click emergency hotlines. | Offline / Online |
| 8 | **Safe APK Inspector (Read-Only)** | Zero-execution static analysis of Android `.apk` files parsing ZIP headers, SHA-256 hashes, `AndroidManifest.xml`, and native architectures without running code. | Offline / Online |
| 9 | **Multi-Screenshot Scam Journey Mapper** | Detects progression across 8 documented fraud funnel stages (Hook → Trust → Investment → Group Isolation → Deposit → Paper Profit → Tier Upgrade → Extortion). | Offline / Online |
| 10 | **Live Evidence Verification (Tavily)** | Researches factual claims in real time against official regulatory databases (`sebi.gov.in`, `rbi.org.in`, `scores.gov.in`, `cybercrime.gov.in`). | Online (with graceful offline fallback) |

---

## 🏗️ Core Architecture & Flow

```
                      USER INPUT
      (Paste Message / Upload Screenshot / Safe APK)
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
   [Vision OCR Pipeline]          [Text Input Pipeline]
   - Blur & Contrast Prep         - Unicode Normalization
   - In-Memory EasyOCR            - Multilingual Matching
   - OCR Clarity Score            - Sensitive Data Masking
         │                                 │
         └────────────────┬────────────────┘
                          ▼
            [Deterministic Rule Engine]  <--- SOLE SOURCE OF TRUTH
            ├── 12 Threat Categories
            ├── Hindi / Hinglish Matching
            ├── Educational Exemption Filter
            └── Remote-Access Context Classifier
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   [Risk Score 0-100]  [Evidence Bounding Boxes]  [Safe Action Gate]
   - HIGH (45-100)     - Direct Visual Overlays   - STOP_AND_VERIFY
   - SUSPICIOUS (20-44) - Exact Text Highlights    - Refusal Protocol
   - LOW (0-19)
                          │
                          ▼
        [Live Evidence Layer (Tavily Search)]  <--- RESEARCH ONLY
        ├── Regulatory Domain Prioritization (sebi.gov.in, rbi.org.in)
        ├── Evidence Extraction & Claim Comparison
        └── Four Statuses: VERIFIED / CONTRADICTED / NOT_VERIFIED / UNABLE
                          │
                          ▼
             [4-Step Investor Reading Flow]
             1. Why Flagged (Visual Evidence & Phrases)
             2. Claim Verification (Regulatory Records)
             3. Safe Action Gate (Prevent Harm)
             4. Safe Next Steps (Helplines & Remediation)
```

### ⚖️ Architectural Guarantees & Hackathon Guardrails

1. **The LLM Never Decides Risk**: The application NEVER passes a user message to an LLM asking *"Is this a scam?"*. All scoring, categorization, and threshold decisions are deterministic Python code.
2. **100% Offline Capability**: If no internet access or API key is available, the core analyzer, OCR vision pipeline, and APK inspector function completely offline with zero degradation in risk detection.
3. **No Fake Evidence / Zero Hallucination**: Every displayed source link and quote originates from actual retrieved search records. If no record is found, SachCheck honestly reports `NOT_VERIFIED` rather than guessing.
4. **Honest Uncertainty**: `NO SEARCH RESULT ≠ FALSE` and `NO SEARCH RESULT ≠ SCAM`. Absence of evidence is presented neutrally without bias.
5. **Registration ≠ Endorsement**: Corroborating a company in the SEBI directory verifies registration status, but SachCheck explicitly warns that *registration never guarantees safety or returns*.
6. **Zero Screenshot Retention**: Uploaded images are processed strictly in volatile RAM and immediately discarded. No user data is stored on disk or in databases.

---

## 🎯 Detailed Feature Breakdown

### 1. ✍️ Financial Message Analyzer (Mode A)
- **Instant Analysis**: Paste raw text from SMS, WhatsApp chats, Telegram channels, Instagram DMs, or emails.
- **Quick-Test Samples**: One-click benchmark examples for instant evaluation:
  - `💡 100% Guaranteed Profit` (High-return capital doubling scam)
  - `💡 AnyDesk Remote Support` (Urgent KYC withdrawal account freeze)
  - `💡 SEBI Advisory Claim` (Genuine broker registration lookup)
- **Privacy Masking**: Detects and highlights sensitive tokens (OTPs, PINs, passwords, bank account numbers, UPI IDs, Aadhaar, PAN) and informs the user prior to analysis.

### 2. 📸 Vision OCR & Image Evidence Highlighting (Mode B)
- **Local OCR Extraction**: Uses EasyOCR directly on CPU/GPU without sending images to third-party cloud vision APIs.
- **Instant Preview**: Collapsible image preview cards let users inspect single or multi-page screenshots.
- **OCR Clarity Meter**: Displays image readability (e.g. `85% Clarity`) separately from scam risk score (`70/100 High Risk`).
- **Interactive Correction**: Extracted text is displayed in an editable review area, enabling users to correct optical errors before triggering analysis.
- **Visual Bounding Boxes**: Overlays color-coded bounding boxes directly onto the screenshot in Step 1 (*Why This Was Flagged*), allowing users to immediately spot exact phrases of concern on their chat interface.

### 3. 📦 Safe APK Inspector (Mode C)
- **Read-Only Static Archive Analysis**: Safe, zero-execution inspection of third-party Android application packages (`.apk` / `.zip`).
- **Cryptographic Verification**: Computes SHA-256 hash digest for cross-referencing with threat databases.
- **Structural Integrity**: Checks for `AndroidManifest.xml`, validates ZIP directory traversal boundaries, counts compiled DEX executables (`classes.dex`), and inspects native architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
- **Zero-Execution Guarantee**: Files are never unpacked to disk, executed, or emulated. Clean archive metadata includes an explicit warning that only official app stores should be trusted.

### 4. 🛡️ Malicious & Remote-Access App Alert System
- **Context-Aware Classification**: Distinguishes between legitimate IT support (e.g. *"Our office uses AnyDesk for printer setup"*) and financial coercion (e.g. *"Install AnyDesk to unblock your trading withdrawal"*).
- **Targeted Application Signatures**:
  - AnyDesk (`anydesk`, `any desk`, `9-digit code`, `anydesk address`)
  - TeamViewer (`teamviewer`, `team viewer`, `quicksupport`)
  - RustDesk (`rustdesk`, `rust desk`)
  - UltraViewer, Splashtop, Chrome Remote Desktop, AirDroid
- **Critical Stop Conditions (`STOP_AND_VERIFY`)**:
  - `Remote Access + Credential Solicitation (OTP / PIN / Password)` → **Immediate Account Takeover Risk**
  - `Remote Access + Financial Context + Payment Demands` → **Advance Fee Fraud Funnel**
  - `Unknown APK + Financial Account + Credential Request` → **Mobile Banking Trojan**
  - `Remote Access + High-Pressure Urgency + Financial Action` → **Coercive Takeover**
- **Interactive 7-Step Remediation Workflow**: Immediate toggle for victims to disconnect network, revoke accessibility/device administrator permissions, uninstall applications, freeze bank/broker accounts, reset passwords from an uninfected device, and dial 1930.

### 5. 🛑 Safe Action Gate
Detects specific actionable demands within the message and provides decisive barrier alerts:
- `APP_INSTALLATION`: Warns against third-party sideloaded APKs.
- `CREDENTIAL_SHARING`: Blocks sharing of OTPs, UPI PINs, passwords, and 2FA tokens.
- `PAYMENT`: Warns against irreversible peer-to-peer UPI and personal bank transfers.
- `JOIN_EXTERNAL_GROUP`: Identifies boiler-room syndicate funnels into private Telegram/WhatsApp VIP groups.
- `LINK_CLICK`: Warns on suspicious URL shorteners (`bit.ly`, `tinyurl`) and unverified domains.
- `PERSONAL_DATA_SHARING`: Advises against sharing PAN, Aadhaar, or bank statements in informal chats.
- `INVESTMENT_ACTION`: Refuses speculative trading on unsolicited stock tips.

### 6. 🗺️ Multi-Screenshot Scam Journey Mapper
When multiple screenshots from the same conversation are uploaded, SachCheck evaluates progression across the 8 classic stages of cyber-investment fraud:
1. **Initial Contact**: Cold outreach or social media engagement.
2. **Trust Building**: Impersonating registered entities or claiming institutional backing.
3. **Investment Opportunity**: High-return promises, algorithmic arbitrage, or insider tips.
4. **Group / App Isolation**: Moving the victim into private channels or custom APKs.
5. **Trial Deposit**: Small initial transfer to establish payment habits.
6. **Simulated Paper Profit**: Fabricated dashboard gains to induce false confidence.
7. **Tier Upgrade / Pressure**: Demanding larger capital to unlock higher VIP tiers.
8. **Withdrawal Extortion**: Blocking withdrawals and demanding clearance taxes or fees.

### 7. 🌐 Live Evidence-Based Claim Verification (Tavily)
- **Targeted Query Generation**: Automatically extracts entity names, SEBI registration numbers, broker domains, and UPI IDs, generating surgical search queries (e.g. `site:sebi.gov.in "Kotak Securities"`).
- **Official Domain Prioritization**:
  - Regulators: `sebi.gov.in`, `scores.gov.in`, `investor.sebi.gov.in`, `rbi.org.in`, `sachet.rbi.org.in`
  - Law Enforcement & Government: `cybercrime.gov.in`, `i4c.gov.in`, `mha.gov.in`, `gov.in`, `nic.in`
  - Recognized Exchanges: `nseindia.com`, `bseindia.com`, `mcxindia.com`
- **Side-by-Side Corroboration**: Displays *"What the source establishes"* vs. *"What it does NOT establish"*.
- **Four Clear Verification States**:
  - `VERIFIED`: Confirmed by official regulatory directories.
  - `CONTRADICTED`: Directly refuted by regulatory warnings or caution lists.
  - `NOT_VERIFIED`: Insufficient public evidence retrieved.
  - `UNABLE_TO_VERIFY`: Live research offline or network timeout.

### 8. 🛡️ Financial Advice Guardrail
SachCheck strictly declines to provide financial advice, price predictions, or stock recommendations (*"Should I buy Tata Motors?"* or *"Will Nifty go up tomorrow?"*). It issues a clear policy refusal notice and redirects users to SEBI-registered Research Analysts (RAs) and Investment Advisers (IAs).

---

## 📌 Threat Categories & Scoring Matrix

Every message is scored deterministically without double-counting within the same category:

| Category | Score | Severity | Description & Example Patterns |
|---|:---:|:---:|---|
| **Guaranteed / Certain Returns** | `+30` | High | Claims of 100% profit, fixed returns, zero loss, capital doubling (*"100% profit", "paise double ho jayenge", "guaranteed 40%", "no loss"*). |
| **Payment Request** | `+25` | High | Demands to transfer funds to personal UPI IDs or unverified accounts (*"Send ₹10,000", "UPI pe payment bhejo", "deposit to profit@paytm"*). |
| **Withdrawal Fee / Extortion** | `+25` | High | Advance fee, clearance tax, or deposit demanded to unblock funds (*"pay ₹5,000 fee to withdraw", "account frozen deposit"*). |
| **Credential Request** | `+25` | High | Solicitations for OTPs, PINs, passwords, or 2FA credentials (*"share your OTP", "send mPIN", "provide password"*). |
| **Authority / Impersonation** | `+20` | Medium | Unverified claims of regulator endorsement (*"SEBI approved scheme", "RBI certified plan"*). Standalone mentions of SEBI in educational context do not trigger. |
| **Suspicious Link Patterns** | `+20` | Medium | Obfuscated links or suspicious TLDs (*bit.ly, tinyurl, t.me, .xyz, .top, .vip*). |
| **App Installation Request** | `+20` | High | Solicitations to download custom APKs or remote desktop tools (*"download this APK", "install AnyDesk"*). |
| **Urgency / FOMO** | `+15` | Medium | Coercive psychological pressure (*"URGENT", "act now", "sirf aaj", "only 5 slots left", "limited time"*). |
| **Manipulative Trading Language** | `+15` | Medium | Claims of insider operators, guaranteed breakouts, or jackpot calls (*"operator tip", "sure shot breakout", "insider news"*). |
| **Fake Profit / Proof** | `+15` | Medium | Fabricated balance screenshots, bank receipts, or profit cards (*"today's profit ₹50,000", "daily profit proof"*). |
| **External Group Invitation** | `+10` | Low | Pressure to move to private channels (*"join our VIP Telegram", "join WhatsApp group"*). |
| **Referral Pressure** | `+10` | Low | Pyramid or multi-level recruitment bonuses (*"refer 5 friends to earn ₹1,000 bonus"*). |

### Deterministic Risk Thresholds
- **LOW RISK** (`0 – 19` pts): Informational or educational messages; no compounding red flags.
- **SUSPICIOUS** (`20 – 44` pts): Contains one significant red flag (e.g. payment request or unverified authority claim).
- **HIGH RISK** (`45 – 100` pts): Compounding threat signals present (e.g. guaranteed return + payment + urgency).
- **Score Cap**: Deterministic score is strictly bounded between `0` and `100`.

---

## 🎨 Design System & UI Architecture

The presentation layer of SachCheck follows modern fintech safety standards:
- **Theme**: Clean light theme (`#FFFFFF` cards, soft `#F6F8FB` canvas, deep navy `#0F172A` typography, trust-blue `#2563EB` primary accent).
- **Accessibility**: 100% WCAG AA compliant text contrast across all states.
- **Risk Colors**: High Risk (`#DC2626` on `#FEF2F2`), Suspicious (`#D97706` on `#FFFBEB`), Low Risk (`#16A34A` on `#F0FDF4`). Every risk state pairs an icon, score, and label.
- **4-Step User Reading Flow**:
  1. **Why This Was Flagged**: Visual annotated screenshot bounding boxes and matched phrase cards.
  2. **Claim Verification**: Side-by-side regulatory corroboration from official sources.
  3. **Safe Action Gate**: Explicit directives for detected actionable commands.
  4. **Safe Next Steps**: Targeted investor guidance, remediation workflows, and hotlines.
- **Compact Sidebar**: Live research status pill, session metrics (Scans, High Risk, Low Risk), and advanced API override settings.

---

## 📁 Project Directory Structure

```
SachCheck/
├── app.py                         # Streamlit application UI & interactive workflows
├── config.py                      # Configuration, environment variables, & domain registries
├── evaluate.py                    # Benchmark runner evaluating 28 labeled test cases
├── requirements.txt               # Production dependencies (Streamlit, EasyOCR, Pillow, Tavily)
├── .env.example                   # Environment variable template
├── README.md                      # Comprehensive project documentation
│
├── .streamlit/
│   └── config.toml                # Streamlit UI theme configuration
│
├── analyzer/                      # Phase 1: Deterministic Risk Engine & Safety Gates
│   ├── __init__.py                # Package exports
│   ├── models.py                  # Strongly typed data models (RiskScore, Indicator, etc.)
│   ├── rules.py                   # 12 Threat rules, regexes, and negative context exemptions
│   ├── scoring.py                 # Mathematical score computation, thresholding & capping
│   ├── analyzer.py                # Main deterministic orchestrator
│   ├── action_gate.py             # Action Gate identifying actionable commands (payment, APK, OTP)
│   ├── remote_access_apps.py      # Remote Desktop capability knowledge base & context analyzer
│   ├── apk_analyzer.py            # Zero-execution read-only static APK archive inspector
│   ├── privacy.py                 # Privacy auditor & sensitive token redaction
│   └── scam_journey.py            # Multi-screenshot 8-stage fraud funnel mapper
│
├── ocr/                           # Modular Computer Vision Pipeline
│   ├── __init__.py                # Package exports
│   ├── models.py                  # OCRBox, OCRResult dataclasses
│   ├── preprocessor.py            # Grayscale, contrast adjustment & blur detection
│   ├── provider.py                # BaseOCRProvider, EasyOCRProvider, MockOCRProvider
│   ├── service.py                 # OCR Service & visual bounding box rendering
│   └── structure.py               # Chat structure parsing (bubbles, timestamps, senders)
│
├── research/                      # Phase 2: Live Web Research using Tavily
│   ├── __init__.py                # Package exports
│   ├── models.py                  # SourceRecord, ClaimVerificationResult dataclasses
│   ├── researcher.py              # Research orchestration & query dispatching
│   ├── claim_extractor.py         # Entity, URL, and factual claim extraction
│   ├── entity_extractor.py        # Regex extractors for SEBI numbers, companies, UPI IDs
│   ├── source_filter.py           # Domain classification & official source prioritization
│   ├── evidence.py                # Claim ↔ Evidence comparison & status resolution
│   └── providers/
│       ├── __init__.py
│       └── tavily_provider.py     # Tavily SDK integration with caching & error handling
│
├── utils/
│   ├── highlighting.py            # Safe HTML highlighting & XSS escaping
│   └── ui_theme.py                # CSS styles, SVG score gauges, and UI component helpers
│
├── data/
│   ├── sample_messages.py         # 28 labeled synthetic test cases (EN + Hinglish)
│   └── sample_screenshots/        # Synthetic benchmark chat screenshots
│       ├── sample_guaranteed_profit.png
│       └── sample_anydesk_fraud.png
│
└── tests/                         # Comprehensive Automated Test Suite (87 tests)
    ├── test_analyzer.py           # 30 tests for deterministic rule engine & scoring
    ├── test_guardrails.py         # 7 tests for financial advice guardrail
    ├── test_remote_access_alert.py# 14 tests for remote-access detection & APK inspection
    ├── test_research.py           # 21 tests for Tavily research provider & domain filtering
    └── test_screenshot_profiler.py# 15 tests for OCR vision pipeline & scam journey
```

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10, 3.11, 3.12, 3.13, or 3.14
* Recommended: Virtual environment (`venv` or `conda`)
* Operating System: macOS, Linux, or Windows

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/your-repo/SachCheck.git
cd SachCheck

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 2. Configure Environment (Optional for Live Tavily Search)
To enable live web research against official regulatory registries:
```bash
cp .env.example .env
```
Edit `.env` to include your Tavily API key:
```env
TAVILY_API_KEY=tvly-your_api_key_here
```
> **Note**: An API key is **NOT required** for the core analyzer, screenshot OCR, APK inspection, or deterministic scoring. If omitted, SachCheck operates seamlessly in Offline Mode.

### 3. Launch the Application
```bash
streamlit run app.py
```
Open **[http://localhost:8501](http://localhost:8501)** in your web browser.

---

## 🧪 Testing & Quality Assurance

### 1. Automated Test Suite (87 Tests)
Run the full pytest suite covering all modules:
```bash
python3 -m pytest -v
```
Output:
```
tests/test_analyzer.py ..............................                    [ 34%]
tests/test_guardrails.py .......                                         [ 42%]
tests/test_remote_access_alert.py ..............                         [ 58%]
tests/test_research.py .....................                             [ 82%]
tests/test_screenshot_profiler.py ...............                        [100%]

============================== 87 passed in 0.52s ==============================
```

### 2. Synthetic Dataset Evaluation Benchmark
SachCheck evaluates against 28 pre-labeled synthetic benchmark cases across English and Hinglish:
```bash
python3 evaluate.py
```
Output:
```
======================================================================
  INTERNAL SYNTHETIC TEST-SET EVALUATION
======================================================================
Total Synthetic Cases : 28
Correctly Classified : 28
Incorrectly Classified: 0
Accuracy Rate         : 100.0%
False Positives       : 0
======================================================================
```

---

## ⚖️ Investor Safety & Cybercrime Helplines

If you or someone you know has been targeted by financial fraud:

* **National Cyber Crime Reporting Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
* **National Cybercrime Helpline**: Dial **1930** (Toll-Free, 24/7)
* **SEBI SCORES Portal**: [scores.gov.in](https://scores.gov.in)
* **SEBI Toll-Free Investor Helpline**: Dial **1800 22 7575** / **1800 266 7575**
* **RBI Sachet Portal**: [sachet.rbi.org.in](https://sachet.rbi.org.in)
* **Chakshu (DoT Fraud Communications Portal)**: [sancharsaathi.gov.in/sfc](https://sancharsaathi.gov.in/sfc)

---

## 📜 Disclaimer

*SachCheck is an automated cyber-defense and educational verification tool engineered for the SANGYAN Investor Resilience Hackathon. Risk scores and claim corroboration are generated deterministically based on predefined threat indicators and public regulatory registries. SachCheck does NOT provide financial advice, stock recommendations, or commercial warranties. Always verify investment opportunities through SEBI-registered intermediaries.*
