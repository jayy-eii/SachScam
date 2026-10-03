# 🛡️ SachCheck — Investor Safety Platform
> Built for the **SANGYAN Investor Resilience Hackathon**

SachCheck is an investor-protection system engineered to safeguard retail investors from common financial scams, pump-and-dump syndicates, unauthorized advisory channels, fraudulent screenshot funnels, and deceptive social-media investment solicitations.

---

## 📸 Features: Screenshot Profiler & Malicious / Remote-Access App Alert

SachCheck provides an advanced defensive suite for retail investors:
1. **📸 Analyze Screenshot**: Local OCR-powered screenshot and chat risk profiler for WhatsApp, Telegram, forwarded messages, and social media.
2. **✍️ Paste Message**: Instant text-based deterministic threat profiler with Hindi / Hinglish linguistic recognition.
3. **📦 Safe APK Inspector (Read-Only)**: Zero-execution static inspection of third-party Android APK archives.
4. **🛡️ Malicious / Remote-Access App Alert**: Context-aware detection of remote desktop software (AnyDesk, TeamViewer, RustDesk) and unknown APK solicitations.

---

## 🛡️ Feature: Malicious / Remote-Access App Alert

The **Remote-Access App Alert** detects situations where a financial solicitation or chat conversation asks the user to:
- Install remote-access applications (AnyDesk, TeamViewer, RustDesk, QuickSupport, etc.)
- Share remote-access session codes or connection IDs
- Grant remote-control or screen-sharing permissions to an unverified caller or sender
- Install unknown Android APKs outside official app stores
- Grant device administrator or accessibility permissions

### ⚖️ Core Principle: App Capability vs. Message Context Abuse
> **CRITICAL DISTINCTION**:
> SachCheck **NEVER** classifies legitimate remote-access software (such as AnyDesk, TeamViewer, or RustDesk) as malware or scam tools.
> Remote-access applications are authentic, widely used IT management utilities.
> Instead, SachCheck evaluates **HOW THE APPLICATION IS BEING USED IN THE MESSAGE CONTEXT**:
> - Legitimate internal IT / printer support → **INFORMATIONAL / LOW CAUTION** (no scam accusation).
> - Solicited to "fix" a trading or bank account → **HIGH CAUTION**.
> - Combined with demands for OTP / PIN / Password → **STOP AND VERIFY (Immediate Takeover Risk)**.
> - Combined with demands for fee / payment transfers → **STOP AND VERIFY (Fraud Funnel)**.

### 🛑 Special Stop Conditions (`STOP_AND_VERIFY`)
The system triggers an emergency stop state under 4 critical combinations:
1. **Remote Access + Credential Solicitation (OTP / PIN / Password)**: Immediate account takeover vector.
2. **Remote Access + Financial Context + Payment Demands**: Advance fee fraud funnel.
3. **Unknown APK + Financial Account + Credential Request**: Mobile banking trojan / credential harvest vector.
4. **Remote Access + High-Pressure Urgency + Financial Action**: High-pressure coercion funnel.

### 📦 Safe Read-Only Static APK Inspector
For inspecting suspicious `.apk` files directly:
- **Zero Execution**: The file is NEVER executed, installed, or run in any environment.
- **Pure Static Metadata**: Parses ZIP header, computes SHA-256 cryptographic digest, verifies presence of `AndroidManifest.xml`, counts compiled `.dex` files, and detects compiled native architectures (`lib/arm64-v8a`, etc.).
- **Security Notice**: Explicitly emphasizes that clean archive metadata does not guarantee the absence of malicious code and instructs users to only install applications from official stores (Google Play / App Store).

### 🚨 Interactive Incident Response Mode
For users who already granted remote access or shared an AnyDesk ID:
- An interactive toggle in the UI immediately provides an emergency 7-step remediation workflow:
  1. *End remote session immediately (close AnyDesk/TeamViewer or disconnect Wi-Fi/Mobile Data).*
  2. *Uninstall the remote-access software.*
  3. *Review installed apps and device accessibility / admin permissions.*
  4. *Check bank and demat accounts for unauthorized activity.*
  5. *Change passwords and UPI PINs from an independent, clean device.*
  6. *Contact bank/broker emergency helplines to freeze accounts.*
  7. *Dial 1930 or report at cybercrime.gov.in.*

---

---

## 🏗️ Architecture Overview

SachCheck operates a dual-layer architecture where **deterministic rule analysis** is paired with **authentic live web research** and **computer vision**:

1. **Two Input Modes**:
   * **📸 Analyze Screenshot**: Upload single or multiple chat screenshots (PNG, JPG, JPEG, WEBP).
   * **✍️ Paste Message**: Paste raw message text from WhatsApp, Telegram, SMS, or social media.
2. **Deterministic Risk Score**: A 0–100 explainable indicator score calculated strictly by Python rules.
3. **OCR Quality vs Risk Separation**: OCR confidence (e.g. `82%`) is displayed separately from Risk Score (`72/100`) and never artificially blended into fraud likelihood.
4. **Visual Evidence Highlighting**: Color-coded bounding boxes are drawn on the screenshot only where matched text actually exists—never inventing fake bounding boxes.
5. **Multi-Screenshot Scam Journey**: Progressively analyzes multi-screenshot conversations across 8 documented fraud funnel stages.

### ⚖️ Core Architectural Guarantees
1. **The LLM and search engine NEVER decide risk levels or scam verdicts**: The deterministic rule engine is the sole source of truth for the risk score.
2. **Phase 1 remains 100% offline**: If Tavily is unconfigured or unavailable, the core analyzer and OCR continue to function without interruption.
3. **No Fake Evidence / Zero Hallucination**: Every displayed source originates from actual retrieved Tavily search results. If no search results are found, the system reports `NOT_VERIFIED` rather than fabricating evidence.
4. **Honest Uncertainty**: `NO SEARCH RESULT ≠ FALSE` and `NO SEARCH RESULT ≠ SCAM`. If OCR fails, the platform reports `Text could not be reliably extracted` rather than inventing missing text.
5. **Registration ≠ Endorsement**: Finding an entity in the SEBI directory verifies registration status, but NEVER implies government endorsement or guaranteed safety.
6. **Zero Screenshot Retention**: Uploaded screenshots are processed in memory and never permanently stored on disk.

---

## 📌 Threat Categories & Scoring

Every indicator is evaluated deterministically without double-counting:

| Category | Score | Severity | Description / Examples |
|---|:---:|:---:|---|
| **Guaranteed / Certain Returns** | `+30` | High | Claims of 100% profit, fixed returns, zero loss, capital doubling (*"100% profit", "paise double ho jayenge", "guaranteed 40%"*). |
| **Payment Request** | `+25` | High | Requests to transfer money to personal accounts, unverified UPI IDs, registration fees (*"Send ₹10,000", "UPI pe payment bhejo"*). |
| **Withdrawal Fee / Extortion** | `+25` | High | Advance fee, clearance tax, or deposit demanded to release profits (*"pay ₹5,000 fee to withdraw", "account frozen deposit"*). |
| **Credential Request** | `+25` | High | Solicitations for OTPs, PINs, or passwords (*"share your OTP", "send mPIN"*). |
| **Authority / Impersonation** | `+20` | Medium | Unverified claims of regulator endorsement (*"SEBI approved tip", "RBI certified plan"*). Standalone *"SEBI"* does not trigger. |
| **Suspicious Link Patterns** | `+20` | Medium | Shortened or obfuscated links (*bit.ly, tinyurl, unverified Telegram group links*). |
| **App Installation Request** | `+20` | High | Requests to install custom APKs or third-party software outside official app stores (*"download this APK"*). |
| **Urgency / FOMO** | `+15` | Medium | High-pressure psychological tactics (*"URGENT", "act now", "sirf aaj", "only 5 slots remaining"*). |
| **Manipulative Trading Language** | `+15` | Medium | Promises of insider intelligence, operator breakouts, or jackpot calls (*"operator tip", "sure shot breakout"*). |
| **Fake Profit / Proof** | `+15` | Medium | Fabricated balance screenshots or profit proofs (*"today's profit ₹50,000", "daily profit proof"*). |
| **External Group Invitation** | `+10` | Low | Requests to move to private channels (*"join our VIP Telegram", "join WhatsApp group"*). |
| **Referral Pressure** | `+10` | Low | Multi-level recruitment incentives (*"refer 5 friends to earn bonus"*). |

### Deterministic Risk Levels (0–100)
* **LOW Risk** (`0 – 19` pts): Low risk indicators detected. No high-risk indicators or minimal single urgency cues.
* **MEDIUM Risk** (`20 – 44` pts): Medium risk indicators detected. Contains one major red flag (e.g. payment request or authority claim).
* **HIGH Risk** (`45 – 100` pts): High risk indicators detected. Compounding signals present (e.g. guaranteed return + payment + urgency).
* **Score Capping**: Final score is capped at `100/100`.

---

## 🛑 Safe Action Gate

The **Safe Action Gate** detects specific actionable requests inside messages and provides targeted investor protection directives:

* `APP_INSTALLATION`: Alerts on third-party APK downloads bypassing Google Play / App Store.
* `CREDENTIAL_SHARING`: Blocks sharing of OTPs, UPI PINs, or banking passwords.
* `PAYMENT`: Warns against irreversible UPI or personal account transfers.
* `JOIN_EXTERNAL_GROUP`: Advises on boiler-room syndicate tactics in closed Telegram / WhatsApp groups.
* `LINK_CLICK`: Evaluates unverified or shortened URLs.
* `PERSONAL_DATA_SHARING`: Warns against sharing PAN, Aadhaar, or bank statements in informal chats.
* `INVESTMENT_ACTION`: Refuses speculative trading on unsolicited tips.

---

## 🗺️ Multi-Screenshot Scam Journey Mapper

When multiple screenshots from the same conversation are uploaded, SachCheck maps evidence across 8 documented fraud stages:

1. **Initial Contact**: Unsolicited outreach from an unknown number or cold contact.
2. **Trust Building**: Fictitious regulatory credentials or senior mentor claims.
3. **Investment Opportunity**: High-return promises, guaranteed profits, or algorithmic signals.
4. **Group / App Invitation**: Isolating the victim into a private VIP Telegram channel or custom APK.
5. **Deposit Request**: Small trial investment or registration fee.
6. **Profit Claim**: Simulated paper gains on a fake dashboard.
7. **Additional Payment**: Escalating pressure to invest larger capital to upgrade tiers.
8. **Withdrawal Problem / Extortion**: Demanding advance taxes or clearance fees to release funds.

> **Principle**: Only stages supported by actual extracted text are displayed. If evidence is insufficient, the system explicitly reports that no structured multi-stage progression was found.

---

## 🌐 Phase 2: Live Evidence-Based Claim Verification (Tavily)

1. **Targeted Query Generation**: Queries are targeted (e.g. `site:sebi.gov.in "ABC Capital"`) with credentials strictly redacted.
2. **Official Regulatory Priority**:
   * `sebi.gov.in`, `scores.gov.in`, `investor.sebi.gov.in`
   * `rbi.org.in`, `sachet.rbi.org.in`
   * `cybercrime.gov.in`, `i4c.gov.in`, `gov.in`
   * Recognized exchanges (`nseindia.com`, `bseindia.com`)
3. **Verification Statuses**:
   * `VERIFIED`: Directly corroborated by official regulatory directories.
   * `CONTRADICTED`: Conflicts directly with regulatory records or caution lists.
   * `NOT_VERIFIED`: Insufficient public evidence retrieved.
   * `UNABLE_TO_VERIFY`: Live research unconfigured or network timeout.
4. **Registration ≠ Endorsement**: Confirmed registration explicitly notes that SEBI registration never implies government endorsement or guaranteed returns.

---

## 🔒 Privacy & Data Handling

* **In-Memory Processing**: Uploaded screenshots are processed in memory and never stored permanently on disk.
* **Sensitive Token Detection**: Automatically detects and warns about OTPs, PINs, passwords, bank account numbers, debit/credit cards, Aadhaar, and PAN.
* **Query Redaction**: Strips sensitive authentication credentials before making external web queries.
* **No ID Demands**: SachCheck never requires personal identity documents from users.

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.13, 3.14 on macOS, Linux, and Windows)

### 1. Installation
```bash
git clone <repository_url>
cd SachCheck
pip install -r requirements.txt
```

### 2. Configure Environment (Optional for Live Tavily Web Search)
```bash
cp .env.example .env
```
Edit `.env`:
```env
TAVILY_API_KEY=tvly-your_api_key_here
```
*(If no API key is set, SachCheck runs seamlessly in Offline Evaluation Mode.)*

### 3. Launch the Streamlit Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🧪 Automated Test Suite

SachCheck includes a comprehensive automated test suite with **87 unit and integration tests**:

```bash
python3 -m pytest -v
```

### Covered Test Suites:
- `tests/test_remote_access_alert.py`: 14 tests for Remote Access, APK Inspection, Stop Conditions, Benign IT Contexts, Multilingual Hindi/Hinglish, and Incident Response.
- `tests/test_screenshot_profiler.py`: 15 tests for OCR pre-processing, chat structure, privacy redaction, and multi-screenshot scam journeys.
- `tests/test_analyzer.py`: 30 tests for deterministic risk engine, categories, thresholds, and negative contexts.
- `tests/test_research.py`: 21 tests for Tavily search provider, domain filtering, and claim verification.
- `tests/test_guardrails.py`: 7 tests for investor protection advice guardrails.

### Covered Remote-Access Alert Scenarios (Section 27):
1. ✅ **TEST 1**: `"Install AnyDesk and send me the code."` (Detects AnyDesk, install action, session code request, warns of remote capability without labeling app as malware).
2. ✅ **TEST 2**: `"Install AnyDesk and I'll fix your trading account."` (Detects AnyDesk, financial context, account-fix claim, flags HIGH_CAUTION).
3. ✅ **TEST 3**: `"Install AnyDesk and send OTP/PIN."` (Detects AnyDesk + OTP/PIN credential request, triggers STOP_AND_VERIFY).
4. ✅ **TEST 4**: `"Download this APK to unlock your withdrawal."` (Detects APK request, financial withdrawal context, flags HIGH_CAUTION).
5. ✅ **TEST 5**: `"Pay ₹5,000 and install TeamViewer so I can process your refund."` (Detects payment request, TeamViewer, refund context, triggers STOP_AND_VERIFY).
6. ✅ **TEST 6**: `"Our office uses TeamViewer for internal IT support."` (Distinguishes legitimate IT usage, assigns INFORMATIONAL/LOW_CAUTION with zero scam accusations).
7. ✅ **TEST 7**: `"Use AnyDesk to help me fix my printer."` (Distinguishes non-financial usage, assigns INFORMATIONAL/LOW_CAUTION).
8. ✅ **TEST 8**: Hindi: `"AnyDesk install karo aur ID bhejo."` (Detects AnyDesk, session ID request in Hindi).
9. ✅ **TEST 9**: Hinglish: `"Sir trading account unlock karne ke liye TeamViewer install karke access de do."` (Detects TeamViewer, financial context, account access request, flags HIGH_CAUTION).
10. ✅ **TEST 10**: Blurry screenshot / Low OCR confidence & Safe APK Inspector (Read-only ZIP parsing, SHA256 digest, AndroidManifest validation, zero execution).

### Internal Synthetic Test-Set Evaluation
Run the evaluation script on the 28 labeled synthetic test cases:
```bash
python3 evaluate.py
```
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

## 📁 Project Directory Structure

```
SachCheck/
├── app.py                     # Streamlit UI (Screenshot, Paste, and APK Inspector modes)
├── config.py                  # Environment config & official domain registry
├── evaluate.py                # Synthetic evaluation runner (28 cases)
├── requirements.txt           # Dependencies (Streamlit, EasyOCR, Pillow, Tavily, Pytest)
├── .env.example               # Template environment configuration
├── README.md                  # Documentation and architecture guide
│
├── ocr/                       # Modular OCR Vision Pipeline
│   ├── __init__.py            # Package exports
│   ├── models.py              # OCRBox, OCRResult dataclasses
│   ├── preprocessor.py        # Blur detection, scaling, contrast enhancement
│   ├── provider.py            # BaseOCRProvider, EasyOCRProvider, MockOCRProvider
│   ├── service.py             # OCRService & Visual Evidence Bounding Box Highlighting
│   └── structure.py           # ChatStructureDetector, ChatMessage, Timestamps & Senders
│
├── analyzer/                  # Phase 1: Deterministic Risk Engine & Defense Gates
│   ├── __init__.py            # Package exports
│   ├── remote_access_apps.py  # Remote Access Capability Reference & Context Analyzer
│   ├── apk_analyzer.py        # Safe read-only static APK inspector (zero execution)
│   ├── action_gate.py         # Safe Action Gate & remote action solicitations
│   ├── rules.py               # 12 Predefined threat rules & negative context patterns
│   ├── analyzer.py            # Main analysis orchestrator
│   ├── scoring.py             # Score computation, capping at 100 & thresholds
│   ├── privacy.py             # PrivacyAuditor & credential redaction
│   ├── scam_journey.py        # Multi-screenshot 8-stage scam journey mapper
│   └── models.py              # Strongly-typed analysis dataclasses
│
├── research/                  # Phase 2: Live Web Research using Tavily
│   ├── __init__.py            # Package exports
│   ├── models.py              # SourceRecord, ClaimVerificationResult
│   ├── researcher.py          # Research orchestrator
│   ├── claim_extractor.py     # Claim extraction & targeted query generation
│   ├── entity_extractor.py    # Company, SEBI number, UPI, and URL extraction
│   ├── source_filter.py       # Domain classification & regulator prioritization
│   ├── evidence.py            # Claim ↔ Evidence comparison & status assignment
│   └── providers/
│       └── tavily_provider.py # Tavily SDK integration with error handling & cache
│
├── data/
│   └── sample_messages.py     # 28 labeled synthetic test messages
│
├── utils/
│   └── highlighting.py        # Safe HTML escaping & text highlight utilities
│
└── tests/
    ├── test_remote_access_alert.py # Tests for 10 remote access & APK inspection scenarios
    ├── test_screenshot_profiler.py # Tests for 15 screenshot & OCR profiling scenarios
    ├── test_analyzer.py       # Unit tests for rules and scoring
    ├── test_guardrails.py     # Unit tests for financial advice guardrail
    └── test_research.py       # Unit tests for Tavily research with mock fixtures
```

---

## ⚖️ National Cybercrime Reporting

If you or someone you know has been targeted by financial fraud:
* **National Cyber Crime Reporting Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
* **National Cybercrime Helpline**: Dial **1930**
* **SEBI SCORES Portal**: [scores.gov.in](https://scores.gov.in)
* **RBI Sachet Portal**: [sachet.rbi.org.in](https://sachet.rbi.org.in)
