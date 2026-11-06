# Toroka 🏃‍♂️🇰🇪

> **Toroka** *(Swahili for "run away" / "escape")* is a Kenya-first, evidence-first digital safety and fraud investigation assistant. 

Toroka helps individuals, shoppers, and businesses verify suspicious SMS messages, WhatsApp chats, social media shops, M-PESA payment requests, links, and emails. Talk to Toroka like an AI assistant—paste a message, upload a screenshot, drop email headers, or share a seller's profile, and Toroka delivers a calm, objective, evidence-backed assessment with dated sources, actionable next steps, and complete transparency on what could and could not be verified.

---

## ⚡ Key Highlights

- **Conversational Safety Assistant:** Powered by conversational AI with deterministic rule-based safety backstops. Explains risk factors in plain language without technical jargon or shame.
- **Open Reading Design:** A clean, borderless chat canvas where findings flow naturally as editorial reading text rather than boxed chat bubbles or cluttered cards.
- **Interactive Action Menu (+):** Instant access to targeted workflows:
  - 🔍 **Check a suspicious message:** SMS, WhatsApp, Telegram, or email.
  - 🛍️ **Investigate an online shop:** Instagram, TikTok, Facebook pages, delivery-fee scams.
  - 📞 **Look up a number or website:** M-PESA Till numbers, Paybills, phone numbers, domain names.
  - 🛡️ **I already paid or shared something:** Calm emergency triage and immediate action plan.
  - ✉️ **Full email headers:** Deep email forensic inspection (SPF/DKIM/DMARC, spoofing detection).
- **Decision-First Link & Social Investigation:** Multi-platform URL parser (TikTok, Instagram, Facebook, X, WhatsApp), public TikTok oEmbed metadata context, SSRF-hardened safe website reads, and shopper-facing decision reports featuring warning signs, pre-payment advice, and copyable seller messages.
- **Deep Kenyan Fraud Intelligence:** Purpose-built for local payment vectors:
  - M-PESA "wrong transfer" reversal scams and fake MPESA confirmation SMS.
  - Unregulated deposit requests and "pay delivery fee before dispatch" shop tactics.
  - Impersonation of Safaricom (e.g. fake 333 / SIM swap alerts) and Kenya Revenue Authority (KRA).
  - Job recruitments, task scams, and advance-fee pyramid schemes.
- **Privacy by Default:** No account required. Checks run anonymously, message history stays local to your device, evidence is encrypted with ephemeral retention, and PINs/passwords are never collected.
- **Bilingual (English & Kiswahili):** Full UI and investigation support in both English and Kiswahili (`EN` / `SW` toggle).

---

## 🧭 Verdicts & Assessment Policy

Toroka evaluates evidence deterministically through multi-layered heuristic rules, verified official registries, and machine learning signals. Every investigation returns one of five transparent outcomes:

| Verdict | Meaning | What It Guarantees |
|---|---|---|
| **`high_risk`** | Verified threat indicators found (e.g. requesting M-PESA PIN, impersonating official authorities, known malicious infrastructure). | Explicit danger warning; immediate defensive actions recommended. |
| **`suspicious_verify_first`** | Strong risk signals detected (e.g. newly registered domain, unverified shop requiring upfront deposit, pressure tactics). | Warning to pause and verify through independent official channels before sending money. |
| **`inconclusive`** | Insufficient corroborating evidence to confirm legitimacy or risk. | Cautionary guidance with missing verification steps. |
| **`no_known_threats_found`** | No threat indicators matched across current threat feeds and rules. | **Never a guarantee of safety.** Explains what was checked and what remains unknown. |
| **`verified_official`** | Authenticated channel or domain from a reviewed, dated official registry (e.g. Safaricom, KRA). | Confirms the entity/domain is legitimate. **Never vouches for unauthorized offers or PIN requests.** |

### Radical Transparency
Every report breaks down coverage explicitly:
- **Checked:** Specific databases, rules, and threat feeds that ran successfully.
- **Not Checked:** Checks that were not applicable to the submitted data.
- **Could Not Check:** External lookups that failed, timed out, or were platform-restricted.
- **Official Sources Cited:** Dated references to public statements and regulatory registries.

---

## 🔬 Multi-Phase Intelligence Architecture

Toroka combines deterministic rule engines, OSINT connectors, email forensics, graph correlation, and machine learning:

```
                            [ User Input ]
             (Text, Links, Screenshots, Phone/Till, .eml)
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │   FastAPI Gateway & Auth     │
                   └──────────────┬───────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Email Engine   │    │  Rules Engine    │    │ Connectors / OSINT│
│ • RFC 5322 parser│    │ • Assessment v0.3│    │ • DNS / RDAP age │
│ • DKIM/SPF/DMARC │    │ • M-PESA logic   │    │ • URL redirect   │
│ • Spoofing check │    │ • Shop taxonomy  │    │ • Safe OCR       │
│ • Phishing links │    │ • Swahili rules  │    │ • Threat feeds   │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                   ┌──────────────────────────────┐
                   │    Intelligence Pipeline     │
                   │ • Phase 2: Content Patterns  │
                   │ • Phase 3: Identity Graph    │
                   │ • Phase 4: Campaign Clusters │
                   │ • Phase 5: Observation Fusion│
                   │ • Phase 6: Threat Feed Sync │
                   │ • Phase 7: Historical Memory │
                   │ • ML: Autonomous Classifier  │
                   └──────────────┬───────────────┘
                                  │
                                 ▼
                   ┌──────────────────────────────┐
                   │   Conversational AI Agent    │
                   │ (Gemini + Local Safety Fallback)
                   └──────────────┬───────────────┘
                                  │
                                 ▼
                   ┌──────────────────────────────┐
                   │    Modern Responsive UI     │
                   │ (PWA Shell, English & Swahili)│
                   └──────────────────────────────┘
```

1. **Email Forensics Engine (`services/api/toroka_email_forensics/`)**:
   - Parses RFC 5322 headers and MIME structures.
   - Validates SPF, DKIM, and DMARC authentication headers.
   - Detects display-name impersonation and mismatched `Return-Path` vs `From` headers.
   - Inspects relay hops and extracts embedded URLs for punycode/IDN homograph attacks.
2. **Shop & Seller Intelligence (`services/api/toroka_evidence/`, `app/social_intelligence.py`)**:
   - Evaluates Instagram, TikTok, and web merchant profiles.
   - Assesses contact transparency, payment destination safety, and return policies.
   - Contextual guidance distinguishing safe cash-on-delivery from risky unescrowed deposits.
3. **Correlation & Campaign Clustering (Phases 3–7)**:
   - Privacy-preserving entity hashing (`toroka-v3:{kind}:{digest}`) using HMAC-SHA256.
   - Correlates shared infrastructure (phone numbers, domains, payment handles) across fraud campaigns.
   - Ingests threat feeds (OpenPhish, URLhaus, PhishTank) with automatic deduplication.
4. **Autonomous ML Classifier (`packages/rules/ssi_rules/ml/`)**:
   - Scikit-Learn TF-IDF classifier operating alongside deterministic rules.
   - Shadow evaluation and champion-challenger promotion pipeline.

---

## 📁 Repository Structure

```
smart-scam-identifier/
├── packages/
│   ├── rules/                 # Pure assessment logic, fraud taxonomy, and ML
│   │   ├── ssi_rules/         # Rules engine, signals, shop evaluation, Swahili cues
│   │   │   └── ml/            # Autonomous ML training, models, and telemetry
│   │   └── tests/             # Golden case tests, feature tests, ML tests
│   └── connectors/            # External I/O adapters
│       ├── ssi_connectors/    # DNS, RDAP, URL fetcher, OCR, Web Risk, Places
│       └── tests/             # Connector mock tests
├── services/
│   └── api/                   # FastAPI backend and web application
│       ├── app/               # Core routing, conversational AI agent, and DB models
│       │   ├── ai_agent.py    # Conversational fraud investigator (Gemini / local)
│       │   ├── routes_core.py # Core investigation endpoints
│       │   ├── routes_email.py# Email forensics API
│       │   └── static/        # PWA frontend (HTML, CSS, JS, Service Worker)
│       ├── toroka_build3/     # Build 3 evidence and intelligence connectors
│       ├── toroka_build4/     # Build 4 advanced domain intelligence
│       ├── toroka_email_forensics/ # RFC 5322 header & authentication engine
│       ├── toroka_evidence/   # Evidence store & shop discovery providers
│       ├── toroka_phase3/     # Identity graph & entity correlation
│       ├── toroka_phase4/     # Campaign clustering & syndicate correlation
│       ├── toroka_phase5/     # Cross-source observation fusion
│       ├── toroka_phase6/     # Threat intelligence feeds
│       ├── toroka_phase7/     # Historical case memory & contextual scoring
│       ├── migrations/        # Alembic database migrations
│       └── tests/             # Comprehensive API and integration test suite
├── eval/                      # Benchmark evaluation suite with labelled cases
├── docs/                      # Architecture Decision Records (ADRs) & research
│   ├── adr/                   # ADR-001 (Monolith), ADR-002 (Rules), ADR-003 (Privacy)
│   └── research/              # Kenyan user research plans and interview guides
├── scripts/                   # Operational and live diagnostic utilities
├── web-tests/                 # Playwright end-to-end browser test suite
├── Dockerfile                 # Multi-stage production container
├── docker-compose.yml         # Container orchestration
├── render.yaml                # Render production deployment blueprint
├── pyproject.toml             # Python package configuration
└── requirements.txt           # Production dependencies
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Virtual environment (`venv` or `uv`)

### 1. Installation
Clone the repository and install dependencies:
```bash
# Clone
git clone https://github.com/pmkaulani/toroka.git
cd toroka/smart-scam-identifier

# Create and activate virtual environment
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and configure your keys:
```bash
cp .env.example .env
```
Key configuration options:
- `GEMINI_API_KEY`: *(Optional)* Enables Gemini conversational AI for natural chat. When unset, Toroka seamlessly falls back to high-accuracy local deterministic intelligence.
- `DATABASE_URL`: Defaults to `sqlite:///./ssi.db` for local development. Use PostgreSQL for production concurrency (`postgresql://user:pass@host/toroka`).
- `SECRET_KEY` & `TOROKA_ENTITY_HASH_SECRET`: 32+ byte secrets for sessions and privacy-preserving entity hashing.

### 3. Run Migrations & Start Server
```bash
# Set PYTHONPATH
# Windows (PowerShell):
$env:PYTHONPATH = "packages/rules;packages/connectors;services/api"
# Linux/macOS:
export PYTHONPATH="packages/rules:packages/connectors:services/api"

# Run migrations
alembic -c services/api/alembic.ini upgrade head

# Start application server
uvicorn services.api.app.main:app --reload --host 0.0.0.0 --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your browser. Interactive OpenAPI documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 🧪 Testing & Validation

The codebase maintains rigorous automated test coverage across unit, integration, and golden-case test suites:

```bash
# Run core test suites
pytest services/api/tests/ packages/rules/tests/ packages/connectors/tests/ -q

# Run conversational AI & chat tests
pytest services/api/tests/test_conversation_about_toroka.py -v

# Run email forensics tests
pytest services/api/tests/test_email_forensics.py services/api/tests/test_email_chat_integration_contract.py -v

# Run web interface and action menu tests
pytest services/api/tests/test_web.py services/api/tests/test_composer_actions_menu.py -v

# Run labelled benchmark evaluation (29+ cases)
python eval/run_eval.py
```

---

## 🌐 Production Deployment

Toroka is deployed on **Render** as a high-performance web service:

- **Configuration:** Managed via [render.yaml](render.yaml).
- **Runtime:** `gunicorn` with `uvicorn.workers.UvicornWorker` for asynchronous request concurrency.
- **Health Check Endpoint:** `GET /v1/health` (returns `{"status": "ok"}`).
- **Static Assets:** Cached and served with proper `Content-Security-Policy` and PWA service worker offline shell headers.

---

## 🛡️ Responsible Safety & Privacy Principles

1. **No Accusations:** Toroka analyzes messages, domains, numbers, and technical evidence. It never accuses individuals or proclaims moral judgments.
2. **Contextual Guidance:** Asking for a deposit or payment is not automatically fraud, but requesting upfront payment without an escrow mechanism or verified physical presence warrants caution.
3. **Never Share Credentials:** Toroka will **never** ask you for your M-PESA PIN, bank password, or one-time passcode (OTP), and warns users whenever messages solicit credentials.
4. **Data Minimization:** No personal phone numbers or user identities are published in public indicator searches. All cross-case correlations rely on one-way salted HMAC digests.

---

## 📄 License

Proprietary and confidential. Developed for digital safety in Kenya and East Africa.
