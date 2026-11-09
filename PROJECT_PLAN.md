# Project Plan: Intelligent Spam Email Deleter (Gmail Edition)

> **Status Legend**:  
> 🟢 **`[COMPLETED]`** — Finished and verified  
> 🟡 **`[IN PROGRESS]`** — Undergoing at the moment  
> ⚪ **`[PLANNED]`** — Queued for future implementation  

---

## 📊 Live Project Status Dashboard

| Metric | Status |
| :--- | :--- |
| **Current Phase** | **Milestone 5: Cloud Deployment & Google OAuth Connection** |
| **Active Task** | Deploy to Streamlit Community Cloud (free permanent hosting) & connect Google OAuth |
| **GitHub Repository** | `https://github.com/debanjan-steel/Spam-Email-Deleter` (Branch: `main`) |
| **Interface** | Progressive Web App (PWA) on Mobile & Desktop |
| **1-Click Launchers** | `Start Spam Deleter (No Terminal).vbs` (Silent background runner, NO terminal window) & `Open Spam Deleter.url` |
| **Email Target** | Gmail Multi-Account (Switch between personal, work, and extra Gmail inboxes) |
| **Cloud Deploy Ready** | `render.yaml`, `Dockerfile`, `supabase_schema.sql` included |
| **Overall Progress** | `90% Completed` |
| **Last Updated** | 2026-11-08 |

---

## 1. Project Overview & Multi-Account Scope
The **Intelligent Spam Email Deleter** is an automated mail-cleaning Progressive Web App (PWA) that allows you to connect **multiple Gmail accounts** simultaneously. You can switch between your inboxes with one click, scan and clean spam in Account A, switch to Account B, and do the same.

---

## 2. Safety-First Decision Flow

```
                      [ Incoming Gmail Message ]
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Tier 1: Absolute Immunity Guard (NEVER TOUCH)               │ ──► [ PROTECTED / SAFE ]
  │ • Google Contacts & senders you have replied to             │     (Bypasses all deletion)
  │ • Starred / Flagged / Marked Important                      │
  │ • Critical transaction keywords (2FA, Order #, Bank, Bills) │
  │ • Explicit User Whitelist (configured domains/senders)      │
  └──────────────────────────────────────────────────────────────┘
                                  │ (Not Protected)
                                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Tier 2: User-Defined Targeted Rules (Manual Blacklist)      │ ──► [ TARGETED FOR TRASH ]
  │ • Exact sender emails added by user in dashboard            │     (Matched by custom rule)
  │ • Specific domains (e.g. *@promo.example.com)               │
  │ • Custom subject keywords / patterns                        │
  └──────────────────────────────────────────────────────────────┘
                                  │ (No direct manual match)
                                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Tier 3: Automated Spam Scoring Engine                       │
  │ • Existing Gmail SPAM folder classification                 │
  │ • SPF / DKIM / DMARC authentication check                   │
  │ • Bulk email headers & List-Unsubscribe detection           │
  │ • Optional Gemini AI semantic reasoning for borderline cases│
  └──────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Tier 4: PWA Dashboard Review & Safe Multi-Account Execution │
  │ • Dry-Run Preview table with visual confidence ratings      │
  │ • One-click "Move to Trash" (Never immediate hard expunge)  │
  │ • SQLite Audit Log tagged per account + Instant Undo/Restore│
  └──────────────────────────────────────────────────────────────┘
```

---

## 3. Dynamic Task Breakdown & Milestones

### 🟢 Milestone 0: Environment & Workspace Foundation `[COMPLETED]`
- [x] 🟢 **Task 0.1**: Target and verify Python 3.13 installation.
- [x] 🟢 **Task 0.2**: Create local virtual environment (`.venv`).
- [x] 🟢 **Task 0.3**: Configure IDE settings in `.vscode/settings.json` for default interpreter and auto-activation.
- [x] 🟢 **Task 0.4**: Create `.python-version` (3.13) and `.gitignore` (ignoring `.venv`, credentials, caches, `tokens/`).
- [x] 🟢 **Task 0.5**: Initialize local Git repository.
- [x] 🟢 **Task 0.6**: Formulate architectural defense-in-depth safety strategy.

---

### 🟢 Milestone 1: Dependencies, Config & Multi-Account Gmail Auth `[COMPLETED]`
- [x] 🟢 **Task 1.1**: Define base dependencies in `requirements.txt` and install into `.venv`.
- [x] 🟢 **Task 1.2**: Create configuration manager and default YAMLs:
  - `config/config.yaml`: Core settings (thresholds, batch size, trash vs permanent).
  - `config/whitelist.yaml`: Protected senders, domains, and safe keywords.
  - `config/custom_rules.yaml`: User-defined targeted delete rules (manual sender/domain/keyword blacklist).
- [x] 🟢 **Task 1.3**: Implement Multi-Account Google OAuth 2.0 flow (`src/auth/gmail_auth.py`):
  - Store tokens per account in `tokens/{email}.json`.
  - Methods: `list_accounts()`, `add_account()`, `get_service_for_account()`, `remove_account()`.
- [x] 🟢 **Task 1.4**: Implement Gmail API Connector (`src/connectors/gmail_connector.py`):
  - Pagination, batching, header/label inspection, soft-delete to Trash, untrash restore.

---

### 🟢 Milestone 2: Whitelist Guard & Custom Rules Engine `[COMPLETED]`
- [x] 🟢 **Task 2.1**: Implement Whitelist Guard (`src/engine/whitelist_guard.py`):
  - Starred & Important label immunity.
  - Critical transactional keywords (2FA, flight, order, bank, receipt).
- [x] 🟢 **Task 2.2**: Implement Custom Targeted Rules Engine (`src/engine/custom_rules.py`):
  - Rule matcher for manual sender email addresses, wildcard domains, and subject patterns.
  - Dynamic rule persistence (load/save directly from dashboard).
- [x] 🟢 **Task 2.3**: Build automated scoring engine (`src/engine/spam_scorer.py`):
  - SPF/DKIM/DMARC status, `List-Unsubscribe` header detection, keyword heuristics.
  - Unified confidence score [0.0 - 1.0].

---

### 🟢 Milestone 3: Multi-Account Audit Logging & Undo/Restore Mechanism `[COMPLETED]`
- [x] 🟢 **Task 3.1**: SQLite Audit Storage (`src/storage/audit_logger.py`):
  - Log batch ID, account email, message ID, sender, subject, date, spam score, and rule reason.
- [x] 🟢 **Task 3.2**: Multi-Account Restore / Rollback Engine:
  - Undo an entire batch for the specific account that owned those emails.

---

### 🟢 Milestone 4: Progressive Web App & 1-Click Launchers `[COMPLETED]`
- [x] 🟢 **Task 4.1**: Build Multi-Account PWA Dashboard (`src/web/app.py`):
  - Account Switcher dropdown & "➕ Add Account" flow in sidebar.
  - Scan & Clean tab scoped to active account.
  - Custom Rules tab (shared or per-account).
  - Whitelist & Safeguards tab.
  - Audit Log tab with account filtering & 1-click batch restore.
  - Setup tab with OAuth instructions & file uploader.
- [x] 🟢 **Task 4.2**: Progressive Web App (PWA) assets:
  - `static/manifest.json`, `static/sw.js`, `static/icon-192.png`, `static/icon-512.png`.
  - Enables "Install as App" on desktop/mobile in Chrome and Edge.
- [x] 🟢 **Task 4.3**: 1-Click Desktop Launchers:
  - `Start Spam Deleter (No Terminal).vbs`: Silent launcher without any command prompt window.
  - `Open Spam Deleter.url`: Internet shortcut pointing to `http://localhost:8501`.
  - `Start App.bat`: Standard batch launcher.
  - `APP_URL.txt`: Saved URL and launch instructions.
- [x] 🟢 **Task 4.4**: Cloud Deployment templates:
  - `render.yaml` for Render 1-click deployment.
  - `Dockerfile` for Docker-compatible clouds (Render, Railway, Fly, Cloud Run).
  - `supabase_schema.sql` for Supabase Postgres storage.
- [x] 🟢 **Task 4.5**: Unit tests in `tests/test_engine.py` (6/6 tests passing).
- [x] 🟢 **Task 4.6**: High-Volume Scanning & Batch Deletion Engine (`10,000+` emails):
  - Raised UI scan ceiling from 500 to 50,000 emails with 1-click presets (`500`, `1,000`, `2,500`, `5,000`, `10,000`, `25,000`).
  - High-throughput IMAP connector with persistent connection reuse and chunked multi-message `FETCH` commands (eliminating Google IMAP connection throttling).
  - Gmail API connector pagination across pages using `pageToken` up to `max_results`.
  - Batch trashing (`trash_messages_batch`) and undo restore (`untrash_messages_batch`) with real-time progress indicators.
  - Responsive results table filtering (`🎯 Deletion Candidates`, `📋 All Scanned`, `🛡️ Safe & Protected`) to keep browser memory snappy with 10,000+ rows.
  - Unit test verification in `tests/test_high_volume_batch.py`.

---

### 🟡 Milestone 5: Google Cloud OAuth Client Setup & End-to-End Run `[IN PROGRESS]`
- [ ] 🟡 **Task 5.1**: User drops `credentials.json` into project folder (or uploads via dashboard).
- [ ] ⚪ **Task 5.2**: Connect first Gmail account and test dry-run scan.
- [ ] ⚪ **Task 5.3**: Connect second Gmail account and test switching between accounts.

---

## 4. Architecture & Directory Layout

```
spam_email_deleter/
├── .venv/                                      # 🟢 Python 3.13 virtual environment
├── .vscode/
│   └── settings.json                           # 🟢 IDE configuration
├── .gitignore                                  # 🟢 Git exclusions
├── .python-version                             # 🟢 Python 3.13 pin
├── PROJECT_PLAN.md                             # 🟢 Dynamic project roadmap & tracker
├── requirements.txt                            # 🟢 Project dependencies
├── credentials.json                            # 🟡 Google Cloud OAuth Client Secret (User provides)
├── tokens/                                     # 🟢 Multi-Account saved OAuth tokens
│   └── {email}.json
├── audit_log.db                                # 🟢 SQLite multi-account audit database
├── config/
│   ├── config.yaml                             # 🟢 App settings & thresholds
│   ├── whitelist.yaml                          # 🟢 Protected senders, domains & keywords
│   └── custom_rules.yaml                       # 🟢 User-defined manual delete rules
├── static/
│   ├── manifest.json                           # 🟢 PWA web app manifest
│   ├── sw.js                                   # 🟢 PWA Service Worker
│   ├── icon-192.png                            # 🟢 PWA app icon (192px)
│   └── icon-512.png                            # 🟢 PWA app icon (512px)
├── src/
│   ├── __init__.py                             # 🟢 Package init
│   ├── config_loader.py                        # 🟢 Configuration loader
│   ├── auth/
│   │   ├── __init__.py                         # 🟢 Auth init
│   │   └── gmail_auth.py                       # 🟢 Multi-Account OAuth 2.0 manager
│   ├── connectors/
│   │   ├── __init__.py                         # 🟢 Connectors init
│   │   └── gmail_connector.py                  # 🟢 Gmail REST API client
│   ├── engine/
│   │   ├── __init__.py                         # 🟢 Engine init
│   │   ├── whitelist_guard.py                  # 🟢 Absolute protection filters
│   │   ├── custom_rules.py                     # 🟢 Manual user rules matcher
│   │   └── spam_scorer.py                      # 🟢 Heuristic & header scorer
│   ├── storage/
│   │   ├── __init__.py                         # 🟢 Storage init
│   │   └── audit_logger.py                     # 🟢 Multi-account audit trail & rollback
│   └── web/
│       ├── __init__.py                         # 🟢 Web init
│       └── app.py                              # 🟢 Multi-Account PWA Dashboard (Streamlit)
├── tests/
│   └── test_engine.py                          # 🟢 Test suite (6/6 tests passing)
├── Open Spam Deleter.url                       # 🟢 1-Click Internet Shortcut
├── Start Spam Deleter (No Terminal).vbs        # 🟢 1-Click Silent Launcher (No black window)
├── Start App.bat                               # 🟢 1-Click Batch Launcher
├── APP_URL.txt                                 # 🟢 Saved Access URL & instructions
├── render.yaml                                 # 🟢 Render cloud deployment config
├── Dockerfile                                  # 🟢 Cloud Dockerfile container
└── supabase_schema.sql                         # 🟢 Supabase cloud DB schema
```
