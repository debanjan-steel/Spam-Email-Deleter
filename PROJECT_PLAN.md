# Project Plan: Intelligent Spam Email Deleter (Gmail Edition)

> **Status Legend**:  
> 🟢 **`[COMPLETED]`** — Finished and verified  
> 🟡 **`[IN PROGRESS]`** — Undergoing at the moment  
> ⚪ **`[PLANNED]`** — Queued for future implementation  

---

## 📊 Live Project Status Dashboard

| Metric | Status |
| :--- | :--- |
| **Current Phase** | **Milestone 5: Live Testing & Gmail Cloud OAuth Client Connection** |
| **Active Task** | Waiting for user to supply Google Cloud `credentials.json` and launch the web app |
| **Interface** | Local Web Dashboard (`streamlit run src/web/app.py` or `python run_dashboard.py`) |
| **Email Target** | Gmail (Google OAuth 2.0 & Gmail REST API) |
| **Overall Progress** | `85% Completed` (Core engine, rules manager, safeguards, and web dashboard fully built & tested) |
| **Last Updated** | 2026-11-08 |

---

## 1. Project Overview & Scope
The **Intelligent Spam Email Deleter** is a dedicated Python 3.13 application paired with a **Local Web Dashboard** for Gmail. It cleans out unwanted email through a combination of:
1. **User-Defined Manual Deletion Rules**: Targeted blacklist of specific senders, domains, subject keywords, or patterns.
2. **Automated Spam Detection**: Multi-layer heuristics, authentication header checks (SPF/DKIM), and optional AI verification.
3. **Ironclad Protection Safeguards**: High-priority immunity whitelist preventing any contact, starred email, receipt, or critical communication from ever being deleted.

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
  │ Tier 4: Local Web Dashboard Review & Safe Execution         │
  │ • Dry-Run Preview table with visual confidence ratings      │
  │ • One-click "Move to Trash" (Never immediate hard expunge)  │
  │ • SQLite Audit Log + Instant "Undo / Restore Batch" action  │
  └──────────────────────────────────────────────────────────────┘
```

---

## 3. Dynamic Task Breakdown & Milestones

### 🟢 Milestone 0: Environment & Workspace Foundation `[COMPLETED]`
- [x] 🟢 **Task 0.1**: Target and verify Python 3.13 installation.
- [x] 🟢 **Task 0.2**: Create local virtual environment (`.venv`).
- [x] 🟢 **Task 0.3**: Configure IDE settings in `.vscode/settings.json` for default interpreter and auto-activation.
- [x] 🟢 **Task 0.4**: Create `.python-version` (3.13) and `.gitignore` (ignoring `.venv`, credentials, caches).
- [x] 🟢 **Task 0.5**: Initialize local Git repository.
- [x] 🟢 **Task 0.6**: Formulate architectural defense-in-depth safety strategy.

---

### 🟢 Milestone 1: Dependencies, Config & Gmail Authentication `[COMPLETED]`
- [x] 🟢 **Task 1.1**: Define base dependencies in `requirements.txt` and install into `.venv`.
- [x] 🟢 **Task 1.2**: Create configuration manager and default YAMLs:
  - `config/config.yaml`: Core settings (thresholds, batch size, trash vs permanent).
  - `config/whitelist.yaml`: Protected senders, domains, and safe keywords.
  - `config/custom_rules.yaml`: User-defined targeted delete rules (manual sender/domain/keyword blacklist).
- [x] 🟢 **Task 1.3**: Implement Google OAuth 2.0 flow (`src/auth/gmail_auth.py`) supporting automatic browser consent and token storage (`token.json`).
- [x] 🟢 **Task 1.4**: Implement Gmail API Connector (`src/connectors/gmail_connector.py`) with support for:
  - Reading messages with pagination and batching.
  - Inspecting headers, labels, and snippets.
  - Soft-delete action (moving messages to `TRASH`).
  - Restoring messages from `TRASH` back to `INBOX`.
- [x] 🟢 **Task 1.5**: Implement quick connection verification script and auth helpers.

---

### 🟢 Milestone 2: Whitelist Guard & Custom Rules Engine `[COMPLETED]`
- [x] 🟢 **Task 2.1**: Implement Whitelist Guard (`src/engine/whitelist_guard.py`):
  - Check Starred & Important labels.
  - Check sensitive transaction keywords (2FA, flight, order, bank, receipt).
  - Case-insensitive sender and domain matching.
- [x] 🟢 **Task 2.2**: Implement Custom Targeted Rules Engine (`src/engine/custom_rules.py`):
  - Rule matcher for manual sender email addresses, wildcard domains, and subject patterns.
  - Dynamic rule persistence (load/save directly from dashboard).
- [x] 🟢 **Task 2.3**: Build automated scoring engine (`src/engine/spam_scorer.py`):
  - Header inspection (SPF/DKIM/DMARC status, `List-Unsubscribe` header).
  - Suspicious pattern heuristics.
  - Unified confidence score [0.0 - 1.0] and decision tagging (`PROTECTED`, `TARGETED_TRASH`, `SPAM_TRASH`, `SAFE`).

---

### 🟢 Milestone 3: Audit Logging & Undo/Restore Mechanism `[COMPLETED]`
- [x] 🟢 **Task 3.1**: SQLite Audit Storage (`src/storage/audit_logger.py`):
  - Log batch ID, message ID, sender, subject, date, spam score, matched rule, and original labels.
- [x] 🟢 **Task 3.2**: Restore / Rollback Engine:
  - Function to undo an entire batch or individual selected messages using Gmail's untrash API.

---

### 🟢 Milestone 4: Local Web Dashboard `[COMPLETED]`
- [x] 🟢 **Task 4.1**: Build Web Dashboard (`src/web/app.py`):
  - **Account & Status Header**: Show connected Gmail address, unread count, and spam count.
  - **Scan & Clean Tab**:
    - Select folders to scan (Inbox, Spam, Promotions, Updates).
    - "Run Dry-Run Scan" simulation button.
    - Editable data table with checkboxes to confirm deletion candidates.
    - "Move Selected Emails to Trash" action button.
  - **Custom Rules Manager Tab**:
    - Add/remove specific email IDs, domains, or subject keywords to delete.
  - **Whitelist & Safety Tab**:
    - Manage protected email IDs, domains, and keywords with 1-click removal and addition.
  - **Audit & Undo Tab**:
    - View history of past cleanup runs.
    - 1-click "Undo / Restore Batch" button.
  - **Setup & Help Tab**:
    - In-app Google Cloud OAuth setup instructions + drag-and-drop `credentials.json` uploader.
- [x] 🟢 **Task 4.2**: Create one-click launcher `run_dashboard.py`.
- [x] 🟢 **Task 4.3**: Unit test suite in `tests/test_engine.py` (5/5 tests passing).

---

### 🟡 Milestone 5: Google Cloud OAuth Client Setup & End-to-End Run `[IN PROGRESS]`
- [ ] 🟡 **Task 5.1**: User sets up Google Cloud OAuth client ID and places `credentials.json` in project root (or uploads via dashboard).
- [ ] ⚪ **Task 5.2**: Perform first live Gmail OAuth sign-in and run a dry-run scan on actual mailbox.

---

## 4. Architecture & Directory Layout

```
spam_email_deleter/
├── .venv/                          # 🟢 Python 3.13 virtual environment
├── .vscode/
│   └── settings.json               # 🟢 IDE configuration
├── .gitignore                      # 🟢 Git exclusions
├── .python-version                 # 🟢 Python 3.13 pin
├── PROJECT_PLAN.md                 # 🟢 Dynamic project roadmap & tracker
├── requirements.txt                # 🟢 Project dependencies
├── credentials.json                # 🟡 Google Cloud OAuth Client Secret (User provides)
├── token.json                      # ⚪ Saved OAuth Access/Refresh Token (Generated on login)
├── audit_log.db                    # 🟢 SQLite audit trail & rollback database
├── config/
│   ├── config.yaml                 # 🟢 App settings & thresholds
│   ├── whitelist.yaml              # 🟢 Protected senders, domains & keywords
│   └── custom_rules.yaml           # 🟢 User-defined manual delete rules
├── src/
│   ├── __init__.py                 # 🟢 Package init
│   ├── config_loader.py            # 🟢 Configuration loader & sync manager
│   ├── auth/
│   │   ├── __init__.py             # 🟢 Auth init
│   │   └── gmail_auth.py           # 🟢 Google OAuth 2.0 flow
│   ├── connectors/
│   │   ├── __init__.py             # 🟢 Connectors init
│   │   └── gmail_connector.py      # 🟢 Gmail REST API client
│   ├── engine/
│   │   ├── __init__.py             # 🟢 Engine init
│   │   ├── whitelist_guard.py      # 🟢 Absolute protection filters
│   │   ├── custom_rules.py         # 🟢 Manual user rules matcher
│   │   └── spam_scorer.py          # 🟢 Heuristic & header scorer
│   ├── storage/
│   │   ├── __init__.py             # 🟢 Storage init
│   │   └── audit_logger.py         # 🟢 SQLite audit trail & rollback
│   └── web/
│       ├── __init__.py             # 🟢 Web init
│       └── app.py                  # 🟢 Local Web Dashboard (Streamlit)
├── tests/
│   └── test_engine.py              # 🟢 Test suite (5/5 tests passing)
└── run_dashboard.py                # 🟢 One-click launcher for the web app
```

---

## 5. Technology Stack

- **Language**: Python 3.13
- **Web Dashboard**: `streamlit` (Responsive local web interface with interactive tables and forms)
- **Data Handling**: `pandas`, `pydantic` v2, `pyyaml`
- **Gmail Protocol**: `google-api-python-client`, `google-auth-oauthlib`, `google-auth-httplib2`
- **Audit Storage**: `sqlite3`
