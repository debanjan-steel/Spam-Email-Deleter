"""Streamlit Web Dashboard for Intelligent Spam Email Deleter.
"""
from datetime import datetime
from pathlib import Path
import uuid
import streamlit as st
import pandas as pd

from src.auth.gmail_auth import GmailAuthenticator
from src.config_loader import ConfigManager
from src.connectors.gmail_connector import GmailConnector, EmailMessage
from src.engine.custom_rules import CustomRulesMatcher
from src.engine.spam_scorer import ClassificationResult, SpamScorer
from src.engine.whitelist_guard import WhitelistGuard
from src.storage.audit_logger import AuditLogger

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

st.set_page_config(
    page_title="Gmail Spam Deleter & Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State & Managers
if "config_mgr" not in st.session_state:
    st.session_state.config_mgr = ConfigManager()
if "audit_logger" not in st.session_state:
    st.session_state.audit_logger = AuditLogger()
if "auth" not in st.session_state:
    st.session_state.auth = GmailAuthenticator()
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "selected_mids" not in st.session_state:
    st.session_state.selected_mids = set()

config_mgr: ConfigManager = st.session_state.config_mgr
audit_logger: AuditLogger = st.session_state.audit_logger
auth: GmailAuthenticator = st.session_state.auth

# Sidebar: Account & Quick Status
with st.sidebar:
    st.title("🛡️ Mail Guard")
    st.caption("Intelligent Gmail Cleaner & Spam Deleter")
    st.divider()

    user_email, total_msgs = None, None
    is_connected = False

    if auth.has_credentials_file():
        if auth.has_saved_token():
            try:
                user_email, total_msgs = auth.get_profile()
                if user_email:
                    is_connected = True
            except Exception:
                is_connected = False

        if is_connected:
            st.success(f"**Connected**\n\n📧 `{user_email}`")
            if total_msgs is not None:
                st.caption(f"Total Mailbox Messages: {total_msgs:,}")
            if st.button("🚪 Sign Out / Reset Token", use_container_width=True):
                auth.logout()
                st.session_state.scan_results = []
                st.rerun()
        else:
            st.warning("Gmail not connected yet.")
            if st.button("🔑 Sign In with Google", type="primary", use_container_width=True):
                try:
                    with st.spinner("Opening browser for Google OAuth consent..."):
                        auth.get_credentials()
                    st.success("Authenticated successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Authentication failed: {e}")
    else:
        st.error("Missing `credentials.json`")
        st.info("Place your Google Cloud OAuth Client credentials.json in the project folder to connect.")

    st.divider()
    st.markdown("### Safety Guarantee")
    st.markdown("✅ **Soft-delete only**: Items are moved to Trash with 30-day recovery.")
    st.markdown("✅ **Zero-touch whitelist**: Personal contacts, 2FA codes, order receipts, and starred emails are permanently immune.")

# Main Application Tabs
tab_scan, tab_rules, tab_whitelist, tab_audit, tab_setup = st.tabs([
    "🔍 Scan & Clean",
    "🎯 Custom Deletion Rules",
    "🛡️ Whitelist & Safeguards",
    "↩️ Audit Log & Undo",
    "⚙️ Setup & Help",
])

# -------------------------------------------------------------
# TAB 1: SCAN & CLEAN
# -------------------------------------------------------------
with tab_scan:
    st.header("🔍 Scan Mailbox for Unwanted Emails")

    if not is_connected:
        st.warning("Please sign in with Google in the sidebar to scan your mailbox.")
    else:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            folders_to_scan = st.multiselect(
                "Select Folders / Labels to Scan",
                options=["INBOX", "SPAM", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES"],
                default=["SPAM", "CATEGORY_PROMOTIONS"],
                help="Choose which Gmail categories or folders to search."
            )
        with col2:
            max_emails = st.number_input(
                "Max Emails to Fetch",
                min_value=10,
                max_value=300,
                value=50,
                step=10,
            )
        with col3:
            custom_query = st.text_input(
                "Optional Gmail Query",
                placeholder="e.g. is:unread",
                help="Advanced Gmail search operators to refine the scan."
            )

        btn_scan = st.button("▶️ Run Simulation / Dry-Run Scan", type="primary")

        if btn_scan:
            try:
                service = auth.get_service()
                connector = GmailConnector(service)
                whitelist_guard = WhitelistGuard(config_mgr.whitelist)
                custom_rules = CustomRulesMatcher(config_mgr.custom_rules)
                scorer = SpamScorer(whitelist_guard, custom_rules, config_mgr.app_config.detection)

                all_mids = []
                with st.spinner("Fetching message IDs from Gmail..."):
                    if folders_to_scan:
                        for label in folders_to_scan:
                            mids = connector.list_message_ids(
                                query=custom_query or None,
                                label_ids=[label],
                                max_results=max_emails,
                            )
                            all_mids.extend(mids)
                    else:
                        all_mids = connector.list_message_ids(
                            query=custom_query or None,
                            max_results=max_emails,
                        )
                # Deduplicate
                unique_mids = list(dict.fromkeys(all_mids))[:max_emails]

                if not unique_mids:
                    st.info("No emails found matching the selected criteria.")
                    st.session_state.scan_results = []
                else:
                    with st.spinner(f"Analyzing {len(unique_mids)} emails with safety & spam rules..."):
                        messages = connector.get_messages_batch(unique_mids)
                        results = [scorer.evaluate(m) for m in messages]
                        st.session_state.scan_results = results
                        # Pre-select items targeted for deletion
                        st.session_state.selected_mids = {
                            r.message_id for r in results if r.action in ("TARGETED_TRASH", "SPAM_TRASH")
                        }
                    st.success(f"Scan complete! Evaluated {len(results)} emails.")
            except Exception as e:
                st.error(f"Error during scan: {e}")

        # Render Results Table
        results = st.session_state.scan_results
        if results:
            st.divider()

            # Metrics
            total_count = len(results)
            prot_count = sum(1 for r in results if r.is_protected)
            manual_count = sum(1 for r in results if r.action == "TARGETED_TRASH")
            spam_count = sum(1 for r in results if r.action == "SPAM_TRASH")
            safe_count = sum(1 for r in results if r.action == "SAFE")

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Total Scanned", total_count)
            m2.metric("🛡️ Protected (Immune)", prot_count)
            m3.metric("🎯 Custom Rule Matches", manual_count)
            m4.metric("🚨 Auto-Detected Spam", spam_count)
            m5.metric("✅ Safe / Normal", safe_count)

            st.subheader("Candidate Emails")

            # Bulk Actions
            col_a, col_b, col_c = st.columns([1, 1, 2])
            with col_a:
                if st.button("Select All Deletion Candidates"):
                    st.session_state.selected_mids = {
                        r.message_id for r in results if r.action in ("TARGETED_TRASH", "SPAM_TRASH")
                    }
                    st.rerun()
            with col_b:
                if st.button("Deselect All"):
                    st.session_state.selected_mids = set()
                    st.rerun()

            table_data = []
            for r in results:
                is_checked = r.message_id in st.session_state.selected_mids
                action_badge = {
                    "PROTECTED": "🛡️ Immune",
                    "TARGETED_TRASH": "🎯 Manual Rule",
                    "SPAM_TRASH": "🚨 Spam",
                    "SAFE": "✅ Safe",
                }.get(r.action, r.action)

                table_data.append({
                    "Select": is_checked,
                    "Action": action_badge,
                    "Score": f"{r.score:.2f}",
                    "Sender": r.sender[:25],
                    "Email": r.sender_email,
                    "Subject": r.subject[:45],
                    "Date": r.date_str[:16] if r.date_str else "",
                    "Reason": r.reason,
                    "Message ID": r.message_id,
                })

            df = pd.DataFrame(table_data)
            edited_df = st.data_editor(
                df,
                disabled=["Action", "Score", "Sender", "Email", "Subject", "Date", "Reason", "Message ID"],
                hide_index=True,
                use_container_width=True,
                key="results_editor"
            )

            # Update selected mids from editor
            new_selected = set(
                edited_df[edited_df["Select"] == True]["Message ID"].tolist()
            )
            st.session_state.selected_mids = new_selected

            st.write(f"**{len(new_selected)} emails selected for deletion.**")

            # Execution Button
            if new_selected:
                if st.button(f"🗑️ Move {len(new_selected)} Selected Emails to Trash", type="primary"):
                    try:
                        service = auth.get_service()
                        connector = GmailConnector(service)
                        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
                        
                        trashed_results = []
                        with st.spinner(f"Moving {len(new_selected)} emails to Trash..."):
                            for r in results:
                                if r.message_id in new_selected:
                                    success = connector.trash_message(r.message_id)
                                    if success:
                                        trashed_results.append(r)

                        # Record in Audit Log
                        audit_logger.record_batch(batch_id, trashed_results, action_type="TRASH")
                        
                        st.success(f"Successfully moved {len(trashed_results)} emails to Trash! Batch ID: `{batch_id}`")
                        st.info("You can undo this anytime in the 'Audit Log & Undo' tab.")
                        
                        # Clear processed from current scan results
                        st.session_state.scan_results = [
                            r for r in results if r.message_id not in new_selected
                        ]
                        st.session_state.selected_mids = set()
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to move items to trash: {e}")

# -------------------------------------------------------------
# TAB 2: CUSTOM DELETION RULES (MANUAL BLACKLIST)
# -------------------------------------------------------------
with tab_rules:
    st.header("🎯 User-Defined Manual Deletion Rules")
    st.markdown(
        "Define exact email addresses, domains, or subject keywords you want **automatically flagged for deletion**. "
        "These take effect immediately during scans (unless protected by your Whitelist)."
    )

    custom_rules = config_mgr.custom_rules

    # Section 1: Add New Rule
    with st.expander("➕ Add New Deletion Rule", expanded=True):
        col_type, col_val, col_btn = st.columns([1, 2, 1])
        with col_type:
            rule_type = st.selectbox(
                "Rule Type",
                ["Specific Email ID", "Sender Domain", "Subject Keyword"],
            )
        with col_val:
            rule_value = st.text_input("Rule Value", placeholder="e.g. spammer@badsite.com or spamdeals.xyz")
        with col_btn:
            st.write("")
            st.write("")
            if st.button("Add Rule", type="primary", use_container_width=True):
                val = rule_value.strip()
                if val:
                    if rule_type == "Specific Email ID":
                        if val.lower() not in [s.lower() for s in custom_rules.targeted_senders]:
                            custom_rules.targeted_senders.append(val.lower())
                            config_mgr.save_custom_rules(custom_rules)
                            st.success(f"Added email rule: {val}")
                            st.rerun()
                    elif rule_type == "Sender Domain":
                        clean_dom = val.lower().replace("@", "").strip()
                        if clean_dom not in [d.lower() for d in custom_rules.targeted_domains]:
                            custom_rules.targeted_domains.append(clean_dom)
                            config_mgr.save_custom_rules(custom_rules)
                            st.success(f"Added domain rule: {clean_dom}")
                            st.rerun()
                    elif rule_type == "Subject Keyword":
                        if val.lower() not in [k.lower() for k in custom_rules.targeted_subject_keywords]:
                            custom_rules.targeted_subject_keywords.append(val.lower())
                            config_mgr.save_custom_rules(custom_rules)
                            st.success(f"Added subject keyword rule: {val}")
                            st.rerun()

    st.divider()

    # Section 2: Active Rules Display
    c1, c2, c3 = st.columns(3)

    with c1:
        st.subheader("Targeted Senders")
        if not custom_rules.targeted_senders:
            st.caption("No specific senders added yet.")
        else:
            for s in list(custom_rules.targeted_senders):
                r_col1, r_col2 = st.columns([3, 1])
                r_col1.write(f"`{s}`")
                if r_col2.button("❌", key=f"del_sender_{s}"):
                    custom_rules.targeted_senders.remove(s)
                    config_mgr.save_custom_rules(custom_rules)
                    st.rerun()

    with c2:
        st.subheader("Targeted Domains")
        if not custom_rules.targeted_domains:
            st.caption("No domains added yet.")
        else:
            for d in list(custom_rules.targeted_domains):
                r_col1, r_col2 = st.columns([3, 1])
                r_col1.write(f"`@{d}`")
                if r_col2.button("❌", key=f"del_domain_{d}"):
                    custom_rules.targeted_domains.remove(d)
                    config_mgr.save_custom_rules(custom_rules)
                    st.rerun()

    with c3:
        st.subheader("Targeted Subject Keywords")
        if not custom_rules.targeted_subject_keywords:
            st.caption("No subject keywords added yet.")
        else:
            for k in list(custom_rules.targeted_subject_keywords):
                r_col1, r_col2 = st.columns([3, 1])
                r_col1.write(f"`{k}`")
                if r_col2.button("❌", key=f"del_kw_{k}"):
                    custom_rules.targeted_subject_keywords.remove(k)
                    config_mgr.save_custom_rules(custom_rules)
                    st.rerun()

# -------------------------------------------------------------
# TAB 3: WHITELIST & SAFEGUARDS
# -------------------------------------------------------------
with tab_whitelist:
    st.header("🛡️ Whitelist & Safety Safeguards")
    st.markdown(
        "Emails matching any rule here have **absolute immunity**. The deleter will **NEVER** touch or trash them."
    )

    wl = config_mgr.whitelist

    st.subheader("Protection Flags")
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        new_starred = st.checkbox("Protect Starred / Flagged Emails", value=wl.protection_flags.protect_starred)
    with col_f2:
        new_imp = st.checkbox("Protect Gmail 'Important' Emails", value=wl.protection_flags.protect_important)

    if new_starred != wl.protection_flags.protect_starred or new_imp != wl.protection_flags.protect_important:
        wl.protection_flags.protect_starred = new_starred
        wl.protection_flags.protect_important = new_imp
        config_mgr.save_whitelist(wl)
        st.success("Updated protection flags!")

    st.divider()

    # Add Whitelist Entry
    with st.expander("➕ Add Trusted Sender or Domain", expanded=False):
        w_type, w_val, w_btn = st.columns([1, 2, 1])
        with w_type:
            wl_entry_type = st.selectbox("Type", ["Trusted Email Address", "Trusted Domain", "Safe Keyword"])
        with w_val:
            wl_entry_val = st.text_input("Value", placeholder="e.g. boss@work.com or mybank.com or receipt")
        with w_btn:
            st.write("")
            st.write("")
            if st.button("Add to Whitelist", type="primary", use_container_width=True):
                w_val_clean = wl_entry_val.strip().lower()
                if w_val_clean:
                    if wl_entry_type == "Trusted Email Address":
                        if w_val_clean not in [s.lower() for s in wl.protected_senders]:
                            wl.protected_senders.append(w_val_clean)
                            config_mgr.save_whitelist(wl)
                            st.rerun()
                    elif wl_entry_type == "Trusted Domain":
                        if w_val_clean not in [d.lower() for d in wl.protected_domains]:
                            wl.protected_domains.append(w_val_clean)
                            config_mgr.save_whitelist(wl)
                            st.rerun()
                    elif wl_entry_type == "Safe Keyword":
                        if w_val_clean not in [k.lower() for k in wl.protected_keywords]:
                            wl.protected_keywords.append(w_val_clean)
                            config_mgr.save_whitelist(wl)
                            st.rerun()

    # Active Whitelists
    w_c1, w_c2, w_c3 = st.columns(3)
    with w_c1:
        st.subheader("Trusted Senders")
        for s in list(wl.protected_senders):
            r1, r2 = st.columns([3, 1])
            r1.write(f"`{s}`")
            if r2.button("❌", key=f"del_wl_s_{s}"):
                wl.protected_senders.remove(s)
                config_mgr.save_whitelist(wl)
                st.rerun()

    with w_c2:
        st.subheader("Trusted Domains")
        for d in list(wl.protected_domains):
            r1, r2 = st.columns([3, 1])
            r1.write(f"`{d}`")
            if r2.button("❌", key=f"del_wl_d_{d}"):
                wl.protected_domains.remove(d)
                config_mgr.save_whitelist(wl)
                st.rerun()

    with w_c3:
        st.subheader("Protected Keywords")
        for k in list(wl.protected_keywords):
            r1, r2 = st.columns([3, 1])
            r1.write(f"`{k}`")
            if r2.button("❌", key=f"del_wl_k_{k}"):
                wl.protected_keywords.remove(k)
                config_mgr.save_whitelist(wl)
                st.rerun()

# -------------------------------------------------------------
# TAB 4: AUDIT LOG & UNDO
# -------------------------------------------------------------
with tab_audit:
    st.header("↩️ Audit Log & Undo / Rollback")
    st.markdown(
        "Every batch of emails moved to Trash is recorded here. "
        "If an email was trashed by mistake, you can **instantly undo the entire batch**."
    )

    batches = audit_logger.list_batches(limit=25)
    if not batches:
        st.info("No cleanup batches recorded yet.")
    else:
        for b in batches:
            bid = b["batch_id"]
            status = b["status"]
            ts = b["timestamp"][:19].replace("T", " ")
            count = b["total_messages"]

            with st.expander(f"📦 Batch: {bid} — {count} emails — {ts} UTC [{status}]", expanded=(status == "ACTIVE")):
                b_col1, b_col2 = st.columns([3, 1])
                with b_col1:
                    st.write(f"**Status**: `{status}` | **Action**: `{b['action_type']}` | **Messages**: `{count}`")
                with b_col2:
                    if status == "ACTIVE" and is_connected:
                        if st.button(f"↩️ Undo / Restore Batch", key=f"undo_{bid}", type="primary"):
                            try:
                                service = auth.get_service()
                                connector = GmailConnector(service)
                                entries = audit_logger.get_batch_entries(bid)
                                
                                with st.spinner(f"Restoring {len(entries)} emails from Trash..."):
                                    restored = 0
                                    for entry in entries:
                                        if connector.untrash_message(entry["message_id"]):
                                            restored += 1
                                
                                audit_logger.mark_batch_restored(bid)
                                st.success(f"Restored {restored} emails back to their original state!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to restore batch: {e}")
                    elif status == "RESTORED":
                        st.caption("✅ Already restored.")

                # Table of messages in batch
                entries = audit_logger.get_batch_entries(bid)
                if entries:
                    e_df = pd.DataFrame(entries)[["sender_email", "subject", "score", "reason", "trashed_at"]]
                    st.dataframe(e_df, use_container_width=True, hide_index=True)

# -------------------------------------------------------------
# TAB 5: SETUP & HELP
# -------------------------------------------------------------
with tab_setup:
    st.header("⚙️ Google Cloud OAuth Setup Guide")
    st.markdown("""
    To allow this local dashboard to connect to your Gmail safely without entering your password, 
    you need a free **Google Cloud OAuth Client ID**.

    ### 3-Minute Step-by-Step Setup:
    1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
    2. Create a new project (or select an existing one), e.g., `Spam Deleter`.
    3. In the search bar at the top, search for **Gmail API** and click **Enable**.
    4. Go to **APIs & Services** > **OAuth consent screen**:
       - Choose **External** (or Internal if on Google Workspace).
       - Fill in an App name (e.g. `Spam Deleter`) and your email address.
       - Under **Test users**, add your own Gmail address (this allows you to log in).
    5. Go to **APIs & Services** > **Credentials**:
       - Click **Create Credentials** > **OAuth client ID**.
       - Application type: Select **Desktop app**.
       - Click **Create**.
    6. Click **Download JSON** on the created client, rename the downloaded file to `credentials.json`, and place it in the root folder of this project:
       ```
       c:\\Users\\deban\\OneDrive\\Desktop\\Self Projects\\New Project\\credentials.json
       ```
    7. Return to the dashboard and click **Sign In with Google** in the sidebar. A Google login prompt will open in your browser asking for permission. Click **Allow**!
    """)

    st.divider()

    # Upload helper
    st.subheader("Upload `credentials.json` directly")
    uploaded = st.file_uploader("Upload your downloaded Google Cloud credentials.json", type=["json"])
    if uploaded is not None:
        target_path = WORKSPACE_ROOT / "credentials.json"
        with open(target_path, "wb") as f:
            f.write(uploaded.getbuffer())
        st.success("`credentials.json` uploaded and saved successfully! Refreshing...")
        st.rerun()
