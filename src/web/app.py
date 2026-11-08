"""Streamlit Web Dashboard for Intelligent Spam Email Deleter.
Supports Progressive Web App (PWA) installation, Google App Passwords, OAuth, and Multiple Gmail Accounts.
"""
import sys
from datetime import datetime
import json
from pathlib import Path
import uuid

# Ensure repository root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from src.auth.gmail_auth import GmailAuthenticator
from src.config_loader import ConfigManager
from src.connectors.gmail_connector import EmailMessage
from src.engine.custom_rules import CustomRulesMatcher
from src.engine.spam_scorer import ClassificationResult, SpamScorer
from src.engine.whitelist_guard import WhitelistGuard
from src.storage.audit_logger import AuditLogger

st.set_page_config(
    page_title="Gmail Spam Deleter & Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def get_current_redirect_uri() -> str:
    """Detects whether running locally or on Streamlit Cloud to set OAuth redirect URI."""
    if hasattr(st, "secrets") and "app_url" in st.secrets:
        return str(st.secrets["app_url"]).rstrip("/")
    try:
        host = st.context.headers.get("host", "")
        if "localhost" in host or "127.0.0.1" in host:
            return "http://localhost:8501"
        if host:
            return f"https://{host}"
    except Exception:
        pass
    return "https://spam-email-deleter.streamlit.app"

# Inject PWA Manifest & Service Worker for 1-Click App Installation on Mobile & Desktop
pwa_header_html = """
<link rel="manifest" href="/app/static/manifest.json">
<meta name="theme-color" content="#FF4B4B">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Spam Deleter">
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/app/static/sw.js')
        .then(reg => console.log('PWA ServiceWorker registered', reg))
        .catch(err => console.log('PWA ServiceWorker registration failed', err));
    });
  }
</script>
"""
components.html(pwa_header_html, height=0, width=0)

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
if "active_account" not in st.session_state:
    st.session_state.active_account = None

config_mgr: ConfigManager = st.session_state.config_mgr
audit_logger: AuditLogger = st.session_state.audit_logger
auth: GmailAuthenticator = st.session_state.auth

# Handle Web/Mobile OAuth Redirect Callback
query_params = st.query_params
if "code" in query_params:
    auth_code = query_params["code"]
    try:
        redirect_uri = get_current_redirect_uri()
        newly_connected = auth.exchange_code(auth_code, redirect_uri=redirect_uri)
        st.session_state.active_account = newly_connected
        st.query_params.clear()
        st.success(f"🎉 Successfully connected `{newly_connected}` via Google OAuth!")
        st.rerun()
    except Exception as e:
        st.query_params.clear()
        st.error(f"OAuth code exchange failed: {e}")

# Retrieve Connected Accounts
connected_accounts = auth.list_accounts()
account_emails = [a["email"] for a in connected_accounts]

if account_emails:
    if st.session_state.active_account not in account_emails:
        st.session_state.active_account = account_emails[0]
else:
    st.session_state.active_account = None

active_account_email = st.session_state.active_account
active_account_info = next((a for a in connected_accounts if a["email"] == active_account_email), None)

# Sidebar: Multi-Account Switcher & Connection Management
with st.sidebar:
    st.title("🛡️ Mail Guard")
    st.caption("Multi-Account Gmail Cleaner & Spam Deleter")
    st.divider()

    st.subheader("📬 Connected Accounts")
    if connected_accounts:
        selected_email = st.selectbox(
            "Switch Active Account",
            options=account_emails,
            index=account_emails.index(active_account_email) if active_account_email in account_emails else 0,
            key="account_selector",
        )
        if selected_email != st.session_state.active_account:
            st.session_state.active_account = selected_email
            st.session_state.scan_results = []
            st.session_state.selected_mids = set()
            st.rerun()

        if active_account_info:
            acc_type = active_account_info.get("type", "oauth")
            badge = "🔑 App Password" if acc_type == "app_password" else "🌐 Google OAuth"
            st.success(f"**Active**: `{active_account_email}`\n\n({badge})")
            total_msgs = active_account_info.get("messages_total", 0)
            st.caption(f"Total Mailbox Messages: {total_msgs:,}")

        if st.button("🗑️ Disconnect Active Account", use_container_width=True):
            auth.remove_account(active_account_email)
            st.warning(f"Disconnected `{active_account_email}`.")
            st.session_state.active_account = None
            st.session_state.scan_results = []
            st.rerun()
    else:
        st.info("No accounts connected yet. Add one below!")

    st.divider()
    st.markdown("### Safety Guarantee")
    st.markdown("✅ **Soft-delete only**: Items moved to Trash (30-day recovery window).")
    st.markdown("✅ **Zero-touch whitelist**: Personal contacts, 2FA codes, order receipts, and starred emails are never deleted.")
    st.markdown("✅ **Mobile PWA**: Open in Safari/Chrome on your phone and tap **Add to Home Screen**.")

# Main Application Tabs
tab_scan, tab_add_account, tab_rules, tab_whitelist, tab_audit, tab_cloud = st.tabs([
    "🔍 Scan & Clean",
    "➕ Add Gmail Account",
    "🎯 Custom Deletion Rules",
    "🛡️ Whitelist & Safeguards",
    "↩️ Audit Log & Undo",
    "☁️ Cloud Credentials & Policy",
])

# -------------------------------------------------------------
# TAB 1: SCAN & CLEAN
# -------------------------------------------------------------
with tab_scan:
    if not active_account_email:
        st.header("📬 Connect Your First Gmail Account")
        st.info("No Gmail account is active. Go to the **➕ Add Gmail Account** tab to connect your inbox in 10 seconds!")
    else:
        st.header(f"🔍 Scan Mailbox: `{active_account_email}`")

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
                help="Advanced search filters (e.g. is:unread)."
            )

        btn_scan = st.button(f"▶️ Run Dry-Run Scan on {active_account_email}", type="primary")

        if btn_scan:
            try:
                connector = auth.get_connector_for_account(active_account_email)
                whitelist_guard = WhitelistGuard(config_mgr.whitelist)
                custom_rules = CustomRulesMatcher(config_mgr.custom_rules)
                scorer = SpamScorer(whitelist_guard, custom_rules, config_mgr.app_config.detection)

                all_mids = []
                with st.spinner(f"Fetching message IDs from {active_account_email}..."):
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
                unique_mids = list(dict.fromkeys(all_mids))[:max_emails]

                if not unique_mids:
                    st.info("No emails found matching the selected criteria.")
                    st.session_state.scan_results = []
                else:
                    with st.spinner(f"Analyzing {len(unique_mids)} emails with safety & spam rules..."):
                        messages = connector.get_messages_batch(unique_mids)
                        results = [scorer.evaluate(m) for m in messages]
                        st.session_state.scan_results = results
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

            st.subheader(f"Candidate Emails ({active_account_email})")

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

            new_selected = set(
                edited_df[edited_df["Select"] == True]["Message ID"].tolist()
            )
            st.session_state.selected_mids = new_selected

            st.write(f"**{len(new_selected)} emails selected for deletion in {active_account_email}.**")

            if new_selected:
                if st.button(f"🗑️ Move {len(new_selected)} Selected Emails to Trash ({active_account_email})", type="primary"):
                    try:
                        connector = auth.get_connector_for_account(active_account_email)
                        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
                        
                        trashed_results = []
                        with st.spinner(f"Moving {len(new_selected)} emails to Trash in {active_account_email}..."):
                            for r in results:
                                if r.message_id in new_selected:
                                    success = connector.trash_message(r.message_id)
                                    if success:
                                        trashed_results.append(r)

                        audit_logger.record_batch(
                            batch_id,
                            trashed_results,
                            account_email=active_account_email,
                            action_type="TRASH"
                        )
                        
                        st.success(f"Moved {len(trashed_results)} emails to Trash in `{active_account_email}`! Batch ID: `{batch_id}`")
                        st.info("You can undo this anytime in the 'Audit Log & Undo' tab.")
                        
                        st.session_state.scan_results = [
                            r for r in results if r.message_id not in new_selected
                        ]
                        st.session_state.selected_mids = set()
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to move items to trash: {e}")

# -------------------------------------------------------------
# TAB 2: ADD GMAIL ACCOUNT (APP PASSWORD & OAUTH)
# -------------------------------------------------------------
with tab_add_account:
    st.header("➕ Connect a Gmail Account")

    st.markdown("""
    You can connect **any Gmail account** using a Google App Password without dealing with Google Cloud Console,
    test users, or verification!
    """)

    col_method1, col_method2 = st.columns(2)

    with col_method1:
        st.subheader("⚡ Method 1: Google App Password (Recommended)")
        st.markdown("""
        **Zero setup, zero test user limits. Works with ANY Gmail account in 30 seconds:**

        1. Go to **[myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)** in your browser *(sign in to the Gmail account you want to connect)*.
        2. Name it `Spam Deleter` and click **Create**.
        3. Google will show you a yellow box with a **16-character password** (e.g. `abcd efgh ijkl mnop`).
        4. Enter your email and that 16-character code below:
        """)

        input_email = st.text_input("Gmail Address", placeholder="e.g. yourname@gmail.com", key="imap_email")
        input_pass = st.text_input("16-Character App Password", placeholder="e.g. abcd efgh ijkl mnop", type="password", key="imap_pass")

        if st.button("🚀 Connect with App Password", type="primary", use_container_width=True):
            if not input_email or not input_pass:
                st.warning("Please enter both your Gmail address and 16-character App Password.")
            else:
                with st.spinner(f"Verifying and connecting {input_email}..."):
                    ok, msg = auth.add_app_password_account(input_email, input_pass)
                if ok:
                    st.success(msg)
                    st.session_state.active_account = input_email.strip().lower()
                    st.session_state.scan_results = []
                    st.rerun()
                else:
                    st.error(msg)

    with col_method2:
        st.subheader("🌐 Method 2: Sign In with Google (OAuth)")
        st.markdown("""
        Connect via Google's official OAuth consent window (requires adding your email to Test Users in Google Cloud Console).
        """)
        if not auth.has_credentials_file():
            st.info("OAuth credentials not configured yet. Use Method 1 for instant access!")
        else:
            try:
                auth_url, _ = auth.get_authorization_url(redirect_uri=get_current_redirect_uri())
                st.link_button("🔑 Sign In with Google", auth_url, use_container_width=True)
            except Exception as e:
                st.error(f"Error generating OAuth link: {e}")

# -------------------------------------------------------------
# TAB 3: CUSTOM DELETION RULES (MANUAL BLACKLIST)
# -------------------------------------------------------------
with tab_rules:
    st.header("🎯 User-Defined Manual Deletion Rules")
    st.markdown(
        "Define exact email addresses, domains, or subject keywords you want **automatically flagged for deletion**. "
        "These apply across all your connected accounts (unless protected by your Whitelist)."
    )

    custom_rules = config_mgr.custom_rules

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
# TAB 4: WHITELIST & SAFEGUARDS
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
# TAB 5: AUDIT LOG & UNDO
# -------------------------------------------------------------
with tab_audit:
    st.header("↩️ Audit Log & Undo / Rollback")
    st.markdown(
        "Every batch of emails moved to Trash is recorded here with the associated Gmail account. "
        "If an email was trashed by mistake, you can **instantly undo the entire batch**."
    )

    batches = audit_logger.list_batches(limit=30)
    if not batches:
        st.info("No cleanup batches recorded yet.")
    else:
        for b in batches:
            bid = b["batch_id"]
            b_acc = b.get("account_email") or "Unknown"
            status = b["status"]
            ts = b["timestamp"][:19].replace("T", " ")
            count = b["total_messages"]

            with st.expander(f"📦 Batch: {bid} — Account: {b_acc} — {count} emails — {ts} UTC [{status}]", expanded=(status == "ACTIVE")):
                b_col1, b_col2 = st.columns([3, 1])
                with b_col1:
                    st.write(f"**Account**: `{b_acc}` | **Status**: `{status}` | **Action**: `{b['action_type']}` | **Messages**: `{count}`")
                with b_col2:
                    if status == "ACTIVE":
                        if st.button(f"↩️ Undo / Restore Batch", key=f"undo_{bid}", type="primary"):
                            try:
                                connector = auth.get_connector_for_account(b_acc)
                                entries = audit_logger.get_batch_entries(bid)
                                
                                with st.spinner(f"Restoring {len(entries)} emails from Trash in {b_acc}..."):
                                    restored = 0
                                    for entry in entries:
                                        if connector.untrash_message(entry["message_id"]):
                                            restored += 1
                                
                                audit_logger.mark_batch_restored(bid)
                                st.success(f"Restored {restored} emails back in `{b_acc}`!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to restore batch: {e}")
                    elif status == "RESTORED":
                        st.caption("✅ Already restored.")

                entries = audit_logger.get_batch_entries(bid)
                if entries:
                    e_df = pd.DataFrame(entries)[["sender_email", "subject", "score", "reason", "trashed_at"]]
                    st.dataframe(e_df, use_container_width=True, hide_index=True)

# -------------------------------------------------------------
# TAB 6: PHONE & CLOUD 24/7 SETUP
# -------------------------------------------------------------
with tab_cloud:
    st.header("☁️ Cloud Credentials & Policy")

    st.subheader("📄 Application Privacy Policy")
    st.markdown("""
    **Effective Date:** 2026-11-08  
    **Application:** Spam Email Deleter (`https://spam-email-deleter.streamlit.app`)

    - **Purpose & Data Use**: This application connects to your Gmail account solely to identify spam/unsolicited emails and allow you to move them to Trash.
    - **No External Data Storage**: Your email content, contact lists, and headers are processed securely in your active session and are never sold, transferred, or stored on external advertising servers.
    - **Security**: Access tokens are kept encrypted. You can disconnect accounts at any time.
    - **Contact**: `debanjan17052002@gmail.com`
    """)
