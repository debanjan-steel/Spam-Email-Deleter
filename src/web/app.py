"""Streamlit Web Dashboard for Intelligent Spam Email Deleter.
Pure Google App Passwords architecture for seamless, restriction-free Gmail access.
"""
import sys
import importlib
from datetime import datetime
from pathlib import Path
import uuid
import re
import json

# Ensure repository root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

# Force reload local src modules on execution so new methods are never stale in memory
for mod_name in list(sys.modules.keys()):
    if mod_name.startswith("src.") or mod_name == "src":
        try:
            importlib.reload(sys.modules[mod_name])
        except Exception:
            pass

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from src.connectors.imap_connector import GmailImapConnector
from src.connectors.gmail_connector import EmailMessage, GmailConnector
from src.auth.gmail_auth import GmailAuthenticator
from src.auth.user_manager import UserManager
from src.config_loader import ConfigManager
from src.engine.custom_rules import CustomRulesMatcher
from src.engine.spam_scorer import ClassificationResult, SpamScorer
from src.engine.whitelist_guard import WhitelistGuard
from src.storage.audit_logger import AuditLogger

# Guaranteed fail-safe: Ensure add_app_password_account exists on GmailAuthenticator
if not hasattr(GmailAuthenticator, "add_app_password_account"):
    def _add_app_password_account(self, email_address: str, app_password: str):
        clean_email = email_address.strip().lower()
        connector = GmailImapConnector(clean_email, app_password)
        success, err, total_msgs = connector.test_connection()

        if not success:
            return False, f"Could not connect to Gmail: {err}. Please verify your 16-character App Password."

        filename = f"{self._sanitize_email_for_filename(clean_email)}.json"
        target_path = self.tokens_dir / filename

        data = {
            "type": "app_password",
            "email": clean_email,
            "app_password": re.sub(r"\s+", "", app_password),
            "messages_total": total_msgs,
        }
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return True, f"Successfully connected {clean_email}!"

    GmailAuthenticator.add_app_password_account = _add_app_password_account

if not hasattr(GmailAuthenticator, "get_connector_for_account"):
    def _get_connector_for_account(self, email: str):
        filename = f"{self._sanitize_email_for_filename(email)}.json"
        token_path = self.tokens_dir / filename

        if not token_path.exists():
            raise FileNotFoundError(f"No credentials found for account '{email}'.")

        with open(token_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        if content.get("type") == "app_password":
            return GmailImapConnector(content["email"], content["app_password"])

        from src.auth.gmail_auth import SCOPES
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build

        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(creds.to_json())

        service = build("gmail", "v1", credentials=creds)
        return GmailConnector(service)

    GmailAuthenticator.get_connector_for_account = _get_connector_for_account

st.set_page_config(
    page_title="Gmail Spam Deleter & Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject PWA Manifest & Service Worker for 1-Click App Installation on Mobile & Desktop
pwa_header_html = """
<link rel="manifest" href="/app/static/manifest.json">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#FF4B4B">
<meta name="mobile-web-app-capable" content="yes">
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
st.html(pwa_header_html, unsafe_allow_javascript=True)

# Inject Mobile & Desktop Responsive Styles
responsive_css = """
<style>
/* Base Viewport & Horizontal Scroll Lock */
html, body, [data-testid="stAppViewContainer"], .main {
    overflow-x: hidden !important;
    max-width: 100vw !important;
}

/* Touch-friendly buttons (minimum 44px tap target height) */
button[data-testid="stBaseButton-primary"],
button[data-testid="stBaseButton-secondary"] {
    min-height: 46px !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    touch-action: manipulation !important;
}

/* Prevent mobile auto-zoom on input focus */
input, select, textarea {
    font-size: 16px !important;
}

/* Horizontally swipeable tabs with touch inertia */
.stTabs [data-baseweb="tab-list"] {
    gap: 6px !important;
    overflow-x: auto !important;
    overflow-y: hidden !important;
    flex-wrap: nowrap !important;
    -webkit-overflow-scrolling: touch !important;
    scrollbar-width: thin !important;
    padding-bottom: 6px !important;
}
.stTabs [data-baseweb="tab"] {
    flex-shrink: 0 !important;
    white-space: nowrap !important;
    font-size: 0.92rem !important;
    padding: 8px 14px !important;
    border-radius: 6px !important;
}

/* Responsive Rules for Mobile (Android & iPhone <= 768px) */
@media (max-width: 768px) {
    /* Maximize horizontal screen real estate */
    .block-container {
        padding-left: 0.8rem !important;
        padding-right: 0.8rem !important;
        padding-top: 1rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 100% !important;
    }

    /* Wrap multi-columns naturally on phone */
    [data-testid="stHorizontalBlock"] {
        flex-wrap: wrap !important;
        gap: 10px !important;
    }
    
    /* Hide empty spacer columns on phone screens */
    [data-testid="column"]:empty {
        display: none !important;
    }

    /* Metric cards: 2 cards per row on mobile */
    [data-testid="stHorizontalBlock"]:has([data-testid="stMetric"]) > [data-testid="column"] {
        flex: 1 1 calc(50% - 10px) !important;
        min-width: 135px !important;
    }
    [data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.04) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 10px !important;
        padding: 10px 12px !important;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.8rem !important;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.35rem !important;
    }

    /* Ensure tables scroll smoothly within their container without breaking page layout */
    [data-testid="stDataFrame"], [data-testid="stDataEditor"] {
        width: 100% !important;
        max-width: 100% !important;
        overflow-x: auto !important;
    }
}
</style>
"""
st.markdown(responsive_css, unsafe_allow_html=True)

# Initialize User Manager for Multi-Tenant Isolation
user_mgr: UserManager = UserManager()

# Check Authentication Status
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "active_session_token" not in st.session_state:
    st.session_state.active_session_token = None

# Auto-Login via HTTP Cookie (0-redirect, instant) or URL query parameter
cookie_token = st.context.cookies.get("mail_guard_device_token")
url_token = st.query_params.get("session_token")
detected_token = cookie_token or url_token

if not st.session_state.current_user and detected_token:
    u_data = user_mgr.validate_session(detected_token)
    if u_data:
        st.session_state.current_user = u_data
        st.session_state.active_session_token = detected_token
        st.session_state.active_account = None
        st.session_state.scan_results = []
        st.session_state.selected_mids = set()
        if url_token:
            st.query_params.clear()
            st.rerun()
    else:
        # Invalid or expired session: clear parameter and mark for removal from client
        if url_token:
            st.query_params.clear()
        st.session_state.clear_device_token = True

if not st.session_state.current_user:
    # ---------------------------------------------------------
    # AUTHENTICATION SCREEN: LOGIN & CREATE ACCOUNT
    # ---------------------------------------------------------

    # 1. Clear device cookie & localStorage if logged out or token expired
    if st.session_state.get("clear_device_token"):
        st.session_state.pop("clear_device_token")
        clear_cookie_html = """
        <script>
        (function() {
            try {
                var isSecure = window.location.protocol === 'https:' ? '; Secure' : '';
                document.cookie = 'mail_guard_device_token=; path=/; max-age=0; SameSite=Lax' + isSecure;
                localStorage.removeItem('mail_guard_device_token');
                var url = new URL(window.location.href);
                if (url.searchParams.has('session_token')) {
                    url.searchParams.delete('session_token');
                    window.history.replaceState({}, '', url.href);
                }
            } catch (e) {
                console.error('Error clearing device token:', e);
            }
        })();
        </script>
        """
        st.html(clear_cookie_html, unsafe_allow_javascript=True)
    else:
        # 2. Client-side fallback: If device has saved token in localStorage or cookie, auto-restore
        restore_storage_html = """
        <script>
        (function() {
            try {
                var token = localStorage.getItem('mail_guard_device_token');
                if (!token) {
                    var match = document.cookie.match(/(?:^|; )mail_guard_device_token=([^;]*)/);
                    if (match && match[1]) {
                        token = decodeURIComponent(match[1]);
                        localStorage.setItem('mail_guard_device_token', token);
                    }
                }
                if (token) {
                    var isSecure = window.location.protocol === 'https:' ? '; Secure' : '';
                    var maxAge = 60 * 60 * 24 * 365;
                    document.cookie = 'mail_guard_device_token=' + encodeURIComponent(token) + '; path=/; max-age=' + maxAge + '; SameSite=Lax' + isSecure;
                    var url = new URL(window.location.href);
                    if (!url.searchParams.has('session_token')) {
                        url.searchParams.set('session_token', token);
                        window.location.replace(url.href);
                    }
                }
            } catch (e) {
                console.error('LocalStorage check error:', e);
            }
        })();
        </script>
        """
        st.html(restore_storage_html, unsafe_allow_javascript=True)

    col_l, col_main, col_r = st.columns([1, 2, 1])
    with col_main:
        st.markdown("<h1 style='text-align: center;'>🛡️ Mail Guard</h1>", unsafe_allow_html=True)
        st.markdown(
            "<p style='text-align: center; color: #888;'>Multi-User Gmail Cleaner & Intelligent Spam Deleter</p>",
            unsafe_allow_html=True
        )
        st.write("")

        tab_login, tab_register = st.tabs(["🔑 Sign In", "✨ Create Account"])

        with tab_login:
            st.subheader("Sign In to Your Account")
            st.caption("Access your private Gmail accounts and spam deletion rules.")
            with st.form("login_form", clear_on_submit=False):
                login_gmail = st.text_input("Gmail Address", placeholder="e.g. yourname@gmail.com", key="login_gmail_input")
                login_pass = st.text_input("Password", type="password", placeholder="Enter your account password", key="login_pass_input")
                btn_login = st.form_submit_button("🚀 Sign In", type="primary", use_container_width=True)

            if btn_login:
                ok, msg, u_data = user_mgr.authenticate(login_gmail, login_pass)
                if ok:
                    # Issue persistent device session token
                    device_tok = user_mgr.create_session(u_data["id"])
                    st.session_state.current_user = u_data
                    st.session_state.active_session_token = device_tok
                    st.session_state.set_device_token = device_tok
                    st.session_state.active_account = None
                    st.session_state.scan_results = []
                    st.session_state.selected_mids = set()
                    st.success(f"🎉 {msg}")
                    st.rerun()
                else:
                    st.error(msg)

            # Forgot Password Recovery
            with st.expander("❓ Forgot Password?", expanded=False):
                st.markdown("Enter your registered Gmail address below. We'll send an email with your exact account password.")
                rec_gmail = st.text_input("Recovery Gmail Address", placeholder="e.g. yourname@gmail.com", key="rec_gmail_input")
                btn_recover = st.button("📬 Send Password to My Gmail", key="btn_send_recovery", use_container_width=True)
                if btn_recover:
                    if not rec_gmail:
                        st.warning("Please enter your registered Gmail address.")
                    else:
                        with st.spinner(f"Retrieving password for {rec_gmail}..."):
                            ok, msg, _ = user_mgr.recover_password(rec_gmail)
                        if ok:
                            st.success(f"🎉 {msg}")
                        else:
                            st.error(msg)

        with tab_register:
            st.subheader("Create a New Account")
            st.caption("Each account gets a dedicated, 100% private sandbox for unlimited Gmail accounts.")
            with st.form("register_form", clear_on_submit=False):
                reg_gmail = st.text_input("Gmail Address", placeholder="e.g. yourname@gmail.com", key="reg_gmail_input")
                reg_pass = st.text_input("Password", type="password", placeholder="At least 6 characters", key="reg_pass_input")
                reg_confirm = st.text_input("Confirm Password", type="password", placeholder="Re-type your password", key="reg_confirm_input")
                btn_register = st.form_submit_button("✨ Create Account", type="primary", use_container_width=True)

            if btn_register:
                clean_reg_gmail = reg_gmail.strip().lower()
                if not reg_gmail or not clean_reg_gmail:
                    st.warning("Please enter your Gmail address.")
                elif not reg_pass:
                    st.warning("Please enter a password.")
                elif reg_pass != reg_confirm:
                    st.error("Passwords do not match. Please verify your password.")
                elif len(reg_pass) < 6:
                    st.error("Password must be at least 6 characters long.")
                elif user_mgr.user_exists(clean_reg_gmail):
                    st.error(f"❌ **Gmail already in use**: An account with `{clean_reg_gmail}` already exists. Please switch to the **Sign In** tab to access your account.")
                else:
                    ok, msg, u_data = user_mgr.create_user(reg_gmail, reg_pass)
                    if ok:
                        # Issue persistent device session token
                        device_tok = user_mgr.create_session(u_data["id"])
                        st.session_state.current_user = u_data
                        st.session_state.active_session_token = device_tok
                        st.session_state.set_device_token = device_tok
                        st.session_state.active_account = None
                        st.session_state.scan_results = []
                        st.session_state.selected_mids = set()
                        st.success(f"🎉 {msg}")
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")

        st.divider()
        st.markdown("""
        🔒 **Multi-User Isolation & Privacy Guaranteed**:
        - **Persistent Device Login**: Stay logged in on your private phone or laptop until you manually tap Logout.
        - **Safe Link Sharing**: If you share this app link with a friend, they will see a fresh login page to create their own isolated account.
        - **Private Gmail Mailboxes**: Connected Gmail accounts and App Passwords are saved only in your private workspace.
        - **Custom Rules & Whitelists**: Your protected senders and custom blacklist keywords are completely isolated.
        """)

    st.stop()

# -------------------------------------------------------------
# USER IS AUTHENTICATED: LOAD USER-ISOLATED WORKSPACE
# -------------------------------------------------------------
current_user = st.session_state.current_user

# Persist device token to browser cookie & localStorage if newly authenticated
if st.session_state.get("set_device_token"):
    tok_to_store = st.session_state.pop("set_device_token")
    save_cookie_html = f"""
    <script>
    (function() {{
        try {{
            var token = "{tok_to_store}";
            var maxAge = 60 * 60 * 24 * 365; // 1 year
            var isSecure = window.location.protocol === 'https:' ? '; Secure' : '';
            document.cookie = "mail_guard_device_token=" + encodeURIComponent(token) + "; path=/; max-age=" + maxAge + "; SameSite=Lax" + isSecure;
            localStorage.setItem("mail_guard_device_token", token);
            var url = new URL(window.location.href);
            if (url.searchParams.has("session_token")) {{
                url.searchParams.delete("session_token");
                window.history.replaceState({{}}, "", url.href);
            }}
        }} catch(e) {{
            console.error("Error setting persistent device session:", e);
        }}
    }})();
    </script>
    """
    st.html(save_cookie_html, unsafe_allow_javascript=True)

user_paths = user_mgr.get_user_paths(current_user["id"])

# Initialize Managers scoped exclusively to the active user's sandbox
config_mgr: ConfigManager = ConfigManager(config_dir=user_paths["config_dir"])
audit_logger: AuditLogger = AuditLogger(db_path=user_paths["audit_db"])
auth: GmailAuthenticator = GmailAuthenticator(tokens_dir=user_paths["tokens_dir"])

st.session_state.config_mgr = config_mgr
st.session_state.audit_logger = audit_logger
st.session_state.auth = auth

# Initialize Session UI State
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "selected_mids" not in st.session_state:
    st.session_state.selected_mids = set()
if "active_account" not in st.session_state:
    st.session_state.active_account = None

# Retrieve Connected Accounts for this specific user
connected_accounts = auth.list_accounts()
account_emails = [a["email"] for a in connected_accounts]

if account_emails:
    if st.session_state.active_account not in account_emails:
        st.session_state.active_account = account_emails[0]
else:
    st.session_state.active_account = None

active_account_email = st.session_state.active_account
active_account_info = next((a for a in connected_accounts if a["email"] == active_account_email), None)

# Sidebar: Multi-Account Switcher & User Profile
with st.sidebar:
    st.title("🛡️ Mail Guard")
    col_u1, col_u2 = st.columns([2.2, 1])
    with col_u1:
        st.markdown(f"👤 **{current_user.get('gmail', current_user.get('username', 'Account'))}**")
    with col_u2:
        if st.button("🚪 Logout", key="btn_user_logout", use_container_width=True):
            active_tok = st.session_state.get("active_session_token")
            if active_tok:
                user_mgr.revoke_session(active_tok)
            st.session_state.current_user = None
            st.session_state.active_account = None
            st.session_state.active_session_token = None
            st.session_state.scan_results = []
            st.session_state.selected_mids = set()
            st.session_state.clear_device_token = True
            st.query_params.clear()
            st.rerun()

    st.caption("Multi-User Gmail Cleaner & Spam Deleter")
    st.divider()

    st.subheader("📬 Connected Mailboxes")
    if connected_accounts:
        selected_email = st.selectbox(
            "Active Mailbox",
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
            st.success(f"**Connected**: `{active_account_email}`")
            total_msgs = active_account_info.get("messages_total", 0)
            col_cnt, col_rf = st.columns([3.5, 1])
            with col_cnt:
                st.caption(f"📬 Inbox Messages: **{total_msgs:,}**", help="Active message count in your Gmail Inbox. Note: Multi-category scans (Promotions, Social, Purchases, Spam) include emails from those separate folders outside your primary inbox.")
            with col_rf:
                if st.button("🔄", key="sidebar_refresh_total_btn", help="Sync latest mailbox count from Gmail"):
                    live_c = auth.refresh_account_messages_total(active_account_email)
                    if live_c > 0:
                        active_account_info["messages_total"] = live_c
                    st.rerun()

        with st.popover("🗑️ Delete / Disconnect Mailbox", use_container_width=True):
            st.markdown(f"**Delete `{active_account_email}`?**")
            st.caption("This will disconnect this mailbox and delete its saved App Password from your profile. Your emails in Gmail stay completely untouched.")
            if st.button("Confirm Delete Mailbox", key="sidebar_del_mb_btn", type="primary", use_container_width=True):
                auth.remove_account(active_account_email)
                st.warning(f"Deleted connected mailbox `{active_account_email}`.")
                st.session_state.active_account = None
                st.session_state.scan_results = []
                st.session_state.selected_mids = set()
                st.rerun()
    else:
        st.info("No accounts connected yet. Connect one below!")

    st.divider()
    st.markdown("### Safety Guarantee")
    st.markdown("✅ **Soft-delete only**: Items moved to Trash (30-day recovery window).")
    st.markdown("✅ **Zero-touch whitelist**: Personal contacts, 2FA codes, order receipts, and starred emails are never deleted.")
    st.markdown("✅ **Mobile PWA**: Open on your phone in Safari/Chrome and tap **Add to Home Screen** to install as a native app.")

# Main Application Tabs
tab_scan, tab_add_account, tab_rules, tab_whitelist, tab_audit, tab_settings, tab_policy = st.tabs([
    "🔍 Scan & Clean",
    "📬 Mailboxes & Accounts",
    "🎯 Custom Deletion Rules",
    "🛡️ Whitelist & Safeguards",
    "↩️ Audit Log & Undo",
    "⚙️ Settings",
    "📄 Privacy & Security Policy",
])

# -------------------------------------------------------------
# TAB 1: SCAN & CLEAN
# -------------------------------------------------------------
with tab_scan:
    if not active_account_email:
        st.header("📬 Connect Your Gmail Account")
        st.info("No Gmail account is connected yet. Enter your details below or switch to the **📬 Mailboxes & Accounts** tab for step-by-step instructions.")

        q_email = st.text_input("Gmail Address", placeholder="e.g. yourname@gmail.com", key="quick_acc_email")
        q_pass = st.text_input("16-Character Google App Password", placeholder="e.g. abcd efgh ijkl mnop", type="password", key="quick_acc_pass")
        if st.button("🚀 Connect Gmail Account", type="primary", key="quick_connect_btn", use_container_width=True):
            if not q_email or not q_pass:
                st.warning("Please enter both your Gmail address and 16-character App Password.")
            else:
                try:
                    with st.spinner(f"Connecting to Gmail for {q_email}..."):
                        ok, msg = auth.add_app_password_account(q_email, q_pass)
                    if ok:
                        st.success(f"🎉 {msg}")
                        st.session_state.active_account = q_email.strip().lower()
                        st.session_state.scan_results = []
                        st.rerun()
                    else:
                        st.error(msg)
                except Exception as e:
                    st.error(f"Error connecting account: {e}")
    else:
        st.header(f"🔍 Scan Mailbox: `{active_account_email}`")

        ALL_CATEGORIES = [
            "📥 Primary / Inbox",
            "🏷️ Promotions",
            "📢 Updates",
            "👥 Social",
            "💬 Forums",
            "🛍️ Purchases",
            "🚨 Spam",
            "⭐ Starred",
            "🏷️ Important",
            "📤 Sent Mail",
            "📝 Drafts",
            "🗑️ Trash",
            "📬 All Mail",
        ]

        DEFAULT_CATEGORIES = [
            "🏷️ Promotions",
            "🚨 Spam",
            "📢 Updates",
            "👥 Social",
            "💬 Forums",
        ]

        if "selected_folders" not in st.session_state:
            st.session_state.selected_folders = DEFAULT_CATEGORIES.copy()

        # Select All controls placed right on top
        col_hdr, col_all, col_none = st.columns([3, 1, 1])
        with col_hdr:
            st.markdown("##### 📂 Gmail Categories & Folders to Scan")
        with col_all:
            if st.button("✅ Select All (13)", key="btn_all_cats", use_container_width=True):
                st.session_state.selected_folders = ALL_CATEGORIES.copy()
                st.rerun()
        with col_none:
            if st.button("❌ Clear All", key="btn_clear_cats", use_container_width=True):
                st.session_state.selected_folders = []
                st.rerun()

        if "max_emails_input" not in st.session_state:
            st.session_state["max_emails_input"] = 1000

        def set_preset_limit(limit_val: int):
            st.session_state["max_emails_input"] = limit_val

        col1, col2, col3 = st.columns([2.5, 1.2, 1.3])
        with col1:
            folders_to_scan = st.multiselect(
                "Select Folders / Labels to Scan",
                options=ALL_CATEGORIES,
                default=st.session_state.selected_folders,
                help="Choose which Gmail categories or folders to search.",
                label_visibility="collapsed",
            )
            st.session_state.selected_folders = folders_to_scan

        with col2:
            max_emails = st.number_input(
                "Max Emails to Fetch",
                min_value=10,
                max_value=50000,
                step=250,
                key="max_emails_input",
                help="Total maximum emails to fetch across the selected categories. Supports up to 50,000 emails per scan.",
            )

        with col3:
            custom_query = st.text_input(
                "Optional Filter",
                placeholder="e.g. is:unread",
                help="Optional Gmail search filter (e.g. is:unread, older_than:30d)."
            )

        # Quick Preset Buttons for 1-Click Scan Limit Selection
        col_pres_label, col_p1, col_p2, col_p3, col_p4, col_p5, col_p6 = st.columns([1.6, 1, 1, 1, 1, 1.2, 1.2])
        with col_pres_label:
            st.caption("⚡ **Quick Limit Presets:**")
        with col_p1:
            st.button("500", key="p_btn_500", on_click=set_preset_limit, args=(500,), use_container_width=True)
        with col_p2:
            st.button("1,000", key="p_btn_1000", on_click=set_preset_limit, args=(1000,), use_container_width=True)
        with col_p3:
            st.button("2,500", key="p_btn_2500", on_click=set_preset_limit, args=(2500,), use_container_width=True)
        with col_p4:
            st.button("5,000", key="p_btn_5000", on_click=set_preset_limit, args=(5000,), use_container_width=True)
        with col_p5:
            is_active_10k = st.session_state.get("max_emails_input") == 10000
            st.button(
                "10,000 🚀",
                key="p_btn_10000",
                type="primary" if is_active_10k else "secondary",
                on_click=set_preset_limit,
                args=(10000,),
                use_container_width=True,
            )
        with col_p6:
            st.button("25,000", key="p_btn_25000", on_click=set_preset_limit, args=(25000,), use_container_width=True)

        btn_scan = st.button(f"▶️ Run Dry-Run Scan on {active_account_email} (Up to {max_emails:,} Emails)", type="primary")

        if btn_scan:
            try:
                connector = auth.get_connector_for_account(active_account_email)
                whitelist_guard = WhitelistGuard(
                    config_mgr.whitelist,
                    expire_security_alerts=config_mgr.app_config.detection.expire_old_security_alerts,
                    security_alerts_retention_days=config_mgr.app_config.detection.security_alerts_retention_days,
                    expire_categories=config_mgr.app_config.detection.expire_old_categories,
                    categories_retention_days=config_mgr.app_config.detection.categories_retention_days,
                    expired_categories=config_mgr.app_config.detection.expired_categories,
                )
                custom_rules = CustomRulesMatcher(config_mgr.custom_rules)
                scorer = SpamScorer(whitelist_guard, custom_rules, config_mgr.app_config.detection)

                all_mids = []
                mid_to_category = {}
                with st.spinner(f"Discovering message IDs from {active_account_email}..."):
                    if folders_to_scan:
                        # Dynamically fill quota across selected categories until max_emails limit is satisfied
                        for label in folders_to_scan:
                            current_unique = len(dict.fromkeys(all_mids))
                            remaining_needed = max_emails - current_unique
                            if remaining_needed <= 0:
                                break
                            mids = connector.list_message_ids(
                                query=custom_query or None,
                                label_ids=[label],
                                max_results=remaining_needed,
                            )
                            for m in mids:
                                if m not in mid_to_category:
                                    mid_to_category[m] = label
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
                    scan_progress = st.progress(0, text="Fetching and analyzing emails...")
                    def on_scan_progress(done, total):
                        pct = min(1.0, max(0.0, done / max(total, 1)))
                        scan_progress.progress(pct, text=f"Analyzing emails: {done:,} of {total:,} ({int(pct*100)}%)...")

                    messages = connector.get_messages_batch(unique_mids, progress_callback=on_scan_progress)

                    # Tag scanned category labels onto messages
                    for m in messages:
                        if m.id in mid_to_category:
                            cat_label = mid_to_category[m.id].lower()
                            if "promotion" in cat_label and "CATEGORY_PROMOTIONS" not in m.labels:
                                m.labels.append("CATEGORY_PROMOTIONS")
                            elif "social" in cat_label and "CATEGORY_SOCIAL" not in m.labels:
                                m.labels.append("CATEGORY_SOCIAL")
                            elif "purchase" in cat_label and "CATEGORY_PURCHASES" not in m.labels:
                                m.labels.append("CATEGORY_PURCHASES")

                    results = [scorer.evaluate(m) for m in messages]
                    scan_progress.empty()

                    # Live sync the current total messages in mailbox
                    try:
                        live_c = auth.refresh_account_messages_total(active_account_email)
                        if live_c > 0 and active_account_info:
                            active_account_info["messages_total"] = live_c
                    except Exception:
                        pass

                    st.session_state.scan_results = results
                    st.session_state.selected_mids = {
                        r.message_id for r in results if r.action in ("TARGETED_TRASH", "SPAM_TRASH")
                    }
                    if len(results) < max_emails:
                        st.info(f"ℹ️ Scan complete: Evaluated all {len(results):,} available emails across the selected categories (requested limit: up to {max_emails:,}).")
                    else:
                        st.success(f"🎉 Scan complete! Successfully evaluated {len(results):,} emails.")
            except Exception as e:
                st.error(f"Error during scan: {e}")

        # Render Results Table
        # Display persistent action banner from trashing action if present
        if st.session_state.get("trash_action_banner"):
            st.success(st.session_state.pop("trash_action_banner"))
            st.balloons()
        if st.session_state.get("trash_warning_banner"):
            st.warning(st.session_state.pop("trash_warning_banner"))

        results = st.session_state.scan_results
        if results:
            st.divider()

            total_count = len(results)
            prot_count = sum(1 for r in results if r.is_protected)
            manual_count = sum(1 for r in results if r.action == "TARGETED_TRASH")
            spam_count = sum(1 for r in results if r.action == "SPAM_TRASH")
            safe_count = sum(1 for r in results if r.action == "SAFE")
            cand_count = manual_count + spam_count

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Total Scanned", f"{total_count:,}")
            m2.metric("🛡️ Protected (Immune)", f"{prot_count:,}")
            m3.metric("🎯 Custom Rule Matches", f"{manual_count:,}")
            m4.metric("🚨 Auto-Detected Spam", f"{spam_count:,}")
            m5.metric("✅ Safe / Normal", f"{safe_count:,}")

            st.subheader(f"Candidate Emails ({active_account_email})")

            # Default to All Scanned if no deletion candidates remain
            filter_options = [
                f"🎯 Deletion Candidates ({cand_count:,})",
                f"📋 All Scanned Emails ({total_count:,})",
                f"🛡️ Safe & Protected Emails ({safe_count + prot_count:,})",
            ]
            default_filter_idx = 0 if cand_count > 0 else 1

            view_filter = st.radio(
                "Filter View:",
                filter_options,
                index=default_filter_idx,
                horizontal=True,
                key="results_view_filter",
            )

            if "Deletion Candidates" in view_filter:
                display_results = [r for r in results if r.action in ("TARGETED_TRASH", "SPAM_TRASH")]
            elif "Safe & Protected" in view_filter:
                display_results = [r for r in results if r.action in ("PROTECTED", "SAFE")]
            else:
                display_results = results

            col_a, col_b, col_c = st.columns([1.2, 1, 2])
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

            if not display_results:
                if "Deletion Candidates" in view_filter:
                    st.info("🎉 All spam and deletion candidates have been moved to Trash or none were found! Select **📋 All Scanned Emails** above to review safe emails.")
                else:
                    st.info("ℹ️ No emails found matching this filter view.")
            else:
                table_data = []
                for r in display_results:
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
                        "Sender": (r.sender or "")[:25],
                        "Email": r.sender_email or "",
                        "Subject": (r.subject or "(No Subject)")[:45],
                        "Date": r.date_str[:16] if r.date_str else "",
                        "Reason": r.reason or "",
                        "Message ID": r.message_id,
                    })

                TABLE_COLUMNS = ["Select", "Action", "Score", "Sender", "Email", "Subject", "Date", "Reason", "Message ID"]
                df = pd.DataFrame(table_data, columns=TABLE_COLUMNS)

                column_config = {
                    "Select": st.column_config.CheckboxColumn("🗑️", width="small", help="Select to trash"),
                    "Action": st.column_config.TextColumn("Status", width="small"),
                    "Sender": st.column_config.TextColumn("From", width="medium"),
                    "Subject": st.column_config.TextColumn("Subject", width="large"),
                    "Reason": st.column_config.TextColumn("Reason", width="medium"),
                    "Score": st.column_config.TextColumn("Score", width="small"),
                    "Date": st.column_config.TextColumn("Date", width="small"),
                    "Email": None,      # Hidden visually for mobile compactness
                    "Message ID": None, # Hidden visually for mobile compactness
                }
                edited_df = st.data_editor(
                    df,
                    disabled=["Action", "Score", "Sender", "Email", "Subject", "Date", "Reason", "Message ID"],
                    column_config=column_config,
                    hide_index=True,
                    use_container_width=True,
                    key=f"results_editor_{view_filter[:4]}"
                )

                # Preserve selection state accurately and safely across filtered views
                if not edited_df.empty and "Select" in edited_df.columns and "Message ID" in edited_df.columns:
                    checked_in_view = set(edited_df[edited_df["Select"] == True]["Message ID"].dropna().tolist())
                    unchecked_in_view = set(edited_df[edited_df["Select"] == False]["Message ID"].dropna().tolist())
                    st.session_state.selected_mids = (st.session_state.selected_mids - unchecked_in_view) | checked_in_view

            total_selected = len(st.session_state.selected_mids)
            if total_selected:
                st.write(f"**{total_selected:,} emails selected for deletion in {active_account_email}.**")
                if st.button(f"🗑️ Move {total_selected:,} Selected Emails to Trash ({active_account_email})", type="primary"):
                    try:
                        connector = auth.get_connector_for_account(active_account_email)
                        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
                        
                        trashed_results = []
                        trash_progress = st.progress(0, text="Moving emails to Trash...")
                        def on_trash_progress(done, total):
                            pct = min(1.0, max(0.0, done / max(total, 1)))
                            trash_progress.progress(pct, text=f"Moving to Trash: {done:,} of {total:,} ({int(pct*100)}%)...")

                        target_mids = list(st.session_state.selected_mids)
                        if hasattr(connector, "trash_messages_batch"):
                            trashed_mids_list = connector.trash_messages_batch(target_mids, progress_callback=on_trash_progress)
                            trashed_set = set(trashed_mids_list)
                            trashed_results = [r for r in results if r.message_id in trashed_set]
                        else:
                            for idx, r in enumerate(results):
                                if r.message_id in st.session_state.selected_mids:
                                    if connector.trash_message(r.message_id):
                                        trashed_results.append(r)
                                    on_trash_progress(idx + 1, total_selected)

                        trash_progress.empty()

                        if trashed_results:
                            audit_logger.record_batch(
                                batch_id,
                                trashed_results,
                                account_email=active_account_email,
                                action_type="TRASH"
                            )
                            # Live-sync mailbox total directly from Gmail first (prevents misleading temporary local math flash)
                            synced = False
                            try:
                                live_c = auth.refresh_account_messages_total(active_account_email)
                                if live_c > 0 and active_account_info:
                                    active_account_info["messages_total"] = live_c
                                    synced = True
                            except Exception:
                                pass

                            if not synced:
                                current_tot = active_account_info.get("messages_total", 0) if active_account_info else 0
                                new_tot = max(0, current_tot - len(trashed_results))
                                auth.update_account_messages_total(active_account_email, new_tot)
                                if active_account_info:
                                    active_account_info["messages_total"] = new_tot

                            st.session_state.trash_action_banner = (
                                f"🎉 Successfully moved {len(trashed_results):,} emails to Trash in `{active_account_email}`! "
                                f"(Batch ID: `{batch_id}`). You can review or restore them anytime in the 'Audit Log & Undo' tab."
                            )
                        else:
                            st.session_state.trash_warning_banner = "No emails were moved to trash."

                        trashed_mid_set = {r.message_id for r in trashed_results}
                        st.session_state.scan_results = [
                            r for r in results if r.message_id not in trashed_mid_set
                        ]
                        st.session_state.selected_mids -= trashed_mid_set
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to move items to trash: {e}")

# -------------------------------------------------------------
# TAB 2: CONNECTED MAILBOXES & ADD GMAIL ACCOUNT
# -------------------------------------------------------------
with tab_add_account:
    st.header("📬 Connected Mailboxes & Accounts")
    st.markdown(
        "Manage, switch, or delete your connected Gmail mailboxes, or connect a new Gmail account "
        "using a secure 16-character Google App Password."
    )

    st.subheader(f"📋 Your Connected Mailboxes ({len(connected_accounts)})")
    if connected_accounts:
        st.caption("The following Gmail mailboxes are connected to your account. You can switch between them or delete any mailbox below.")
        for idx, acc in enumerate(connected_accounts):
            acc_email = acc["email"]
            total_msgs = acc.get("messages_total", 0)
            is_active = (acc_email == active_account_email)

            with st.container(border=True):
                col_info, col_status, col_action = st.columns([3, 1.8, 1.5])
                with col_info:
                    st.markdown(f"**📧 `{acc_email}`**")
                    st.caption(f"Inbox Messages: **{total_msgs:,}** • Auth: **Google App Password**")
                with col_status:
                    if is_active:
                        st.markdown("<span style='color:#00CC96; font-weight:bold;'>🟢 Active Mailbox</span>", unsafe_allow_html=True)
                    else:
                        if st.button("🔄 Set as Active", key=f"tab2_activate_{acc_email}_{idx}", use_container_width=True):
                            st.session_state.active_account = acc_email
                            st.session_state.scan_results = []
                            st.session_state.selected_mids = set()
                            st.rerun()
                with col_action:
                    with st.popover("🗑️ Delete Mailbox", use_container_width=True):
                        st.markdown(f"**Delete `{acc_email}`?**")
                        st.caption("This will disconnect this mailbox and delete its saved App Password from your profile. Your actual Gmail messages will remain completely untouched.")
                        if st.button("Confirm Delete", key=f"tab2_del_{acc_email}_{idx}", type="primary", use_container_width=True):
                            auth.remove_account(acc_email)
                            if st.session_state.active_account == acc_email:
                                st.session_state.active_account = None
                                st.session_state.scan_results = []
                                st.session_state.selected_mids = set()
                            st.success(f"Deleted connected mailbox `{acc_email}`.")
                            st.rerun()

        if len(connected_accounts) > 1:
            st.write("")
            with st.popover("🚨 Disconnect / Delete All Mailboxes"):
                st.markdown("**Are you sure you want to delete all connected mailboxes?**")
                st.caption("All saved Gmail credentials in your private profile will be purged. Your emails in Gmail stay safe.")
                if st.button("Yes, Delete All Mailboxes", type="primary", key="tab2_del_all_btn"):
                    auth.remove_all_accounts()
                    st.session_state.active_account = None
                    st.session_state.scan_results = []
                    st.session_state.selected_mids = set()
                    st.success("All connected mailboxes have been deleted.")
                    st.rerun()
    else:
        st.info("No mailboxes are connected yet. Connect your Gmail account below to start scanning!")

    st.divider()

    st.subheader("➕ Connect with Google App Password")
    st.markdown(
        "Connect any Gmail account instantly using a secure **16-character Google App Password**. "
        "No Google Cloud Console setup, no test users, and zero permissions roadblocks!"
    )

    with st.container():
        input_email = st.text_input(
            "Gmail Address",
            placeholder="e.g. yourname@gmail.com",
            key="add_acc_email",
            help="The Gmail address you want to scan and clean."
        )
        input_pass = st.text_input(
            "16-Character Google App Password",
            placeholder="e.g. abcd efgh ijkl mnop",
            type="password",
            key="add_acc_pass",
            help="The 16-character code generated from your Google Account Security settings."
        )

        btn_connect = st.button("🚀 Connect Gmail Account", type="primary", use_container_width=True)

        if btn_connect:
            if not input_email or not input_pass:
                st.warning("Please enter both your Gmail address and 16-character App Password.")
            else:
                try:
                    with st.spinner(f"Connecting to Gmail for {input_email}..."):
                        ok, msg = auth.add_app_password_account(input_email, input_pass)
                    if ok:
                        st.success(f"🎉 {msg}")
                        st.session_state.active_account = input_email.strip().lower()
                        st.session_state.scan_results = []
                        st.rerun()
                    else:
                        st.error(msg)
                except Exception as e:
                    st.error(f"Error connecting account: {e}")

    st.divider()

    st.subheader("📖 How to Find & Generate Your Account's Google App Password")
    st.markdown("""
An **App Password** is a dedicated 16-character code Google generates specifically for third-party apps to access your Gmail via IMAP without ever sharing your actual Google password.

#### 4 Simple Steps (Takes ~30 seconds):
1. **Ensure 2-Step Verification is Enabled**:
   - Google requires 2-Step Verification before allowing App Passwords.
   - If not yet enabled, turn it on here: 👉 [myaccount.google.com/signinoptions/two-step-verification](https://myaccount.google.com/signinoptions/two-step-verification)
2. **Open the Direct App Passwords Page**:
   - Go directly to: 👉 **[myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)**
   - *(Make sure you are logged in with the Gmail account you want to connect)*.
3. **Generate the 16-Character Code**:
   - In the text box labeled **"App name"**, type `Spam Deleter` (or any label you prefer) and click **Create**.
4. **Copy & Connect**:
   - Google will show a yellow box with a **16-character code** (formatted like `abcd efgh ijkl mnop`).
   - Copy the code, paste it into the **16-Character Google App Password** field above, and click **Connect Gmail Account**!
""")
    st.info("💡 **Note**: Any spaces in your copied code are stripped automatically. You can safely revoke or delete this App Password anytime directly in your Google Account Security settings.")

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
        new_imp = st.checkbox("Protect Important Emails", value=wl.protection_flags.protect_important)

    if new_starred != wl.protection_flags.protect_starred or new_imp != wl.protection_flags.protect_important:
        wl.protection_flags.protect_starred = new_starred
        wl.protection_flags.protect_important = new_imp
        config_mgr.save_whitelist(wl)
        st.success("Updated protection flags!")

    st.divider()

    st.subheader("⏱️ Ephemeral Security & Sign-In Alerts Lifecycle")
    st.caption(
        "Automated sign-in notices and login alerts (from GitHub, Google, Microsoft, Apple, Steam, Discord, etc.) are critical when recent, "
        "but become obsolete inbox clutter over time. When enabled, login notifications older than your chosen safety window will be automatically flagged for cleanup even if the provider domain is whitelisted."
    )
    col_s1, col_s2 = st.columns([2, 1])
    with col_s1:
        new_expire = st.checkbox(
            "Auto-expire and trash old login & security alert emails",
            value=config_mgr.app_config.detection.expire_old_security_alerts,
            help="When checked, sign-in alerts (GitHub, Google, Microsoft, Apple, etc.) older than the safety retention period are sent to Trash. Recent alerts remain 100% protected."
        )
    with col_s2:
        retention_options = [7, 14, 21, 30]
        current_retention = config_mgr.app_config.detection.security_alerts_retention_days
        curr_idx = retention_options.index(current_retention) if current_retention in retention_options else 1
        new_retention = st.selectbox(
            "Safety Retention Window",
            options=retention_options,
            index=curr_idx,
            format_func=lambda x: f"{x} days ({'Recommended' if x == 14 else 'Aggressive' if x == 7 else 'Extended'})",
            disabled=not new_expire,
            help="14 days is recommended: provides a safe 2-week buffer for travel and holidays, while Google keeps its online activity log for 28 days."
        )

    if (
        new_expire != config_mgr.app_config.detection.expire_old_security_alerts
        or new_retention != config_mgr.app_config.detection.security_alerts_retention_days
    ):
        config_mgr.app_config.detection.expire_old_security_alerts = new_expire
        config_mgr.app_config.detection.security_alerts_retention_days = new_retention
        config_mgr.save_app_config(config_mgr.app_config)
        st.success("Updated security alerts lifecycle settings!")

    st.divider()

    st.subheader("🛍️ Ephemeral Categories Lifecycle (Promotions, Social & Purchases)")
    st.caption(
        "Promotional marketing emails, social network updates, and purchase/order delivery notifications are kept for 14 days. "
        "After the 14-day retention period, they are automatically flagged for cleanup. Starred emails remain 100% immune forever."
    )
    col_c1, col_c2 = st.columns([2, 1])
    with col_c1:
        new_cat_expire = st.checkbox(
            "Auto-expire and trash old Promotion, Social, and Purchase emails",
            value=config_mgr.app_config.detection.expire_old_categories,
            help="When checked, emails in Promotions, Social, or Purchases older than the retention period are sent to Trash. Recent ones remain protected."
        )
    with col_c2:
        cat_retention_options = [7, 14, 21, 30]
        curr_cat_ret = config_mgr.app_config.detection.categories_retention_days
        curr_cat_idx = cat_retention_options.index(curr_cat_ret) if curr_cat_ret in cat_retention_options else 1
        new_cat_retention = st.selectbox(
            "Category Retention Window",
            options=cat_retention_options,
            index=curr_cat_idx,
            format_func=lambda x: f"{x} days ({'Recommended' if x == 14 else 'Aggressive' if x == 7 else 'Extended'})",
            disabled=not new_cat_expire,
            key="cat_retention_selectbox",
            help="14 days is recommended: keeps recent receipts, order tracking, and social notices active while clearing old marketing clutter."
        )

    # Category selector checkboxes
    st.caption("Active Categories for Expiration:")
    ch_c1, ch_c2, ch_c3 = st.columns(3)
    curr_cats = config_mgr.app_config.detection.expired_categories
    with ch_c1:
        exp_promo = st.checkbox("🏷️ Promotions", value=("promotions" in curr_cats), disabled=not new_cat_expire)
    with ch_c2:
        exp_social = st.checkbox("👥 Social", value=("social" in curr_cats), disabled=not new_cat_expire)
    with ch_c3:
        exp_purchases = st.checkbox("🛍️ Purchases", value=("purchases" in curr_cats), disabled=not new_cat_expire)

    updated_cats = []
    if exp_promo:
        updated_cats.append("promotions")
    if exp_social:
        updated_cats.append("social")
    if exp_purchases:
        updated_cats.append("purchases")

    if (
        new_cat_expire != config_mgr.app_config.detection.expire_old_categories
        or new_cat_retention != config_mgr.app_config.detection.categories_retention_days
        or updated_cats != curr_cats
    ):
        config_mgr.app_config.detection.expire_old_categories = new_cat_expire
        config_mgr.app_config.detection.categories_retention_days = new_cat_retention
        config_mgr.app_config.detection.expired_categories = updated_cats
        config_mgr.save_app_config(config_mgr.app_config)
        st.success("Updated category lifecycle settings!")

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
                                total_to_restore = len(entries)
                                entry_mids = [e["message_id"] for e in entries]

                                restore_progress = st.progress(0, text=f"Restoring emails in {b_acc}...")
                                def on_restore_progress(done, total):
                                    pct = min(1.0, max(0.0, done / max(total, 1)))
                                    restore_progress.progress(pct, text=f"Restoring emails: {done:,} of {total:,} ({int(pct*100)}%)...")

                                if hasattr(connector, "untrash_messages_batch"):
                                    restored_mids = connector.untrash_messages_batch(entry_mids, progress_callback=on_restore_progress)
                                    restored = len(restored_mids)
                                else:
                                    restored = 0
                                    for idx, mid in enumerate(entry_mids):
                                        if connector.untrash_message(mid):
                                            restored += 1
                                        on_restore_progress(idx + 1, total_to_restore)

                                restore_progress.empty()
                                audit_logger.mark_batch_restored(bid)
                                st.success(f"Restored {restored:,} emails back in `{b_acc}`!")
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
# TAB 6: SETTINGS (CHANGE PASSWORD & DELETE ACCOUNT)
# -------------------------------------------------------------
with tab_settings:
    st.header("⚙️ Account Settings")
    user_gmail = current_user.get("gmail", current_user.get("username", "User"))
    st.markdown(f"Manage credentials and security settings for **`{user_gmail}`**.")

    st.divider()

    st.subheader("🔑 Change Password")
    st.caption("Update your Spam Deleter account password below.")
    with st.form("change_password_form", clear_on_submit=True):
        col_cp1, col_cp2, col_cp3 = st.columns(3)
        with col_cp1:
            old_pass = st.text_input("Type Old Password", type="password", key="cp_old_pass", placeholder="Current password")
        with col_cp2:
            new_pass = st.text_input("Type New Password", type="password", key="cp_new_pass", placeholder="At least 6 characters")
        with col_cp3:
            confirm_new_pass = st.text_input("Retype New Password", type="password", key="cp_confirm_pass", placeholder="Re-enter new password")

        btn_change_pass = st.form_submit_button("💾 Update Password", type="primary", use_container_width=True)

    if btn_change_pass:
        if not old_pass or not new_pass or not confirm_new_pass:
            st.warning("Please fill in all three password fields.")
        elif new_pass != confirm_new_pass:
            st.error("New passwords do not match. Please verify and retype.")
        elif len(new_pass) < 6:
            st.error("New password must be at least 6 characters long.")
        else:
            with st.spinner("Updating password..."):
                ok, msg = user_mgr.change_password(current_user["id"], old_pass, new_pass)
            if ok:
                new_tok = user_mgr.create_session(current_user["id"])
                st.session_state.active_session_token = new_tok
                st.session_state.set_device_token = new_tok
                st.success(f"🎉 {msg}")
                st.rerun()
            else:
                st.error(msg)

    st.divider()

    st.subheader("📬 Connected Mailboxes")
    st.caption("Manage or remove connected Gmail mailboxes associated with your account.")
    if connected_accounts:
        for idx, acc in enumerate(connected_accounts):
            acc_email = acc["email"]
            total_msgs = acc.get("messages_total", 0)
            c1, c2 = st.columns([3.5, 1.2])
            with c1:
                st.markdown(f"📧 **`{acc_email}`** ({total_msgs:,} messages)")
            with c2:
                with st.popover("🗑️ Delete", key=f"sett_del_pop_{acc_email}_{idx}", use_container_width=True):
                    st.markdown(f"Delete mailbox `{acc_email}`?")
                    st.caption("Removes saved App Password. Your emails in Gmail stay safe.")
                    if st.button("Confirm", key=f"sett_del_btn_{acc_email}_{idx}", type="primary", use_container_width=True):
                        auth.remove_account(acc_email)
                        if st.session_state.active_account == acc_email:
                            st.session_state.active_account = None
                            st.session_state.scan_results = []
                            st.session_state.selected_mids = set()
                        st.success(f"Deleted mailbox `{acc_email}`.")
                        st.rerun()
    else:
        st.info("No mailboxes are connected.")

    st.divider()

    st.subheader("🚨 Delete Your Account")
    st.warning(
        "⚠️ **Permanent Action**: Deleting your account will permanently wipe your account profile, "
        "all saved Gmail connections and App Passwords, custom deletion rules, and audit logs. "
        "This cannot be undone."
    )

    confirm_delete = st.checkbox(
        "I understand that deleting my account is permanent and all my data will be immediately destroyed.",
        key="confirm_account_deletion"
    )

    if st.button("🗑️ Delete My Account Permanently", type="secondary", use_container_width=True):
        if not confirm_delete:
            st.error("Please check the confirmation box above to proceed with account deletion.")
        else:
            with st.spinner("Deleting account and purging workspace..."):
                ok, msg = user_mgr.delete_user(current_user["id"])
            if ok:
                st.session_state.current_user = None
                st.session_state.active_account = None
                st.session_state.active_session_token = None
                st.session_state.clear_device_token = True
                st.session_state.scan_results = []
                st.session_state.selected_mids = set()
                st.query_params.clear()
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

# -------------------------------------------------------------
# TAB 7: PRIVACY & SECURITY POLICY
# -------------------------------------------------------------
with tab_policy:
    st.header("📄 Privacy & Security Policy")

    st.markdown("""
    **Effective Date:** 2026-11-08  
    **Application:** Spam Email Deleter (`https://spam-email-deleter.streamlit.app`)

    - **Purpose & Data Use**: This application connects to your Gmail account over secure SSL IMAP solely to identify spam/unsolicited emails and allow you to move them to Trash.
    - **No External Data Storage**: Your email content, contact lists, and headers are processed directly in your active session and are never sold, transferred, or stored on external advertising servers.
    - **Security**: App Passwords are kept encrypted locally in your isolated session. You can disconnect accounts or revoke App Passwords at any time in your Google Account Security settings.
    - **Developer Contact**: `debanjan17052002@gmail.com`
    """)
