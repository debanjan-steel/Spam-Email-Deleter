"""Google OAuth 2.0 and IMAP App Password Authenticator.
Supports both Google OAuth tokens and Google App Passwords for zero-restriction Gmail access.
"""
from pathlib import Path
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build, Resource

from src.connectors.gmail_connector import GmailConnector
from src.connectors.imap_connector import GmailImapConnector

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify"
]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

class GmailAuthenticator:
    """Manages multi-account authentication via both OAuth 2.0 and Google App Passwords."""

    def __init__(
        self,
        credentials_file: Path = WORKSPACE_ROOT / "credentials.json",
        tokens_dir: Path = WORKSPACE_ROOT / "tokens",
    ):
        self.credentials_file = credentials_file
        self.tokens_dir = tokens_dir
        self.tokens_dir.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_token()

    def _sanitize_email_for_filename(self, email: str) -> str:
        """Sanitizes email address for safe file storage."""
        return re.sub(r"[^\w\.-]", "_", email.lower())

    def _migrate_legacy_token(self) -> None:
        """Migrates a single root token.json to tokens/{email}.json if it exists."""
        legacy_token = WORKSPACE_ROOT / "token.json"
        if legacy_token.exists() and not any(self.tokens_dir.glob("*.json")):
            try:
                creds = Credentials.from_authorized_user_file(str(legacy_token), SCOPES)
                if creds and (creds.valid or (creds.expired and creds.refresh_token)):
                    if creds.expired:
                        creds.refresh(Request())
                    service = build("gmail", "v1", credentials=creds)
                    profile = service.users().getProfile(userId="me").execute()
                    email = profile.get("emailAddress")
                    if email:
                        target = self.tokens_dir / f"{self._sanitize_email_for_filename(email)}.json"
                        with open(target, "w", encoding="utf-8") as f:
                            f.write(creds.to_json())
            except Exception:
                pass

    def get_client_config(self) -> Optional[Dict[str, Any]]:
        """Retrieves Google OAuth client config from file or Streamlit secrets."""
        if self.credentials_file.exists():
            try:
                with open(self.credentials_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._ensure_redirect_uris(data)
                    return data
            except Exception:
                pass

        try:
            import streamlit as st
            sec_dict = st.secrets.to_dict()
            if "web" in sec_dict:
                data = {"web": dict(sec_dict["web"])}
                self._ensure_redirect_uris(data)
                return data
            if "gcp_oauth" in sec_dict:
                data = dict(sec_dict["gcp_oauth"])
                self._ensure_redirect_uris(data)
                return data
        except Exception:
            pass

        return None

    def _ensure_redirect_uris(self, data: Dict[str, Any]) -> None:
        """Ensures redirect_uris key exists in client config."""
        key = "web" if "web" in data else ("installed" if "installed" in data else None)
        if key:
            if "redirect_uris" not in data[key]:
                data[key]["redirect_uris"] = [
                    "https://spam-email-deleter.streamlit.app",
                    "http://localhost:8501"
                ]

    def has_credentials_file(self) -> bool:
        """Checks if Google OAuth credentials exist via file or secrets."""
        return self.get_client_config() is not None

    def add_app_password_account(self, email_address: str, app_password: str) -> Tuple[bool, str]:
        """Validates and stores a Gmail account using Google App Password (IMAP).
        
        Returns:
            (success, message)
        """
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

    def list_accounts(self) -> List[Dict[str, Any]]:
        """Lists all connected Gmail accounts (both OAuth and App Password)."""
        accounts = []
        token_files = list(self.tokens_dir.glob("*.json"))

        for tf in token_files:
            try:
                with open(tf, "r", encoding="utf-8") as f:
                    content = json.load(f)

                # Check if it's an App Password account
                if content.get("type") == "app_password":
                    accounts.append({
                        "email": content["email"],
                        "type": "app_password",
                        "messages_total": content.get("messages_total", 0),
                        "token_file": str(tf),
                    })
                    continue

                # Otherwise it's an OAuth account
                creds = Credentials.from_authorized_user_file(str(tf), SCOPES)
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    with open(tf, "w", encoding="utf-8") as f:
                        f.write(creds.to_json())

                if creds and creds.valid:
                    service = build("gmail", "v1", credentials=creds)
                    profile = service.users().getProfile(userId="me").execute()
                    email = profile.get("emailAddress", tf.stem)
                    accounts.append({
                        "email": email,
                        "type": "oauth",
                        "messages_total": profile.get("messagesTotal", 0),
                        "threads_total": profile.get("threadsTotal", 0),
                        "token_file": str(tf),
                    })
            except Exception:
                continue

        return accounts

    def get_connector_for_account(self, email: str) -> Union[GmailConnector, GmailImapConnector]:
        """Returns the appropriate connector (OAuth Gmail API or IMAP) for the given account."""
        filename = f"{self._sanitize_email_for_filename(email)}.json"
        token_path = self.tokens_dir / filename

        if not token_path.exists():
            raise FileNotFoundError(f"No credentials found for account '{email}'.")

        with open(token_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        # App Password account
        if content.get("type") == "app_password":
            return GmailImapConnector(content["email"], content["app_password"])

        # OAuth account
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(creds.to_json())

        service = build("gmail", "v1", credentials=creds)
        return GmailConnector(service)

    def get_authorization_url(self, redirect_uri: str) -> Tuple[str, str]:
        """Generates Google OAuth consent URL for web & mobile browsers."""
        config = self.get_client_config()
        if not config:
            raise FileNotFoundError(
                "Missing Google OAuth credentials. Place credentials.json in project root "
                "or add gcp_oauth to Streamlit Secrets."
            )

        flow = Flow.from_client_config(
            config,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        return auth_url, state

    def exchange_code(self, code: str, redirect_uri: str) -> str:
        """Exchanges an authorization code returned from Google redirect for tokens."""
        config = self.get_client_config()
        if not config:
            raise FileNotFoundError("Missing Google OAuth credentials.")

        flow = Flow.from_client_config(
            config,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
        )
        flow.fetch_token(code=code)
        creds = flow.credentials

        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress")

        if not email:
            raise ValueError("Could not retrieve email profile for authorized account.")

        filename = f"{self._sanitize_email_for_filename(email)}.json"
        target_path = self.tokens_dir / filename
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(creds.to_json())

        return email

    def remove_account(self, email: str) -> bool:
        """Disconnects and deletes a connected mailbox by removing its stored token file."""
        if not email:
            return False
        clean_email = email.strip().lower()
        filename = f"{self._sanitize_email_for_filename(clean_email)}.json"
        token_path = self.tokens_dir / filename
        removed = False
        if token_path.exists():
            try:
                os.remove(token_path)
                removed = True
            except Exception:
                pass

        # Also inspect and clean any other matching token files for this email
        for tf in list(self.tokens_dir.glob("*.json")):
            try:
                with open(tf, "r", encoding="utf-8") as f:
                    content = json.load(f)
                if content.get("email", "").strip().lower() == clean_email:
                    os.remove(tf)
                    removed = True
            except Exception:
                pass
        return removed

    def remove_all_accounts(self) -> int:
        """Disconnects and deletes all connected mailboxes by purging stored token files."""
        count = 0
        for tf in list(self.tokens_dir.glob("*.json")):
            try:
                os.remove(tf)
                count += 1
            except Exception:
                pass
        return count
