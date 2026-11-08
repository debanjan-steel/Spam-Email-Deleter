"""Google OAuth 2.0 Authenticator supporting Web Redirect & Multiple Gmail Accounts.
Supports cloud deployment (Render, Streamlit Cloud, etc.) and mobile PWA usage.
"""
from pathlib import Path
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build, Resource

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify"
]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

class GmailAuthenticator:
    """Manages multi-account OAuth 2.0 authentication for desktop and cloud web apps."""

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

    def has_credentials_file(self) -> bool:
        """Checks if Google OAuth credentials.json exists."""
        return self.credentials_file.exists()

    def list_accounts(self) -> List[Dict[str, Any]]:
        """Lists all connected Gmail accounts and their basic stats."""
        accounts = []
        token_files = list(self.tokens_dir.glob("*.json"))

        for tf in token_files:
            try:
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
                        "messages_total": profile.get("messagesTotal", 0),
                        "threads_total": profile.get("threadsTotal", 0),
                        "token_file": str(tf),
                    })
            except Exception:
                continue

        return accounts

    def get_authorization_url(self, redirect_uri: str) -> Tuple[str, str]:
        """Generates Google OAuth consent URL for web & mobile browsers.
        
        Returns:
            (auth_url, state)
        """
        if not self.credentials_file.exists():
            raise FileNotFoundError(
                f"Missing '{self.credentials_file.name}'. "
                "Please place credentials.json in project root or upload via the Setup tab."
            )

        flow = Flow.from_client_secrets_file(
            str(self.credentials_file),
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
        """Exchanges an authorization code returned from Google redirect for tokens.
        
        Returns:
            Authenticated email address.
        """
        flow = Flow.from_client_secrets_file(
            str(self.credentials_file),
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

    def add_account_interactive(self) -> str:
        """Desktop loopback fallback."""
        if not self.credentials_file.exists():
            raise FileNotFoundError(
                f"Missing '{self.credentials_file.name}'. "
                "Please place credentials.json in project root."
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(self.credentials_file), SCOPES
        )
        creds = flow.run_local_server(port=0, prompt="consent")

        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress")

        if not email:
            raise ValueError("Could not retrieve email profile.")

        filename = f"{self._sanitize_email_for_filename(email)}.json"
        target_path = self.tokens_dir / filename
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(creds.to_json())

        return email

    def get_service_for_account(self, email: str) -> Resource:
        """Returns the authenticated Google Gmail API service client for a specific account."""
        filename = f"{self._sanitize_email_for_filename(email)}.json"
        token_path = self.tokens_dir / filename

        if not token_path.exists():
            raise FileNotFoundError(f"No credentials token found for account '{email}'.")

        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(creds.to_json())

        return build("gmail", "v1", credentials=creds)

    def remove_account(self, email: str) -> bool:
        """Disconnects an account by removing its token."""
        filename = f"{self._sanitize_email_for_filename(email)}.json"
        token_path = self.tokens_dir / filename
        if token_path.exists():
            os.remove(token_path)
            return True
        return False
