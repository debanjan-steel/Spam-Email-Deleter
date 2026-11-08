"""Google OAuth 2.0 Authenticator supporting Multiple Gmail Accounts.
Allows connecting, listing, switching, and disconnecting multiple Gmail accounts.
"""
from pathlib import Path
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify"
]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

class GmailAuthenticator:
    """Manages multi-account OAuth 2.0 authentication for the Gmail API."""

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
                if creds and creds.valid or (creds.expired and creds.refresh_token):
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
                # If token is corrupt or revoked, keep file stem or delete
                continue

        return accounts

    def add_account(self) -> str:
        """Launches interactive browser OAuth flow to connect a new Gmail account.
        
        Returns:
            The authenticated user's email address.
        """
        if not self.credentials_file.exists():
            raise FileNotFoundError(
                f"Missing '{self.credentials_file.name}'. "
                "Please place your Google Cloud OAuth Client credentials.json in the project root."
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(self.credentials_file), SCOPES
        )
        creds = flow.run_local_server(port=0, prompt="consent")

        # Discover which email was signed in
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress")

        if not email:
            raise ValueError("Could not retrieve email profile for the newly authorized account.")

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
