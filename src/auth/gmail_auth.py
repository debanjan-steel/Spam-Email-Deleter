"""Google OAuth 2.0 Authenticator for Gmail API.
Handles token retrieval, refresh, and interactive consent flow.
"""
from pathlib import Path
from typing import Optional, Tuple
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource

# Scopes needed to read messages, modify labels, and move messages to Trash
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify"
]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

class GmailAuthenticator:
    """Manages OAuth 2.0 authentication for the Gmail API."""

    def __init__(
        self,
        credentials_file: Path = WORKSPACE_ROOT / "credentials.json",
        token_file: Path = WORKSPACE_ROOT / "token.json",
    ):
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.creds: Optional[Credentials] = None
        self.service: Optional[Resource] = None

    def has_credentials_file(self) -> bool:
        """Checks if the client secrets credentials.json exists."""
        return self.credentials_file.exists()

    def has_saved_token(self) -> bool:
        """Checks if token.json exists."""
        return self.token_file.exists()

    def get_credentials(self) -> Credentials:
        """Retrieves valid user credentials from storage, refresh token, or web consent flow."""
        creds = None

        if self.token_file.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(self.token_file), SCOPES)
            except Exception:
                creds = None

        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception:
                    creds = None

            if not creds:
                if not self.credentials_file.exists():
                    raise FileNotFoundError(
                        f"Missing '{self.credentials_file.name}'. "
                        "Please place your Google Cloud OAuth Client credentials.json in the project root."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(self.credentials_file), SCOPES
                )
                creds = flow.run_local_server(port=0)

            # Save the credentials for the next run
            with open(self.token_file, "w", encoding="utf-8") as token:
                token.write(creds.to_json())

        self.creds = creds
        return creds

    def get_service(self) -> Resource:
        """Returns the authenticated Google Gmail API service client."""
        if self.service is None:
            creds = self.get_credentials()
            self.service = build("gmail", "v1", credentials=creds)
        return self.service

    def get_profile(self) -> Tuple[Optional[str], Optional[int]]:
        """Returns (emailAddress, totalMessages) for the authenticated user."""
        try:
            service = self.get_service()
            profile = service.users().getProfile(userId="me").execute()
            return profile.get("emailAddress"), profile.get("messagesTotal")
        except Exception as e:
            return None, None

    def logout(self) -> None:
        """Removes local token file to reset session."""
        self.creds = None
        self.service = None
        if self.token_file.exists():
            os.remove(self.token_file)
