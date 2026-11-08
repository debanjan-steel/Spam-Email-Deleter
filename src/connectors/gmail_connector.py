"""Gmail Connector for retrieving, inspecting, trashing, and restoring messages.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import email.utils

from googleapiclient.discovery import Resource

@dataclass
class EmailMessage:
    id: str
    thread_id: str
    sender: str
    sender_email: str
    sender_domain: str
    recipient: str
    subject: str
    date_str: str
    date: Optional[datetime]
    snippet: str
    labels: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    has_list_unsubscribe: bool = False
    auth_results: str = ""
    is_starred: bool = False
    is_important: bool = False

class GmailConnector:
    """Wrapper around Gmail API to interact with messages safely."""

    def __init__(self, service: Resource):
        self.service = service

    def parse_sender(self, from_header: str) -> tuple[str, str, str]:
        """Extracts (name, email_address, domain) from a From header."""
        name, address = email.utils.parseaddr(from_header)
        domain = address.split("@")[-1].lower() if "@" in address else ""
        return name, address.lower(), domain

    def parse_date(self, date_header: str) -> Optional[datetime]:
        """Parses RFC 2822 date header into datetime object."""
        try:
            parsed = email.utils.parsedate_to_datetime(date_header)
            return parsed
        except Exception:
            return None

    def list_message_ids(
        self,
        query: Optional[str] = None,
        label_ids: Optional[List[str]] = None,
        max_results: int = 50,
    ) -> List[str]:
        """Retrieves a list of message IDs matching the label or search query."""
        params: Dict[str, Any] = {
            "userId": "me",
            "maxResults": min(max_results, 500),
        }
        if query:
            params["q"] = query
        if label_ids:
            params["labelIds"] = label_ids

        result = self.service.users().messages().list(**params).execute()
        messages = result.get("messages", [])
        return [m["id"] for m in messages]

    def get_message(self, message_id: str) -> Optional[EmailMessage]:
        """Retrieves full metadata and parsed properties for a single message."""
        try:
            res = (
                self.service.users()
                .messages()
                .get(userId="me", id=message_id, format="metadata", metadataHeaders=[
                    "From", "To", "Subject", "Date", "List-Unsubscribe", 
                    "Authentication-Results", "Received-SPF"
                ])
                .execute()
            )

            headers_list = res.get("payload", {}).get("headers", [])
            headers_dict = {h["name"]: h["value"] for h in headers_list}

            from_raw = headers_dict.get("From", "")
            name, email_addr, domain = self.parse_sender(from_raw)

            date_raw = headers_dict.get("Date", "")
            date_obj = self.parse_date(date_raw)

            labels = res.get("labelIds", [])
            is_starred = "STARRED" in labels
            is_important = "IMPORTANT" in labels

            auth_results = headers_dict.get("Authentication-Results", "") + " " + headers_dict.get("Received-SPF", "")
            has_unsub = "List-Unsubscribe" in headers_dict

            return EmailMessage(
                id=res["id"],
                thread_id=res.get("threadId", ""),
                sender=name or email_addr,
                sender_email=email_addr,
                sender_domain=domain,
                recipient=headers_dict.get("To", ""),
                subject=headers_dict.get("Subject", "(No Subject)"),
                date_str=date_raw,
                date=date_obj,
                snippet=res.get("snippet", ""),
                labels=labels,
                headers=headers_dict,
                has_list_unsubscribe=has_unsub,
                auth_results=auth_results,
                is_starred=is_starred,
                is_important=is_important,
            )
        except Exception:
            return None

    def get_messages_batch(self, message_ids: List[str]) -> List[EmailMessage]:
        """Retrieves full details for a list of message IDs."""
        messages: List[EmailMessage] = []
        for mid in message_ids:
            msg = self.get_message(mid)
            if msg:
                messages.append(msg)
        return messages

    def trash_message(self, message_id: str) -> bool:
        """Safely moves a message to the Gmail Trash (retains for 30 days)."""
        try:
            self.service.users().messages().trash(userId="me", id=message_id).execute()
            return True
        except Exception:
            return False

    def untrash_message(self, message_id: str) -> bool:
        """Restores a message from Trash back to its original state."""
        try:
            self.service.users().messages().untrash(userId="me", id=message_id).execute()
            return True
        except Exception:
            return False

    def list_labels(self) -> List[Dict[str, str]]:
        """Lists available labels in the user's Gmail account."""
        try:
            res = self.service.users().labels().list(userId="me").execute()
            return res.get("labels", [])
        except Exception:
            return []

