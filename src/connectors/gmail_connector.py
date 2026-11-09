"""Gmail Connector for retrieving, inspecting, trashing, and restoring messages.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any, Callable, Dict, List, Optional
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

    API_CATEGORY_MAP = {
        "primary": {"label": "INBOX", "q": "category:primary in:inbox"},
        "inbox": {"label": "INBOX", "q": None},
        "promotions": {"label": "CATEGORY_PROMOTIONS", "q": None},
        "updates": {"label": "CATEGORY_UPDATES", "q": None},
        "social": {"label": "CATEGORY_SOCIAL", "q": None},
        "forums": {"label": "CATEGORY_FORUMS", "q": None},
        "purchases": {"label": None, "q": "category:purchases OR label:purchases"},
        "spam": {"label": "SPAM", "q": None},
        "trash": {"label": "TRASH", "q": None},
        "important": {"label": "IMPORTANT", "q": None},
        "starred": {"label": "STARRED", "q": None},
        "sent": {"label": "SENT", "q": None},
        "draft": {"label": "DRAFT", "q": None},
        "all mail": {"label": None, "q": None},
        "all": {"label": None, "q": None},
    }

    def list_message_ids(
        self,
        query: Optional[str] = None,
        label_ids: Optional[List[str]] = None,
        max_results: int = 50,
    ) -> List[str]:
        """Retrieves a list of message IDs matching the label or search query,
        paginating through Gmail API pages until max_results is satisfied.
        """
        params: Dict[str, Any] = {
            "userId": "me",
        }
        
        q_parts = []
        if query:
            q_parts.append(f"({query})")

        if label_ids:
            resolved_labels = []
            for lbl in label_ids:
                clean = re.sub(r"[^\w\s]", "", lbl).strip().lower()
                matched = False
                for k, v in self.API_CATEGORY_MAP.items():
                    if k in clean:
                        if v["label"]:
                            resolved_labels.append(v["label"])
                        if v["q"]:
                            q_parts.append(f"({v['q']})")
                        matched = True
                        break
                if not matched and lbl:
                    resolved_labels.append(lbl)
            if resolved_labels:
                params["labelIds"] = resolved_labels

        if q_parts:
            params["q"] = " ".join(q_parts)

        messages = []
        page_token = None
        while len(messages) < max_results:
            page_size = min(max_results - len(messages), 500)
            params["maxResults"] = page_size
            if page_token:
                params["pageToken"] = page_token
            elif "pageToken" in params:
                del params["pageToken"]

            try:
                result = self.service.users().messages().list(**params).execute()
            except Exception:
                break

            batch = result.get("messages", [])
            if not batch:
                break
            messages.extend(batch)

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        return [m["id"] for m in messages[:max_results]]

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

    def get_messages_batch(
        self,
        message_ids: List[str],
        max_workers: int = 10,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[EmailMessage]:
        """Retrieves full details for a list of message IDs in parallel."""
        if not message_ids:
            return []

        results_dict: Dict[str, EmailMessage] = {}
        total = len(message_ids)
        completed = 0

        # For smaller batches, run sequentially to avoid thread overhead
        if total <= 5:
            for mid in message_ids:
                msg = self.get_message(mid)
                if msg:
                    results_dict[mid] = msg
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_id = {executor.submit(self.get_message, mid): mid for mid in message_ids}
                for future in as_completed(future_to_id):
                    mid = future_to_id[future]
                    completed += 1
                    try:
                        msg = future.result()
                        if msg:
                            results_dict[mid] = msg
                    except Exception:
                        pass
                    if progress_callback:
                        progress_callback(completed, total)

        return [results_dict[mid] for mid in message_ids if mid in results_dict]

    def trash_messages_batch(
        self,
        message_ids: List[str],
        max_workers: int = 10,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[str]:
        """Safely moves a batch of messages to the Gmail Trash in parallel."""
        if not message_ids:
            return []

        trashed = []
        total = len(message_ids)
        completed = 0

        if total <= 5:
            for mid in message_ids:
                if self.trash_message(mid):
                    trashed.append(mid)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_id = {executor.submit(self.trash_message, mid): mid for mid in message_ids}
                for future in as_completed(future_to_id):
                    mid = future_to_id[future]
                    completed += 1
                    try:
                        ok = future.result()
                        if ok:
                            trashed.append(mid)
                    except Exception:
                        pass
                    if progress_callback:
                        progress_callback(completed, total)

        return trashed

    def trash_message(self, message_id: str) -> bool:
        """Safely moves a message to the Gmail Trash (retains for 30 days)."""
        try:
            self.service.users().messages().trash(userId="me", id=message_id).execute()
            return True
        except Exception:
            return False

    def untrash_messages_batch(
        self,
        message_ids: List[str],
        max_workers: int = 10,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[str]:
        """Restores a batch of messages from Trash back in parallel."""
        if not message_ids:
            return []

        restored = []
        total = len(message_ids)
        completed = 0

        if total <= 5:
            for mid in message_ids:
                if self.untrash_message(mid):
                    restored.append(mid)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_id = {executor.submit(self.untrash_message, mid): mid for mid in message_ids}
                for future in as_completed(future_to_id):
                    mid = future_to_id[future]
                    completed += 1
                    try:
                        ok = future.result()
                        if ok:
                            restored.append(mid)
                    except Exception:
                        pass
                    if progress_callback:
                        progress_callback(completed, total)

        return restored

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

