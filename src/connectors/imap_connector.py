"""Gmail IMAP Connector for accounts using Google App Passwords.
Allows direct connection with zero Google Cloud Console setup or test user restrictions.
"""
from datetime import datetime, timezone
import email
from email.header import decode_header
import email.utils
import imaplib
import re
from typing import Any, Dict, List, Optional, Tuple

from src.connectors.gmail_connector import EmailMessage

class GmailImapConnector:
    """Connects to Gmail via IMAP over SSL using an App Password."""

    GMAIL_IMAP_HOST = "imap.gmail.com"
    GMAIL_IMAP_PORT = 993

    CATEGORY_MAP = {
        "primary": {"folder": "INBOX", "raw": "category:primary in:inbox"},
        "inbox": {"folder": "INBOX", "raw": "in:inbox"},
        "promotions": {"folder": "[Gmail]/All Mail", "raw": "category:promotions"},
        "updates": {"folder": "[Gmail]/All Mail", "raw": "category:updates"},
        "social": {"folder": "[Gmail]/All Mail", "raw": "category:social"},
        "forums": {"folder": "[Gmail]/All Mail", "raw": "category:forums"},
        "purchases": {"folder": "[Gmail]/All Mail", "raw": "category:purchases OR label:purchases OR purchases"},
        "spam": {"folder": "[Gmail]/Spam", "raw": "in:spam"},
        "trash": {"folder": "[Gmail]/Trash", "raw": "in:trash"},
        "important": {"folder": "[Gmail]/Important", "raw": "is:important"},
        "starred": {"folder": "[Gmail]/Starred", "raw": "is:starred"},
        "sent": {"folder": "[Gmail]/Sent Mail", "raw": "in:sent"},
        "draft": {"folder": "[Gmail]/Drafts", "raw": "in:draft"},
        "all mail": {"folder": "[Gmail]/All Mail", "raw": None},
        "all": {"folder": "[Gmail]/All Mail", "raw": None},
    }

    FOLDER_MAP = {
        "INBOX": "INBOX",
        "SPAM": "[Gmail]/Spam",
        "TRASH": "[Gmail]/Trash",
        "CATEGORY_PROMOTIONS": "[Gmail]/All Mail",
        "CATEGORY_UPDATES": "[Gmail]/All Mail",
    }

    def __init__(self, email_address: str, app_password: str):
        self.email_address = email_address.strip().lower()
        # Remove any spaces in app password (e.g. "abcd efgh ijkl mnop" -> "abcdefghijklmnop")
        self.app_password = re.sub(r"\s+", "", app_password)

    def _get_connection(self) -> imaplib.IMAP4_SSL:
        """Establishes an authenticated IMAP SSL connection."""
        mail = imaplib.IMAP4_SSL(self.GMAIL_IMAP_HOST, self.GMAIL_IMAP_PORT)
        mail.login(self.email_address, self.app_password)
        return mail

    def test_connection(self) -> Tuple[bool, str, int]:
        """Tests if credentials are valid and returns message count.
        
        Returns:
            (success, error_message, total_messages)
        """
        try:
            mail = self._get_connection()
            status, data = mail.select("INBOX", readonly=True)
            total = int(data[0].decode()) if status == "OK" else 0
            mail.logout()
            return True, "", total
        except Exception as e:
            return False, str(e), 0

    def _decode_str(self, header_value: Optional[str]) -> str:
        """Decodes RFC 2047 encoded email header strings."""
        if not header_value:
            return ""
        decoded_parts = []
        for part, encoding in decode_header(header_value):
            if isinstance(part, bytes):
                try:
                    decoded_parts.append(part.decode(encoding or "utf-8", errors="replace"))
                except Exception:
                    decoded_parts.append(part.decode("latin-1", errors="replace"))
            else:
                decoded_parts.append(str(part))
        return "".join(decoded_parts)

    def parse_sender(self, from_header: str) -> Tuple[str, str, str]:
        """Extracts (name, email_address, domain) from a From header."""
        name, address = email.utils.parseaddr(from_header)
        domain = address.split("@")[-1].lower() if "@" in address else ""
        return self._decode_str(name), address.lower(), domain

    def parse_date(self, date_header: str) -> Optional[datetime]:
        """Parses RFC 2822 date header into datetime object."""
        try:
            return email.utils.parsedate_to_datetime(date_header)
        except Exception:
            return None

    def _resolve_category_config(self, label: str) -> Dict[str, Any]:
        """Resolves any label name (with emojis, friendly text, or raw keys) to IMAP search config."""
        clean = re.sub(r"[^\w\s]", "", label).strip().lower()
        for key, cfg in self.CATEGORY_MAP.items():
            if key in clean:
                return cfg
        if label.upper() in self.FOLDER_MAP:
            return {"folder": self.FOLDER_MAP[label.upper()], "raw": None}
        return {"folder": "INBOX", "raw": None}

    def list_message_ids(
        self,
        query: Optional[str] = None,
        label_ids: Optional[List[str]] = None,
        max_results: int = 50,
    ) -> List[str]:
        """Retrieves a list of IMAP sequence IDs matching the folder or search criteria."""
        label_name = label_ids[0] if label_ids else "INBOX"
        cfg = self._resolve_category_config(label_name)
        target_folder = cfg["folder"]

        mail = self._get_connection()
        try:
            # Select target folder with safe fallback to INBOX
            try:
                status, _ = mail.select(f'"{target_folder}"', readonly=True)
            except Exception:
                status = "NO"
            if status != "OK":
                target_folder = "INBOX"
                mail.select(f'"{target_folder}"', readonly=True)

            raw_q = cfg.get("raw")
            if raw_q and query:
                full_raw = f"({raw_q}) {query}"
            elif raw_q:
                full_raw = raw_q
            elif query:
                full_raw = query
            else:
                full_raw = None

            search_success = False
            data = None
            if full_raw:
                try:
                    s_status, s_data = mail.search(None, "X-GM-RAW", f'"{full_raw}"')
                    if s_status == "OK" and s_data and s_data[0]:
                        data = s_data
                        search_success = True
                except Exception:
                    search_success = False

            if not search_success:
                search_criterion = "UNSEEN" if query and "unread" in query.lower() else "ALL"
                status, data = mail.search(None, search_criterion)

            if not data or not data[0]:
                return []

            # Get message IDs (newest first)
            id_list = data[0].split()
            id_list.reverse()
            # Store ID with folder context, e.g. "INBOX:123"
            return [f"{target_folder}:{mid.decode()}" for mid in id_list[:max_results]]
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    def get_message(self, message_id_with_folder: str) -> Optional[EmailMessage]:
        """Retrieves and parses a single email message via IMAP."""
        try:
            folder, mid = message_id_with_folder.split(":", 1)
        except ValueError:
            folder, mid = "INBOX", message_id_with_folder

        mail = self._get_connection()
        try:
            mail.select(f'"{folder}"', readonly=True)
            status, data = mail.fetch(mid, "(BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.400> FLAGS)")
            if status != "OK" or not data or not data[0]:
                return None

            raw_email = b""
            body_snippet = ""
            flags_str = ""

            for part in data:
                if isinstance(part, tuple):
                    if b"BODY[HEADER]" in part[0]:
                        raw_email = part[1]
                    elif b"BODY[TEXT]" in part[0]:
                        try:
                            body_snippet = part[1].decode("utf-8", errors="replace")[:250]
                        except Exception:
                            body_snippet = str(part[1])[:250]
                elif isinstance(part, bytes):
                    flags_str += part.decode("utf-8", errors="replace")

            msg = email.message_from_bytes(raw_email)

            from_raw = msg.get("From", "")
            name, email_addr, domain = self.parse_sender(from_raw)

            subject_raw = msg.get("Subject", "")
            subject = self._decode_str(subject_raw) or "(No Subject)"

            date_raw = msg.get("Date", "")
            date_obj = self.parse_date(date_raw)

            is_starred = "\\Flagged" in flags_str or "Flagged" in flags_str
            is_important = "Important" in flags_str

            auth_results = (msg.get("Authentication-Results", "") + " " + msg.get("Received-SPF", "")).strip()
            has_unsub = "List-Unsubscribe" in msg

            # Clean snippet from raw html/newlines
            clean_snippet = re.sub(r"<[^>]+>", " ", body_snippet)
            clean_snippet = re.sub(r"\s+", " ", clean_snippet).strip()

            labels = [folder]
            if folder == "[Gmail]/Spam":
                labels.append("SPAM")

            return EmailMessage(
                id=message_id_with_folder,
                thread_id=message_id_with_folder,
                sender=name or email_addr,
                sender_email=email_addr,
                sender_domain=domain,
                recipient=msg.get("To", ""),
                subject=subject,
                date_str=date_raw,
                date=date_obj,
                snippet=clean_snippet[:150],
                labels=labels,
                headers=dict(msg.items()),
                has_list_unsubscribe=has_unsub,
                auth_results=auth_results,
                is_starred=is_starred,
                is_important=is_important,
            )
        except Exception:
            return None
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    def get_messages_batch(self, message_ids: List[str]) -> List[EmailMessage]:
        """Retrieves a batch of messages."""
        results: List[EmailMessage] = []
        for mid in message_ids:
            msg = self.get_message(mid)
            if msg:
                results.append(msg)
        return results

    def trash_message(self, message_id_with_folder: str) -> bool:
        """Moves a message to [Gmail]/Trash via IMAP."""
        try:
            folder, mid = message_id_with_folder.split(":", 1)
        except ValueError:
            folder, mid = "INBOX", message_id_with_folder

        mail = self._get_connection()
        try:
            try:
                mail.select(f'"{folder}"')
            except Exception:
                mail.select('"INBOX"')

            # Try standard trash folder names
            trash_folders = ["[Gmail]/Trash", "[Google Mail]/Trash", "[Gmail]/Bin", "Trash", "Bin"]
            copy_ok = False
            for tf in trash_folders:
                try:
                    copy_status, _ = mail.copy(mid, f'"{tf}"')
                    if copy_status == "OK":
                        copy_ok = True
                        break
                except Exception:
                    continue

            if copy_ok:
                # Mark original as deleted and expunge
                mail.store(mid, "+FLAGS", "\\Deleted")
                mail.expunge()
                return True
            return False
        except Exception:
            return False
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    def untrash_message(self, message_id_with_folder: str) -> bool:
        """Restores a message from [Gmail]/Trash back to INBOX."""
        try:
            _, mid = message_id_with_folder.split(":", 1)
        except ValueError:
            mid = message_id_with_folder

        mail = self._get_connection()
        try:
            mail.select('"[Gmail]/Trash"')
            copy_status, _ = mail.copy(mid, '"INBOX"')
            if copy_status == "OK":
                mail.store(mid, "+FLAGS", "\\Deleted")
                mail.expunge()
                return True
            return False
        except Exception:
            return False
        finally:
            try:
                mail.logout()
            except Exception:
                pass

