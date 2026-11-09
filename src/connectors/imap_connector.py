"""Gmail IMAP Connector for accounts using Google App Passwords.
Allows direct connection with zero Google Cloud Console setup or test user restrictions.
"""
from datetime import datetime, timezone
import email
from email.header import decode_header
import email.utils
import imaplib
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

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

    def get_total_messages(self, folder: str = "INBOX") -> int:
        """Fetches the live message count for the mailbox folder."""
        try:
            mail = self._get_connection()
            status, data = mail.select(folder, readonly=True)
            total = int(data[0].decode()) if status == "OK" else 0
            mail.logout()
            return total
        except Exception:
            return 0

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

    def _build_email_message(
        self,
        mid_with_folder: str,
        folder: str,
        raw_email: bytes,
        body_snippet: str,
        flags_str: str,
    ) -> Optional[EmailMessage]:
        """Builds an EmailMessage instance from raw IMAP email data."""
        try:
            if not raw_email:
                return None
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

            clean_snippet = re.sub(r"<[^>]+>", " ", body_snippet)
            clean_snippet = re.sub(r"\s+", " ", clean_snippet).strip()

            labels = [folder]
            if folder == "[Gmail]/Spam":
                labels.append("SPAM")

            return EmailMessage(
                id=mid_with_folder,
                thread_id=mid_with_folder,
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

    def _parse_multi_fetch_response(self, folder: str, fetch_data: list) -> Dict[str, EmailMessage]:
        """Parses multi-message FETCH response data grouped by message sequence number."""
        messages_raw: Dict[str, Dict[str, Any]] = {}
        curr_seq: Optional[str] = None

        for part in fetch_data:
            if isinstance(part, tuple):
                header_line = part[0]
                content = part[1]
                m = re.match(rb"^(\d+)\s+", header_line)
                if m:
                    curr_seq = m.group(1).decode()
                    if curr_seq not in messages_raw:
                        messages_raw[curr_seq] = {"header": b"", "text": "", "flags": ""}

                if curr_seq:
                    if b"BODY[HEADER]" in header_line:
                        messages_raw[curr_seq]["header"] = content
                    elif b"BODY[TEXT]" in header_line:
                        try:
                            messages_raw[curr_seq]["text"] = content.decode("utf-8", errors="replace")[:250]
                        except Exception:
                            messages_raw[curr_seq]["text"] = str(content)[:250]
            elif isinstance(part, bytes):
                if curr_seq:
                    messages_raw[curr_seq]["flags"] += part.decode("utf-8", errors="replace")

        result = {}
        for seq, item in messages_raw.items():
            mid_full = f"{folder}:{seq}"
            msg_obj = self._build_email_message(
                mid_with_folder=mid_full,
                folder=folder,
                raw_email=item["header"],
                body_snippet=item["text"],
                flags_str=item["flags"],
            )
            if msg_obj:
                result[mid_full] = msg_obj
        return result

    def _parse_single_fetch_response(
        self, folder: str, seq: str, mid_with_folder: str, fetch_data: list
    ) -> Optional[EmailMessage]:
        """Parses FETCH response data for a single message."""
        raw_email = b""
        body_snippet = ""
        flags_str = ""

        for part in fetch_data:
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

        return self._build_email_message(mid_with_folder, folder, raw_email, body_snippet, flags_str)

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
            return self._parse_single_fetch_response(folder, mid, message_id_with_folder, data)
        except Exception:
            return None
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    def get_messages_batch(
        self,
        message_ids: List[str],
        chunk_size: int = 50,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[EmailMessage]:
        """High-performance batch retrieval of messages using a single persistent connection
        and chunked multi-message FETCH commands. Supports scanning 10,000+ emails smoothly.
        """
        if not message_ids:
            return []

        # Group by folder, preserving original message_id order
        folder_groups: Dict[str, List[Tuple[str, str]]] = {}
        for mid_with_folder in message_ids:
            try:
                folder, seq = mid_with_folder.split(":", 1)
            except ValueError:
                folder, seq = "INBOX", mid_with_folder
            folder_groups.setdefault(folder, []).append((mid_with_folder, seq))

        results_map: Dict[str, EmailMessage] = {}
        total = len(message_ids)
        processed_count = 0

        mail = self._get_connection()
        try:
            for folder, id_pairs in folder_groups.items():
                try:
                    status, _ = mail.select(f'"{folder}"', readonly=True)
                except Exception:
                    status = "NO"
                if status != "OK":
                    continue

                for i in range(0, len(id_pairs), chunk_size):
                    chunk = id_pairs[i : i + chunk_size]
                    seq_list = [p[1] for p in chunk]
                    seq_set_str = ",".join(seq_list)

                    try:
                        f_status, data = mail.fetch(
                            seq_set_str,
                            "(BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.400> FLAGS)"
                        )
                        if f_status == "OK" and data:
                            chunk_parsed = self._parse_multi_fetch_response(folder, data)
                            results_map.update(chunk_parsed)
                    except Exception:
                        # Fallback for this chunk: fetch individually on the same open connection
                        for mid_full, seq in chunk:
                            try:
                                s_status, s_data = mail.fetch(seq, "(BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.400> FLAGS)")
                                if s_status == "OK" and s_data:
                                    parsed = self._parse_single_fetch_response(folder, seq, mid_full, s_data)
                                    if parsed:
                                        results_map[mid_full] = parsed
                            except Exception:
                                pass

                    processed_count += len(chunk)
                    if progress_callback:
                        progress_callback(min(processed_count, total), total)
        finally:
            try:
                mail.logout()
            except Exception:
                pass

        return [results_map[mid] for mid in message_ids if mid in results_map]

    def trash_messages_batch(
        self,
        message_ids: List[str],
        chunk_size: int = 100,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[str]:
        """Moves a batch of messages to [Gmail]/Trash via a single connection."""
        if not message_ids:
            return []

        folder_groups: Dict[str, List[Tuple[str, str]]] = {}
        for mid_with_folder in message_ids:
            try:
                folder, seq = mid_with_folder.split(":", 1)
            except ValueError:
                folder, seq = "INBOX", mid_with_folder
            folder_groups.setdefault(folder, []).append((mid_with_folder, seq))

        trashed_mids: List[str] = []
        total = len(message_ids)
        processed = 0

        mail = self._get_connection()
        try:
            trash_folders = ["[Gmail]/Trash", "[Google Mail]/Trash", "[Gmail]/Bin", "Trash", "Bin"]
            for folder, id_pairs in folder_groups.items():
                try:
                    mail.select(f'"{folder}"')
                except Exception:
                    mail.select('"INBOX"')

                for i in range(0, len(id_pairs), chunk_size):
                    chunk = id_pairs[i : i + chunk_size]
                    seq_list = [p[1] for p in chunk]
                    seq_set_str = ",".join(seq_list)

                    copied = False
                    for tf in trash_folders:
                        try:
                            copy_status, _ = mail.copy(seq_set_str, f'"{tf}"')
                            if copy_status == "OK":
                                copied = True
                                break
                        except Exception:
                            continue

                    if copied:
                        mail.store(seq_set_str, "+FLAGS", "\\Deleted")
                        trashed_mids.extend([p[0] for p in chunk])
                    else:
                        # Fallback: try individual messages
                        for mid_full, seq in chunk:
                            for tf in trash_folders:
                                try:
                                    copy_status, _ = mail.copy(seq, f'"{tf}"')
                                    if copy_status == "OK":
                                        mail.store(seq, "+FLAGS", "\\Deleted")
                                        trashed_mids.append(mid_full)
                                        break
                                except Exception:
                                    continue

                    processed += len(chunk)
                    if progress_callback:
                        progress_callback(min(processed, total), total)

                try:
                    mail.expunge()
                except Exception:
                    pass
        finally:
            try:
                mail.logout()
            except Exception:
                pass

        return trashed_mids

    def trash_message(self, message_id_with_folder: str) -> bool:
        """Moves a message to [Gmail]/Trash via IMAP."""
        res = self.trash_messages_batch([message_id_with_folder])
        return len(res) > 0

    def untrash_messages_batch(
        self,
        message_ids: List[str],
        chunk_size: int = 100,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[str]:
        """Restores a batch of messages from [Gmail]/Trash back to INBOX via a single connection."""
        if not message_ids:
            return []

        seq_list = []
        for mid_with_folder in message_ids:
            try:
                _, seq = mid_with_folder.split(":", 1)
            except ValueError:
                seq = mid_with_folder
            seq_list.append((mid_with_folder, seq))

        restored_mids: List[str] = []
        total = len(message_ids)
        processed = 0

        mail = self._get_connection()
        try:
            trash_folders = ["[Gmail]/Trash", "[Google Mail]/Trash", "[Gmail]/Bin", "Trash", "Bin"]
            trash_selected = False
            for tf in trash_folders:
                try:
                    status, _ = mail.select(f'"{tf}"')
                    if status == "OK":
                        trash_selected = True
                        break
                except Exception:
                    continue

            if not trash_selected:
                return []

            for i in range(0, len(seq_list), chunk_size):
                chunk = seq_list[i : i + chunk_size]
                chunk_seqs = [p[1] for p in chunk]
                seq_set_str = ",".join(chunk_seqs)

                try:
                    copy_status, _ = mail.copy(seq_set_str, '"INBOX"')
                    if copy_status == "OK":
                        mail.store(seq_set_str, "+FLAGS", "\\Deleted")
                        restored_mids.extend([p[0] for p in chunk])
                    else:
                        for mid_full, seq in chunk:
                            try:
                                c_status, _ = mail.copy(seq, '"INBOX"')
                                if c_status == "OK":
                                    mail.store(seq, "+FLAGS", "\\Deleted")
                                    restored_mids.append(mid_full)
                            except Exception:
                                pass
                except Exception:
                    for mid_full, seq in chunk:
                        try:
                            c_status, _ = mail.copy(seq, '"INBOX"')
                            if c_status == "OK":
                                mail.store(seq, "+FLAGS", "\\Deleted")
                                restored_mids.append(mid_full)
                        except Exception:
                            pass

                processed += len(chunk)
                if progress_callback:
                    progress_callback(min(processed, total), total)

            try:
                mail.expunge()
            except Exception:
                pass
        finally:
            try:
                mail.logout()
            except Exception:
                pass

        return restored_mids

    def untrash_message(self, message_id_with_folder: str) -> bool:
        """Restores a message from [Gmail]/Trash back to INBOX."""
        res = self.untrash_messages_batch([message_id_with_folder])
        return len(res) > 0

