"""User Management and Authentication System for Multi-Tenant Gmail Spam Deleter.
Handles secure Gmail-based registration, password encryption with Fernet for exact retrieval,
outbound email password recovery, password updating, account deletion,
and complete per-user sandbox isolation.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from pathlib import Path
import re
import secrets
import shutil
import smtplib
import sqlite3
from typing import Any, Dict, Generator, Optional, Tuple
import uuid

from cryptography.fernet import Fernet

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = WORKSPACE_ROOT / "data"
USERS_DB_PATH = DATA_DIR / "users.db"
SECRET_KEY_PATH = DATA_DIR / "secret.key"
GLOBAL_CONFIG_DIR = WORKSPACE_ROOT / "config"

class UserManager:
    """Manages application users, password encryption/recovery, and user-isolated workspaces."""

    def __init__(
        self,
        db_path: Path = USERS_DB_PATH,
        data_dir: Path = DATA_DIR,
        secret_key_path: Path = SECRET_KEY_PATH,
        template_config_dir: Path = GLOBAL_CONFIG_DIR,
    ):
        self.db_path = db_path
        self.data_dir = data_dir
        self.users_dir = self.data_dir / "users"
        self.secret_key_path = secret_key_path
        self.template_config_dir = template_config_dir

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.users_dir.mkdir(parents=True, exist_ok=True)
        self.fernet = self._init_fernet()
        self._init_db()

    def _init_fernet(self) -> Fernet:
        """Initializes or loads persistent Fernet encryption key."""
        if not self.secret_key_path.exists():
            key = Fernet.generate_key()
            with open(self.secret_key_path, "wb") as f:
                f.write(key)
        else:
            with open(self.secret_key_path, "rb") as f:
                key = f.read().strip()
        return Fernet(key)

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes the users table and safely migrates columns if upgrading from earlier version."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_users (
                    id TEXT PRIMARY KEY,
                    gmail TEXT UNIQUE NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES app_users(id)
                )
            """)
            conn.commit()

            # Inspect columns to ensure seamless schema migration
            cursor.execute("PRAGMA table_info(app_users)")
            existing_cols = {row["name"] for row in cursor.fetchall()}

            # If upgrading from legacy schema missing 'gmail' or 'password_encrypted'
            if "gmail" not in existing_cols or "password_encrypted" not in existing_cols:
                cursor.execute("DROP TABLE app_users")
                cursor.execute("""
                    CREATE TABLE app_users (
                        id TEXT PRIMARY KEY,
                        gmail TEXT UNIQUE NOT NULL,
                        password_encrypted TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()

    def _encrypt_password(self, password: str) -> str:
        """Encrypts password reversibly using Fernet."""
        return self.fernet.encrypt(password.encode("utf-8")).decode("utf-8")

    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypts password back to exact plaintext using Fernet."""
        return self.fernet.decrypt(encrypted_password.encode("utf-8")).decode("utf-8")

    def _validate_gmail(self, gmail: str) -> bool:
        """Checks if input is a plausible Gmail address."""
        clean = gmail.strip().lower()
        return "@" in clean and "." in clean and len(clean) >= 5

    def create_user(self, gmail: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Registers a new user with their Gmail and password.
        
        Returns:
            (success, message, user_dict)
        """
        clean_gmail = gmail.strip().lower()
        if not self._validate_gmail(clean_gmail):
            return False, "Please enter a valid Gmail address (e.g. yourname@gmail.com).", None
        if len(password) < 6:
            return False, "Password must be at least 6 characters long.", None

        user_id = uuid.uuid4().hex
        pwd_encrypted = self._encrypt_password(password)
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO app_users (id, gmail, password_encrypted, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, clean_gmail, pwd_encrypted, created_at),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            return False, f"An account with '{clean_gmail}' already exists. Please sign in instead.", None
        except Exception as e:
            return False, f"Failed to create account: {e}", None

        # Setup user-isolated workspace directories
        user_paths = self.get_user_paths(user_id)
        user_paths["tokens_dir"].mkdir(parents=True, exist_ok=True)
        user_paths["config_dir"].mkdir(parents=True, exist_ok=True)

        # Seed initial config files from template if available
        for cfg_file in ["config.yaml", "whitelist.yaml", "custom_rules.yaml"]:
            src = self.template_config_dir / cfg_file
            dst = user_paths["config_dir"] / cfg_file
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)

        user_info = {
            "id": user_id,
            "gmail": clean_gmail,
            "created_at": created_at,
        }
        return True, f"Account '{clean_gmail}' created successfully!", user_info

    def authenticate(self, gmail: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Authenticates user credentials.
        
        Returns:
            (success, message, user_dict)
        """
        clean_gmail = gmail.strip().lower()
        if not clean_gmail or not password:
            return False, "Please enter both Gmail address and password.", None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, gmail, password_encrypted, created_at FROM app_users WHERE gmail = ?",
                (clean_gmail,),
            )
            row = cursor.fetchone()

        if not row:
            return False, "Invalid Gmail address or password.", None

        try:
            stored_password = self._decrypt_password(row["password_encrypted"])
        except Exception:
            return False, "Could not decrypt account password. Please contact support.", None

        if stored_password != password:
            return False, "Invalid Gmail address or password.", None

        user_info = {
            "id": row["id"],
            "gmail": row["gmail"],
            "created_at": row["created_at"],
        }
        return True, f"Welcome back, {row['gmail']}!", user_info

    def create_session(self, user_id: str) -> str:
        """Creates and stores a persistent device session token for a user.
        
        Returns:
            device_session_token (str)
        """
        token = secrets.token_urlsafe(32)
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO user_sessions (token, user_id, created_at, last_active)
                VALUES (?, ?, ?, ?)
                """,
                (token, user_id, now_str, now_str),
            )
            conn.commit()
        return token

    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validates a persistent session token. Updates last_active and returns user info if valid."""
        if not token or not isinstance(token, str):
            return None

        clean_token = token.strip()
        now_str = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.gmail, u.created_at, s.last_active
                FROM user_sessions s
                JOIN app_users u ON s.user_id = u.id
                WHERE s.token = ?
                """,
                (clean_token,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            # Update last_active timestamp
            cursor.execute(
                "UPDATE user_sessions SET last_active = ? WHERE token = ?",
                (now_str, clean_token),
            )
            conn.commit()

        return {
            "id": row["id"],
            "gmail": row["gmail"],
            "created_at": row["created_at"],
        }

    def revoke_session(self, token: str) -> bool:
        """Revokes / destroys a single device session token upon logout."""
        if not token:
            return False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token.strip(),))
            conn.commit()
        return True

    def revoke_all_sessions(self, user_id: str) -> bool:
        """Revokes all active sessions for a user (e.g. on password change or account deletion)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        return True

    def recover_password(self, gmail: str) -> Tuple[bool, str, Optional[str]]:
        """Retrieves user's exact password and sends an email to their Gmail address.
        
        Returns:
            (success, message, exact_password)
        """
        clean_gmail = gmail.strip().lower()
        if not self._validate_gmail(clean_gmail):
            return False, "Please enter a valid Gmail address.", None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, gmail, password_encrypted FROM app_users WHERE gmail = ?",
                (clean_gmail,),
            )
            row = cursor.fetchone()

        if not row:
            return False, f"No account found with Gmail address '{clean_gmail}'.", None

        try:
            exact_password = self._decrypt_password(row["password_encrypted"])
        except Exception as e:
            return False, f"Error decrypting account password: {e}", None

        # Dispatch email
        email_sent, email_msg = self.send_recovery_email(clean_gmail, exact_password)
        return True, email_msg, exact_password

    def send_recovery_email(self, recipient_email: str, retrieved_password: str) -> Tuple[bool, str]:
        """Sends an email with the user's exact password using SMTP or provides safe fallback."""
        smtp_sender = None
        smtp_pass = None
        smtp_host = "smtp.gmail.com"
        smtp_port = 465

        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                smtp_sender = st.secrets.get("smtp_email") or st.secrets.get("SMTP_EMAIL")
                smtp_pass = st.secrets.get("smtp_password") or st.secrets.get("SMTP_PASSWORD")
                smtp_host = st.secrets.get("smtp_host", smtp_host)
                smtp_port = int(st.secrets.get("smtp_port", smtp_port))
        except Exception:
            pass

        if not smtp_sender or not smtp_pass:
            smtp_sender = os.environ.get("SMTP_EMAIL")
            smtp_pass = os.environ.get("SMTP_PASSWORD")

        if smtp_sender and smtp_pass:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = "Your Spam Email Deleter Account Password"
                msg["From"] = f"Spam Deleter Guard <{smtp_sender}>"
                msg["To"] = recipient_email

                body_text = f"""Hello,

You requested password recovery for your Spam Email Deleter account ({recipient_email}).

Here is your exact account password:
======================================
{retrieved_password}
======================================

You can now sign in at: https://spam-email-deleter.streamlit.app

Best regards,
Spam Email Deleter Guard Team
"""
                msg.attach(MIMEText(body_text, "plain"))
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                    server.login(smtp_sender, smtp_pass)
                    server.sendmail(smtp_sender, [recipient_email], msg.as_string())
                return True, f"We have sent an email with your exact password to {recipient_email}!"
            except Exception as e:
                return True, f"Your exact password is: **{retrieved_password}** (SMTP error: {e})"

        # Fallback if system SMTP is not configured in secrets
        return True, f"Your exact account password is: **{retrieved_password}**"

    def change_password(self, user_id: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Changes user password after verifying old password.
        
        Returns:
            (success, message)
        """
        if len(new_password) < 6:
            return False, "New password must be at least 6 characters long."

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_encrypted FROM app_users WHERE id = ?",
                (user_id,),
            )
            row = cursor.fetchone()

        if not row:
            return False, "User account not found."

        try:
            current_password = self._decrypt_password(row["password_encrypted"])
        except Exception:
            return False, "Failed to decrypt current password."

        if current_password != old_password:
            return False, "Incorrect old password. Please re-enter your current password."

        new_encrypted = self._encrypt_password(new_password)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE app_users SET password_encrypted = ? WHERE id = ?",
                (new_encrypted, user_id),
            )
            conn.commit()

        # Invalidate existing device sessions on password change
        self.revoke_all_sessions(user_id)

        return True, "Password updated successfully!"

    def delete_user(self, user_id: str) -> Tuple[bool, str]:
        """Permanently deletes the user account and purges their data directory.
        
        Returns:
            (success, message)
        """
        # Revoke all active sessions
        self.revoke_all_sessions(user_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM app_users WHERE id = ?", (user_id,))
            conn.commit()

        # Purge user directory
        user_paths = self.get_user_paths(user_id)
        if user_paths["user_dir"].exists():
            try:
                shutil.rmtree(user_paths["user_dir"], ignore_errors=True)
            except Exception:
                pass

        return True, "Your account and all associated data have been permanently deleted."

    def get_user_paths(self, user_id: str) -> Dict[str, Path]:
        """Returns the isolated directory and file paths for a specific user."""
        user_root = self.users_dir / user_id
        return {
            "user_dir": user_root,
            "tokens_dir": user_root / "tokens",
            "config_dir": user_root / "config",
            "audit_db": user_root / "audit_log.db",
        }
