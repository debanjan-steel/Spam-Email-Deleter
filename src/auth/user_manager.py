"""User Management and Authentication System for Multi-Tenant Gmail Spam Deleter.
Handles secure account creation, password hashing with PBKDF2-HMAC-SHA256,
and complete per-user filesystem isolation.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
from typing import Any, Dict, Generator, Optional, Tuple
import uuid

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = WORKSPACE_ROOT / "data"
USERS_DB_PATH = DATA_DIR / "users.db"
GLOBAL_CONFIG_DIR = WORKSPACE_ROOT / "config"

class UserManager:
    """Manages application users, password hashing, and user-isolated workspaces."""

    def __init__(
        self,
        db_path: Path = USERS_DB_PATH,
        data_dir: Path = DATA_DIR,
        template_config_dir: Path = GLOBAL_CONFIG_DIR,
    ):
        self.db_path = db_path
        self.data_dir = data_dir
        self.users_dir = self.data_dir / "users"
        self.template_config_dir = template_config_dir

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.users_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes the users table if it does not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def _hash_password(self, password: str, salt: str) -> str:
        """Derives a secure 256-bit PBKDF2-HMAC key from password and salt."""
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100_000,
        )
        return dk.hex()

    def create_user(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Registers a new user and sets up their isolated data directories.
        
        Returns:
            (success, message, user_dict)
        """
        clean_username = username.strip().lower()
        if len(clean_username) < 3:
            return False, "Username must be at least 3 characters long.", None
        if not re.match(r"^[a-zA-Z0-9_\-\.@]+$", clean_username):
            return False, "Username can only contain letters, numbers, dots, hyphens, and underscores.", None
        if len(password) < 6:
            return False, "Password must be at least 6 characters long.", None

        user_id = uuid.uuid4().hex
        salt = secrets.token_hex(16)
        pwd_hash = self._hash_password(password, salt)
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO app_users (id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, clean_username, pwd_hash, salt, created_at),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            return False, f"Username '{clean_username}' already exists. Please sign in instead.", None
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
            "username": clean_username,
            "created_at": created_at,
        }
        return True, f"Account '{clean_username}' created successfully!", user_info

    def authenticate(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Authenticates user credentials.
        
        Returns:
            (success, message, user_dict)
        """
        clean_username = username.strip().lower()
        if not clean_username or not password:
            return False, "Please enter both username and password.", None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password_hash, salt, created_at FROM app_users WHERE username = ?",
                (clean_username,),
            )
            row = cursor.fetchone()

        if not row:
            return False, "Invalid username or password.", None

        expected_hash = row["password_hash"]
        computed_hash = self._hash_password(password, row["salt"])

        if not hmac.compare_digest(expected_hash, computed_hash):
            return False, "Invalid username or password.", None

        user_info = {
            "id": row["id"],
            "username": row["username"],
            "created_at": row["created_at"],
        }
        return True, f"Welcome back, {row['username']}!", user_info

    def get_user_paths(self, user_id: str) -> Dict[str, Path]:
        """Returns the isolated directory and file paths for a specific user."""
        user_root = self.users_dir / user_id
        return {
            "user_dir": user_root,
            "tokens_dir": user_root / "tokens",
            "config_dir": user_root / "config",
            "audit_db": user_root / "audit_log.db",
        }
