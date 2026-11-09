"""Unit tests for multi-tenant UserManager with Gmail auth, password recovery, change, and deletion.
"""
import sys
from pathlib import Path
import tempfile

# Ensure workspace root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.auth.user_manager import UserManager

def test_user_manager_full_lifecycle():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        db_path = temp_path / "test_users.db"
        data_dir = temp_path / "data"
        key_path = temp_path / "secret.key"

        user_mgr = UserManager(
            db_path=db_path,
            data_dir=data_dir,
            secret_key_path=key_path,
        )

        # 1. Invalid Gmail format
        ok, msg, _ = user_mgr.create_user("notanemail", "mypassword123")
        assert not ok
        assert "valid Gmail address" in msg

        # 2. Short password
        ok, msg, _ = user_mgr.create_user("user1@gmail.com", "123")
        assert not ok
        assert "at least 6 characters" in msg

        # 3. Successful user creation
        ok, msg, user1 = user_mgr.create_user("User1@Gmail.Com", "MySecretPass_99")
        assert ok
        assert user1["gmail"] == "user1@gmail.com"
        assert "id" in user1

        # 4. Duplicate registration fails
        ok, msg, _ = user_mgr.create_user("user1@gmail.com", "anotherpass")
        assert not ok
        assert "already exists" in msg

        # 5. Successful authentication
        ok, msg, auth_u = user_mgr.authenticate("user1@gmail.com", "MySecretPass_99")
        assert ok
        assert auth_u["id"] == user1["id"]

        # 6. Wrong password fails
        ok, msg, _ = user_mgr.authenticate("user1@gmail.com", "wrongpass")
        assert not ok
        assert "Invalid Gmail address or password" in msg

        # 7. Exact Password Recovery
        ok, msg, retrieved_pass = user_mgr.recover_password("user1@gmail.com")
        assert ok
        assert retrieved_pass == "MySecretPass_99"

        # 8. Password Change
        # 8a. Wrong old password
        ok, msg = user_mgr.change_password(user1["id"], "wrongold", "NewSecretPass_100")
        assert not ok
        assert "Incorrect old password" in msg

        # 8b. Valid password change
        ok, msg = user_mgr.change_password(user1["id"], "MySecretPass_99", "NewSecretPass_100")
        assert ok
        assert "Password updated successfully" in msg

        # 8c. Verify new password works and old fails
        assert not user_mgr.authenticate("user1@gmail.com", "MySecretPass_99")[0]
        assert user_mgr.authenticate("user1@gmail.com", "NewSecretPass_100")[0]

        # 9. Verify isolated user directory
        paths1 = user_mgr.get_user_paths(user1["id"])
        assert paths1["tokens_dir"].exists()

        # 10. Account Deletion
        ok, msg = user_mgr.delete_user(user1["id"])
        assert ok
        # User no longer exists in DB
        assert not user_mgr.authenticate("user1@gmail.com", "NewSecretPass_100")[0]
        # User directory was purged
        assert not paths1["user_dir"].exists()

    print("UserManager full lifecycle tests passed successfully!")

def test_legacy_schema_migration():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        db_path = temp_path / "legacy_users.db"
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE app_users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        user_mgr = UserManager(
            db_path=db_path,
            data_dir=temp_path / "data",
            secret_key_path=temp_path / "secret.key",
        )

        ok, msg, u = user_mgr.create_user("migrated@gmail.com", "valid_pass_123")
        assert ok, f"Migration failed: {msg}"
        assert u["gmail"] == "migrated@gmail.com"

    print("Legacy schema auto-migration test passed successfully!")

def test_device_sessions_lifecycle():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        db_path = temp_path / "session_users.db"
        user_mgr = UserManager(
            db_path=db_path,
            data_dir=temp_path / "data",
            secret_key_path=temp_path / "secret.key",
        )

        ok, msg, user = user_mgr.create_user("sessiontest@gmail.com", "testpass123")
        assert ok

        # 1. Create device session
        token = user_mgr.create_session(user["id"])
        assert token and len(token) > 20

        # 2. Validate session
        valid_user = user_mgr.validate_session(token)
        assert valid_user is not None
        assert valid_user["id"] == user["id"]
        assert valid_user["gmail"] == "sessiontest@gmail.com"

        # 3. Invalid token returns None
        assert user_mgr.validate_session("fake_token_12345") is None

        # 4. Revoke session upon logout
        assert user_mgr.revoke_session(token)
        # Now validation fails
        assert user_mgr.validate_session(token) is None

        # 5. Multiple sessions & revoke_all
        t1 = user_mgr.create_session(user["id"])
        t2 = user_mgr.create_session(user["id"])
        assert user_mgr.validate_session(t1) is not None
        assert user_mgr.validate_session(t2) is not None

        # 6. Container restart simulation (user_sessions wiped, but user exists in app_users)
        t_restart = user_mgr.create_session(user["id"])
        with user_mgr._get_connection() as conn:
            conn.execute("DELETE FROM user_sessions")
            conn.commit()
        # Even with empty user_sessions table, validate_session decrypts and restores!
        restored_user = user_mgr.validate_session(t_restart)
        assert restored_user is not None
        assert restored_user["id"] == user["id"]
        assert restored_user["gmail"] == "sessiontest@gmail.com"

    print("Device session lifecycle tests passed successfully!")

if __name__ == "__main__":
    test_user_manager_full_lifecycle()
    test_legacy_schema_migration()
    test_device_sessions_lifecycle()
