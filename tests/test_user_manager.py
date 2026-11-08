"""Unit tests for multi-tenant UserManager and user isolation.
"""
import sys
from pathlib import Path
import tempfile
import shutil

# Ensure workspace root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.auth.user_manager import UserManager

def test_user_creation_and_auth():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        db_path = temp_path / "test_users.db"
        data_dir = temp_path / "data"

        user_mgr = UserManager(db_path=db_path, data_dir=data_dir)

        # 1. Invalid username (too short)
        ok, msg, u = user_mgr.create_user("ab", "pass123")
        assert not ok
        assert "at least 3 characters" in msg

        # 2. Invalid password (too short)
        ok, msg, u = user_mgr.create_user("user1", "12345")
        assert not ok
        assert "at least 6 characters" in msg

        # 3. Valid user creation
        ok, msg, user1 = user_mgr.create_user("user1", "securepass123")
        assert ok
        assert user1["username"] == "user1"
        assert "id" in user1

        # 4. Duplicate registration fails
        ok, msg, _ = user_mgr.create_user("user1", "anotherpass")
        assert not ok
        assert "already exists" in msg

        # 5. Successful authentication
        ok, msg, auth_u = user_mgr.authenticate("user1", "securepass123")
        assert ok
        assert auth_u["id"] == user1["id"]

        # 6. Wrong password fails
        ok, msg, _ = user_mgr.authenticate("user1", "wrongpass")
        assert not ok
        assert "Invalid username or password" in msg

        # 7. Non-existent user fails
        ok, msg, _ = user_mgr.authenticate("nobody", "securepass123")
        assert not ok

        # 8. User paths exist and are isolated
        paths1 = user_mgr.get_user_paths(user1["id"])
        assert paths1["tokens_dir"].exists()
        assert paths1["config_dir"].exists()

        # 9. Second user is completely isolated
        ok, _, user2 = user_mgr.create_user("user2", "password456")
        assert ok
        paths2 = user_mgr.get_user_paths(user2["id"])
        assert paths1["user_dir"] != paths2["user_dir"]
        assert paths1["tokens_dir"] != paths2["tokens_dir"]

    print("UserManager unit tests passed successfully!")

if __name__ == "__main__":
    test_user_creation_and_auth()

