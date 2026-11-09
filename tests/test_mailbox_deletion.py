"""Unit tests for mailbox deletion and removal in GmailAuthenticator.
"""
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.auth.gmail_auth import GmailAuthenticator

def test_delete_connected_mailbox():
    with tempfile.TemporaryDirectory() as temp_dir:
        tokens_dir = Path(temp_dir) / "tokens"
        tokens_dir.mkdir(parents=True, exist_ok=True)
        auth = GmailAuthenticator(tokens_dir=tokens_dir)

        # 1. Add mock connected mailbox
        acc1_data = {
            "type": "app_password",
            "email": "user1@gmail.com",
            "app_password": "abcdefghijklmnop",
            "messages_total": 1250,
        }
        acc1_file = tokens_dir / f"{auth._sanitize_email_for_filename('user1@gmail.com')}.json"
        with open(acc1_file, "w", encoding="utf-8") as f:
            json.dump(acc1_data, f)

        acc2_data = {
            "type": "app_password",
            "email": "user2@gmail.com",
            "app_password": "ponmlkjihgfedcba",
            "messages_total": 450,
        }
        acc2_file = tokens_dir / f"{auth._sanitize_email_for_filename('user2@gmail.com')}.json"
        with open(acc2_file, "w", encoding="utf-8") as f:
            json.dump(acc2_data, f)

        # Verify listed accounts
        accounts = auth.list_accounts()
        assert len(accounts) == 2
        emails = [a["email"] for a in accounts]
        assert "user1@gmail.com" in emails
        assert "user2@gmail.com" in emails

        # 2. Delete single mailbox
        assert auth.remove_account("user1@gmail.com")
        remaining = auth.list_accounts()
        assert len(remaining) == 1
        assert remaining[0]["email"] == "user2@gmail.com"
        assert not acc1_file.exists()

        # 3. Non-existent mailbox delete returns False
        assert not auth.remove_account("nonexistent@gmail.com")

        # 4. Remove all accounts
        # Add another account back
        with open(acc1_file, "w", encoding="utf-8") as f:
            json.dump(acc1_data, f)
        assert len(auth.list_accounts()) == 2

        count_removed = auth.remove_all_accounts()
        assert count_removed == 2
        assert len(auth.list_accounts()) == 0

    print("Mailbox deletion unit tests passed successfully!")

if __name__ == "__main__":
    test_delete_connected_mailbox()
