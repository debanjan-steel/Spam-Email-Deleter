"""Unit tests for high-volume email scanning, IMAP multi-fetch parsing, and pagination.
"""
from datetime import datetime, timezone
from pathlib import Path
import sys
from unittest.mock import MagicMock

# Ensure workspace root is in path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from src.config_loader import ConfigManager, GeneralSettings
from src.connectors.imap_connector import GmailImapConnector
from src.connectors.gmail_connector import GmailConnector

def test_imap_multi_fetch_parsing():
    """Test that multiple emails returned in a single IMAP FETCH command are parsed correctly."""
    connector = GmailImapConnector("user@gmail.com", "fake_app_password_123")

    mock_fetch_data = [
        (
            b'101 (BODY[HEADER] {60}',
            b'From: Spammer <spammer@badsite.com>\r\nSubject: Win Money Fast\r\n\r\n'
        ),
        (
            b' BODY[TEXT]<0> {30}',
            b'Claim your prize immediately!'
        ),
        b' FLAGS (\\Seen))',
        (
            b'102 (BODY[HEADER] {55}',
            b'From: Boss <boss@company.com>\r\nSubject: Meeting Tomorrow\r\n\r\n'
        ),
        (
            b' BODY[TEXT]<0> {25}',
            b'See you in the morning.'
        ),
        b' FLAGS (\\Flagged \\Seen))'
    ]

    parsed = connector._parse_multi_fetch_response("INBOX", mock_fetch_data)
    assert len(parsed) == 2
    assert "INBOX:101" in parsed
    assert "INBOX:102" in parsed

    msg1 = parsed["INBOX:101"]
    assert msg1.sender_email == "spammer@badsite.com"
    assert msg1.subject == "Win Money Fast"
    assert "Claim your prize" in msg1.snippet
    assert msg1.is_starred is False

    msg2 = parsed["INBOX:102"]
    assert msg2.sender_email == "boss@company.com"
    assert msg2.subject == "Meeting Tomorrow"
    assert msg2.is_starred is True

def test_config_high_limit_default():
    """Test that default max_emails_to_scan is set to 10000."""
    cfg_mgr = ConfigManager()
    assert cfg_mgr.app_config.general.max_emails_to_scan >= 10000

def test_gmail_connector_pagination():
    """Test that Gmail API Connector paginates across pages up to max_results."""
    mock_service = MagicMock()
    
    # Page 1 returns 500 items + nextPageToken
    page1 = {
        "messages": [{"id": f"msg_{i}"} for i in range(500)],
        "nextPageToken": "token_page_2"
    }
    # Page 2 returns 300 items, no nextPageToken
    page2 = {
        "messages": [{"id": f"msg_{i}"} for i in range(500, 800)]
    }

    mock_list = MagicMock()
    mock_list.execute.side_effect = [page1, page2]
    mock_service.users().messages().list.return_value = mock_list

    connector = GmailConnector(mock_service)
    mids = connector.list_message_ids(max_results=1000)

    assert len(mids) == 800
    assert mids[0] == "msg_0"
    assert mids[799] == "msg_799"
    assert mock_service.users().messages().list.call_count == 2

if __name__ == "__main__":
    test_imap_multi_fetch_parsing()
    test_config_high_limit_default()
    test_gmail_connector_pagination()
    print("All high-volume batch tests passed successfully!")

