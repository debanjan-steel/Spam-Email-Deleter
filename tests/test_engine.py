"""Unit tests for the rules engine, whitelist guard, spam scorer, and audit logger.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile

# Ensure workspace root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config_loader import ConfigManager, WhitelistConfig, CustomRulesConfig, DetectionSettings
from src.connectors.gmail_connector import EmailMessage
from src.engine.whitelist_guard import WhitelistGuard
from src.engine.custom_rules import CustomRulesMatcher
from src.engine.spam_scorer import SpamScorer
from src.storage.audit_logger import AuditLogger

def create_sample_message(
    mid: str = "msg_001",
    sender: str = "Promo Sender",
    sender_email: str = "promo@dealmarket.xyz",
    sender_domain: str = "dealmarket.xyz",
    subject: str = "Huge 90% discount on shoes",
    snippet: str = "Click here to claim your prize today",
    is_starred: bool = False,
    is_important: bool = False,
    labels: list = None,
    has_list_unsub: bool = True,
    auth_results: str = "spf=pass dkim=pass",
) -> EmailMessage:
    return EmailMessage(
        id=mid,
        thread_id=f"thread_{mid}",
        sender=sender,
        sender_email=sender_email,
        sender_domain=sender_domain,
        recipient="user@gmail.com",
        subject=subject,
        date_str="Sun, 8 Nov 2026 12:00:00 +0000",
        date=datetime.now(timezone.utc),
        snippet=snippet,
        labels=labels or ["INBOX"],
        has_list_unsubscribe=has_list_unsub,
        auth_results=auth_results,
        is_starred=is_starred,
        is_important=is_important,
    )

def test_whitelist_protection_keywords():
    wl_config = WhitelistConfig(
        protected_keywords=["2fa", "verification code", "receipt", "order confirmation"]
    )
    guard = WhitelistGuard(wl_config)

    # 1. Message with 2FA should be protected
    msg_2fa = create_sample_message(
        subject="Your 2FA security code is 492019",
        snippet="Do not share this code with anyone.",
    )
    is_prot, reason = guard.check_protection(msg_2fa)
    assert is_prot is True
    assert "2fa" in reason

    # 2. Ordinary promotional message should not be protected
    msg_promo = create_sample_message(subject="Check out our latest boots")
    is_prot, _ = guard.check_protection(msg_promo)
    assert is_prot is False

def test_whitelist_starred_immunity():
    wl_config = WhitelistConfig()
    guard = WhitelistGuard(wl_config)

    msg_starred = create_sample_message(is_starred=True)
    is_prot, reason = guard.check_protection(msg_starred)
    assert is_prot is True
    assert "Starred" in reason

def test_custom_rules_matching():
    rules_config = CustomRulesConfig(
        targeted_senders=["annoying.newsletter@spam.com"],
        targeted_domains=["sketchydeals.xyz"],
        targeted_subject_keywords=["free bitcoin giveaway"],
    )
    matcher = CustomRulesMatcher(rules_config)

    # Test exact sender match
    msg1 = create_sample_message(sender_email="annoying.newsletter@spam.com")
    matched, reason = matcher.check_match(msg1)
    assert matched is True
    assert "Sender blacklisted" in reason

    # Test domain match
    msg2 = create_sample_message(sender_email="offers@sub.sketchydeals.xyz", sender_domain="sub.sketchydeals.xyz")
    matched, reason = matcher.check_match(msg2)
    assert matched is True
    assert "Domain blacklisted" in reason

    # Test subject keyword match
    msg3 = create_sample_message(subject="Claim your Free Bitcoin Giveaway now")
    matched, reason = matcher.check_match(msg3)
    assert matched is True
    assert "Subject matched" in reason

def test_pipeline_precedence_whitelist_overrules_blacklist():
    """Verify that even if an email matches a custom delete rule, the Whitelist ALWAYS wins."""
    wl_config = WhitelistConfig(protected_keywords=["invoice"])
    rules_config = CustomRulesConfig(targeted_domains=["company.com"])
    detection_settings = DetectionSettings()

    guard = WhitelistGuard(wl_config)
    matcher = CustomRulesMatcher(rules_config)
    scorer = SpamScorer(guard, matcher, detection_settings)

    # Message matches blacklist domain "company.com", BUT contains critical keyword "invoice"
    msg = create_sample_message(
        sender_email="billing@company.com",
        sender_domain="company.com",
        subject="Your monthly invoice #10294",
    )
    res = scorer.evaluate(msg)

    # Must be PROTECTED, NOT deleted
    assert res.is_protected is True
    assert res.action == "PROTECTED"

def test_audit_logger_record_and_restore():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_audit.db"
        logger = AuditLogger(db_path=db_path)

        res = scorer = create_sample_message(mid="test_101")
        from src.engine.spam_scorer import ClassificationResult
        cl_res = ClassificationResult(
            message_id="test_101",
            thread_id="th_101",
            subject="Spam",
            sender="Spammer",
            sender_email="spammer@test.com",
            date_str="today",
            score=0.9,
            action="SPAM_TRASH",
            reason="High spam score",
            is_protected=False,
            labels=["INBOX"],
        )

        logger.record_batch("batch_test_1", [cl_res], account_email="personal@gmail.com")
        logger.record_batch("batch_test_2", [cl_res], account_email="work@gmail.com")
        
        all_batches = logger.list_batches()
        assert len(all_batches) == 2
        
        personal_batches = logger.list_batches(account_email="personal@gmail.com")
        assert len(personal_batches) == 1
        assert personal_batches[0]["batch_id"] == "batch_test_1"

        entries = logger.get_batch_entries("batch_test_1")
        assert len(entries) == 1
        assert entries[0]["message_id"] == "test_101"
        assert entries[0]["account_email"] == "personal@gmail.com"

        logger.mark_batch_restored("batch_test_1")
        batches_updated = logger.list_batches(account_email="personal@gmail.com")
        assert batches_updated[0]["status"] == "RESTORED"

if __name__ == "__main__":
    test_whitelist_protection_keywords()
    test_whitelist_starred_immunity()
    test_custom_rules_matching()
    test_pipeline_precedence_whitelist_overrules_blacklist()
    test_audit_logger_record_and_restore()
    print("All 6 tests passed successfully (including multi-account audit)!")
