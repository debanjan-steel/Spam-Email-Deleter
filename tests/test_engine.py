"""Unit tests for the rules engine, whitelist guard, spam scorer, and audit logger.
"""
import sys
from datetime import datetime, timezone, timedelta
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
    has_list_unsub: bool = False,
    auth_results: str = "spf=pass dkim=pass",
    date: datetime = None,
) -> EmailMessage:
    msg_date = date or datetime.now(timezone.utc)
    return EmailMessage(
        id=mid,
        thread_id=f"thread_{mid}",
        sender=sender,
        sender_email=sender_email,
        sender_domain=sender_domain,
        recipient="user@gmail.com",
        subject=subject,
        date_str=msg_date.strftime("%a, %d %b %Y %H:%M:%S +0000"),
        date=msg_date,
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
    guard = WhitelistGuard(wl_config, expire_security_alerts=False, expire_categories=False)

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

def test_security_alerts_expiration_active():
    """Verify that old Google security alerts expire after retention period, while recent ones stay protected."""
    wl_config = WhitelistConfig(
        protected_domains=["google.com"],
        protected_keywords=["verification code", "2fa"]
    )
    guard = WhitelistGuard(
        wl_config,
        expire_security_alerts=True,
        security_alerts_retention_days=14
    )
    scorer = SpamScorer(
        guard,
        CustomRulesMatcher(CustomRulesConfig()),
        DetectionSettings(expire_old_security_alerts=True, security_alerts_retention_days=14)
    )

    now = datetime.now(timezone.utc)

    # 1. Recent security alert (3 days old) -> MUST BE PROTECTED
    recent_alert = create_sample_message(
        mid="sec_recent_1",
        sender="Google",
        sender_email="no-reply@accounts.google.com",
        sender_domain="google.com",
        subject="Security alert: New sign-in on Windows",
        snippet="Your Google Account was just signed in to from a new Windows device.",
        date=now - timedelta(days=3),
    )
    res_recent = scorer.evaluate(recent_alert)
    assert res_recent.is_protected is True
    assert res_recent.action == "PROTECTED"
    assert "sign-in alert" in res_recent.reason

    # 2. Expired security alert (20 days old) -> MUST BE TARGETED_TRASH
    expired_alert = create_sample_message(
        mid="sec_expired_1",
        sender="Google",
        sender_email="no-reply@accounts.google.com",
        sender_domain="google.com",
        subject="Security alert: New sign-in on Windows",
        snippet="Your Google Account was just signed in to from a new Windows device.",
        date=now - timedelta(days=20),
    )
    res_expired = scorer.evaluate(expired_alert)
    assert res_expired.is_protected is False
    assert res_expired.action == "TARGETED_TRASH"
    assert res_expired.score == 1.0
    assert "Expired" in res_expired.reason and "Alert" in res_expired.reason

    # 3. Expired security alert that user explicitly STARRED -> MUST REMAIN PROTECTED
    starred_alert = create_sample_message(
        mid="sec_starred_1",
        sender="Google",
        sender_email="no-reply@accounts.google.com",
        sender_domain="google.com",
        subject="Critical security alert",
        snippet="Suspicious sign-in detected.",
        is_starred=True,
        date=now - timedelta(days=25),
    )
    res_starred = scorer.evaluate(starred_alert)
    assert res_starred.is_protected is True
    assert res_starred.action == "PROTECTED"
    assert "Starred" in res_starred.reason

def test_security_alerts_google_invoices_protected():
    """Verify that Google invoices, receipts, and order confirmations NEVER expire or get trashed."""
    wl_config = WhitelistConfig(
        protected_domains=["google.com"],
        protected_keywords=["invoice", "receipt"]
    )
    guard = WhitelistGuard(
        wl_config,
        expire_security_alerts=True,
        security_alerts_retention_days=14
    )
    scorer = SpamScorer(
        guard,
        CustomRulesMatcher(CustomRulesConfig()),
        DetectionSettings(expire_old_security_alerts=True, security_alerts_retention_days=14)
    )

    now = datetime.now(timezone.utc)

    # Old Google Workspace invoice (45 days old)
    invoice_msg = create_sample_message(
        mid="inv_001",
        sender="Google Cloud",
        sender_email="payments-noreply@google.com",
        sender_domain="google.com",
        subject="Your Google Workspace monthly invoice is available",
        snippet="View your invoice and billing summary for the period.",
        has_list_unsub=False,
        date=now - timedelta(days=45),
    )
    res_inv = scorer.evaluate(invoice_msg)
    assert res_inv.is_protected is True
    assert res_inv.action == "PROTECTED"

def test_security_alerts_auto_expire_disabled():
    """Verify that when auto-expiration is disabled, Google security alerts remain protected by domain whitelist."""
    wl_config = WhitelistConfig(protected_domains=["google.com"])
    guard = WhitelistGuard(
        wl_config,
        expire_security_alerts=False,
        security_alerts_retention_days=14
    )
    scorer = SpamScorer(
        guard,
        CustomRulesMatcher(CustomRulesConfig()),
        DetectionSettings(expire_old_security_alerts=False, security_alerts_retention_days=14)
    )

    now = datetime.now(timezone.utc)
    old_alert = create_sample_message(
        mid="sec_disabled_1",
        sender="Google",
        sender_email="no-reply@accounts.google.com",
        sender_domain="google.com",
        subject="Security alert: New sign-in on Windows",
        snippet="Your Google Account was signed in.",
        date=now - timedelta(days=25),
    )
    res = scorer.evaluate(old_alert)
    assert res.is_protected is True
    assert res.action == "PROTECTED"
    assert "google.com" in res.reason

def test_github_and_multiplatform_login_alerts_expiration():
    """Verify that login/sign-in alerts from GitHub, Microsoft, Apple, Discord expire after 14 days,
    while development PRs and receipts stay protected."""
    wl_config = WhitelistConfig(
        protected_domains=["github.com", "microsoft.com", "apple.com", "google.com"],
        protected_keywords=["2fa", "verification code", "receipt", "invoice"]
    )
    guard = WhitelistGuard(
        wl_config,
        expire_security_alerts=True,
        security_alerts_retention_days=14
    )
    scorer = SpamScorer(
        guard,
        CustomRulesMatcher(CustomRulesConfig()),
        DetectionSettings(expire_old_security_alerts=True, security_alerts_retention_days=14)
    )

    now = datetime.now(timezone.utc)

    # 1. GitHub login notice (20 days old) -> MUST BE TARGETED_TRASH
    gh_old_login = create_sample_message(
        mid="gh_login_001",
        sender="GitHub",
        sender_email="no-reply@github.com",
        sender_domain="github.com",
        subject="[GitHub] A new device was used to sign in to your account",
        snippet="We noticed a new sign-in to your GitHub account from Chrome on Windows.",
        date=now - timedelta(days=20),
    )
    res_gh = scorer.evaluate(gh_old_login)
    assert res_gh.is_protected is False
    assert res_gh.action == "TARGETED_TRASH"
    assert res_gh.score == 1.0
    assert "GitHub" in res_gh.reason

    # 2. GitHub recent login notice (3 days old) -> MUST BE PROTECTED
    gh_recent_login = create_sample_message(
        mid="gh_login_002",
        sender="GitHub",
        sender_email="no-reply@github.com",
        sender_domain="github.com",
        subject="[GitHub] Successful sign-in from new IP address",
        snippet="A successful sign-in to your account was detected.",
        date=now - timedelta(days=3),
    )
    res_gh_recent = scorer.evaluate(gh_recent_login)
    assert res_gh_recent.is_protected is True
    assert res_gh_recent.action == "PROTECTED"
    assert "GitHub" in res_gh_recent.reason

    # 3. GitHub Pull Request (25 days old) -> MUST STAY PROTECTED (Excluded from security alert deletion!)
    gh_pr = create_sample_message(
        mid="gh_pr_001",
        sender="GitHub",
        sender_email="notifications@github.com",
        sender_domain="github.com",
        subject="[debanjan-steel/Spam-Email-Deleter] Pull request #2: login feature updated",
        snippet="Review requested on pull request #2.",
        date=now - timedelta(days=25),
    )
    res_pr = scorer.evaluate(gh_pr)
    assert res_pr.is_protected is True
    assert res_pr.action == "PROTECTED"

    # 4. Microsoft unusual sign-in (22 days old) -> MUST BE TARGETED_TRASH
    ms_old_login = create_sample_message(
        mid="ms_login_001",
        sender="Microsoft account team",
        sender_email="account-security-noreply@accountprotection.microsoft.com",
        sender_domain="accountprotection.microsoft.com",
        subject="Microsoft account unusual sign-in activity",
        snippet="We detected something unusual about a recent sign-in to your Microsoft account.",
        date=now - timedelta(days=22),
    )
    res_ms = scorer.evaluate(ms_old_login)
    assert res_ms.is_protected is False
    assert res_ms.action == "TARGETED_TRASH"
    assert "Microsoft" in res_ms.reason

    # 5. Apple ID sign-in alert (18 days old) -> MUST BE TARGETED_TRASH
    apple_old_login = create_sample_message(
        mid="apple_login_001",
        sender="Apple",
        sender_email="appleid@id.apple.com",
        sender_domain="apple.com",
        subject="Your Apple ID was used to sign in to iCloud via a web browser",
        snippet="Date and Time: Sunday, October 22, 2026. Browser: Chrome.",
        date=now - timedelta(days=18),
    )
    res_apple = scorer.evaluate(apple_old_login)
    assert res_apple.is_protected is False
    assert res_apple.action == "TARGETED_TRASH"
    assert "Apple" in res_apple.reason

    # 6. Discord new login alert (16 days old) -> MUST BE TARGETED_TRASH
    discord_old_login = create_sample_message(
        mid="discord_login_001",
        sender="Discord",
        sender_email="noreply@discord.com",
        sender_domain="discord.com",
        subject="New login from London, UK",
        snippet="We noticed a login from an IP address or location you don't usually use.",
        date=now - timedelta(days=16),
    )
    res_discord = scorer.evaluate(discord_old_login)
    assert res_discord.is_protected is False
    assert res_discord.action == "TARGETED_TRASH"
    assert "Discord" in res_discord.reason

def test_recordings_and_links_immunity():
    """Verify that emails containing recordings or shared links are permanently immune."""
    wl_config = WhitelistConfig()
    guard = WhitelistGuard(wl_config, expire_security_alerts=True, security_alerts_retention_days=14)
    scorer = SpamScorer(guard, CustomRulesMatcher(CustomRulesConfig()), DetectionSettings())
    now = datetime.now(timezone.utc)

    # 1. Zoom recording email (30 days old) -> MUST BE PROTECTED
    zoom_msg = create_sample_message(
        mid="zoom_001",
        sender="Zoom Video Communications",
        sender_email="no-reply@zoom.us",
        sender_domain="zoom.us",
        subject="Cloud Recording - Weekly Team Sync is now available",
        snippet="Your recording is ready to view. Access your recording online.",
        date=now - timedelta(days=30),
    )
    res_zoom = scorer.evaluate(zoom_msg)
    assert res_zoom.is_protected is True
    assert res_zoom.action == "PROTECTED"
    assert "recording" in res_zoom.reason.lower()

    # 2. Google Drive / Docs shared link (45 days old) -> MUST BE PROTECTED
    drive_msg = create_sample_message(
        mid="drive_001",
        sender="Alice Partner",
        sender_email="alice@partner.com",
        sender_domain="partner.com",
        subject="Project Roadmap & Specifications",
        snippet="Here is the link to the file on drive.google.com/file/d/12345/view",
        date=now - timedelta(days=45),
    )
    res_drive = scorer.evaluate(drive_msg)
    assert res_drive.is_protected is True
    assert res_drive.action == "PROTECTED"
    assert "link" in res_drive.reason.lower() or "drive" in res_drive.reason.lower()

    # 3. Loom video recording -> MUST BE PROTECTED
    loom_msg = create_sample_message(
        mid="loom_001",
        sender="Bob Developer",
        sender_email="bob@startup.io",
        sender_domain="startup.io",
        subject="Loom: Walkthrough of the new UI dashboard",
        snippet="Watch Bob's video on Loom",
        date=now - timedelta(days=20),
    )
    res_loom = scorer.evaluate(loom_msg)
    assert res_loom.is_protected is True
    assert res_loom.action == "PROTECTED"
    assert "loom" in res_loom.reason.lower()

def test_sender_wide_immunity_from_recording_senders():
    """Verify that senders who have sent recordings or shared links grant immunity to all their emails."""
    wl_config = WhitelistConfig()
    guard = WhitelistGuard(wl_config, expire_security_alerts=True, security_alerts_retention_days=14)
    scorer = SpamScorer(guard, CustomRulesMatcher(CustomRulesConfig()), DetectionSettings())
    now = datetime.now(timezone.utc)

    # 1. First message from mentor: contains a meeting recording
    msg1_recording = create_sample_message(
        mid="mentor_001",
        sender="Mentor John",
        sender_email="john@mentorship.org",
        sender_domain="mentorship.org",
        subject="Session Recording: Career Guidance",
        snippet="Here is the zoom recording from our chat today.",
        date=now - timedelta(days=10),
    )
    res1 = scorer.evaluate(msg1_recording)
    assert res1.is_protected is True
    assert "recording" in res1.reason.lower()
    assert "john@mentorship.org" in guard.recording_senders

    # 2. Second message from same mentor: regular discussion with NO recording/link keywords
    msg2_regular = create_sample_message(
        mid="mentor_002",
        sender="Mentor John",
        sender_email="john@mentorship.org",
        sender_domain="mentorship.org",
        subject="Quick follow up regarding next steps",
        snippet="Let me know how the interview went yesterday.",
        date=now - timedelta(days=2),
    )
    res2 = scorer.evaluate(msg2_regular)
    assert res2.is_protected is True
    assert res2.action == "PROTECTED"
    assert "trusted sender has sent recordings/links" in res2.reason.lower()

def test_regular_emails_older_than_14_days_not_auto_deleted():
    """Verify that normal non-security emails >14 days old are NOT automatically trashed."""
    wl_config = WhitelistConfig()
    guard = WhitelistGuard(wl_config, expire_security_alerts=True, security_alerts_retention_days=14)
    scorer = SpamScorer(guard, CustomRulesMatcher(CustomRulesConfig()), DetectionSettings())
    now = datetime.now(timezone.utc)

    # 1. Normal clean newsletter/email older than 14 days (e.g., 25 days old)
    clean_old_email = create_sample_message(
        mid="clean_old_001",
        sender="Tech Digest",
        sender_email="newsletter@techdigest.com",
        sender_domain="techdigest.com",
        subject="Python 3.13 Release Notes and Performance Insights",
        snippet="Here are the top performance improvements in Python 3.13.",
        labels=["INBOX"],
        date=now - timedelta(days=25),
        auth_results="spf=pass dkim=pass",
    )
    res_clean = scorer.evaluate(clean_old_email)
    # Must NOT be TARGETED_TRASH; score should be 0.0 SAFE
    assert res_clean.action != "TARGETED_TRASH"
    assert res_clean.score < 0.75

    # 2. But 1-time throwaway login alert older than 14 days DOES expire
    login_alert_old = create_sample_message(
        mid="login_old_001",
        sender="Google",
        sender_email="no-reply@accounts.google.com",
        sender_domain="google.com",
        subject="Security alert: New sign-in on Windows",
        snippet="Your Google Account was just signed in to from a new Windows device.",
        date=now - timedelta(days=20),
    )
    res_alert = scorer.evaluate(login_alert_old)
    assert res_alert.action == "TARGETED_TRASH"
    assert res_alert.score == 1.0
    assert "Expired" in res_alert.reason

if __name__ == "__main__":
    test_whitelist_protection_keywords()
    test_whitelist_starred_immunity()
    test_custom_rules_matching()
    test_pipeline_precedence_whitelist_overrules_blacklist()
    test_audit_logger_record_and_restore()
    test_security_alerts_expiration_active()
    test_security_alerts_google_invoices_protected()
    test_security_alerts_auto_expire_disabled()
    test_github_and_multiplatform_login_alerts_expiration()
    test_recordings_and_links_immunity()
    test_sender_wide_immunity_from_recording_senders()
    test_regular_emails_older_than_14_days_not_auto_deleted()
    print("All engine, security alert, recording immunity, and sender-wide safeguard tests passed successfully!")
