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
    assert "Expired Security Alert" in res_expired.reason

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

def test_category_expiration_promotions_social_purchases():
    """Verify that emails in Promotions, Social, and Purchases are kept for 14 days and then trashed."""
    wl_config = WhitelistConfig(
        protected_domains=["google.com", "amazon.com", "linkedin.com"],
        protected_keywords=["receipt", "order confirmation"]
    )
    guard = WhitelistGuard(
        wl_config,
        expire_categories=True,
        categories_retention_days=14,
        expired_categories=["promotions", "social", "purchases"]
    )
    scorer = SpamScorer(
        guard,
        CustomRulesMatcher(CustomRulesConfig()),
        DetectionSettings(
            expire_old_categories=True,
            categories_retention_days=14,
            expired_categories=["promotions", "social", "purchases"]
        )
    )

    now = datetime.now(timezone.utc)

    # 1. Recent Promotion (5 days old) -> MUST BE PROTECTED
    promo_recent = create_sample_message(
        mid="promo_recent_1",
        sender="Nike Store",
        sender_email="news@nike.com",
        sender_domain="nike.com",
        subject="Exclusive Weekend Sale: 30% off sneakers",
        snippet="Check out our latest flash sale",
        labels=["CATEGORY_PROMOTIONS"],
        has_list_unsub=True,
        date=now - timedelta(days=5),
    )
    res_promo_recent = scorer.evaluate(promo_recent)
    assert res_promo_recent.is_protected is True
    assert res_promo_recent.action == "PROTECTED"
    assert "Promotions" in res_promo_recent.reason

    # 2. Expired Promotion (25 days old) -> MUST BE TARGETED_TRASH
    promo_old = create_sample_message(
        mid="promo_old_1",
        sender="Nike Store",
        sender_email="news@nike.com",
        sender_domain="nike.com",
        subject="Exclusive Weekend Sale: 30% off sneakers",
        snippet="Check out our latest flash sale",
        labels=["CATEGORY_PROMOTIONS"],
        has_list_unsub=True,
        date=now - timedelta(days=25),
    )
    res_promo_old = scorer.evaluate(promo_old)
    assert res_promo_old.is_protected is False
    assert res_promo_old.action == "TARGETED_TRASH"
    assert res_promo_old.score == 1.0
    assert "Promotions" in res_promo_old.reason

    # 3. Recent Social update (3 days old) -> MUST BE PROTECTED
    social_recent = create_sample_message(
        mid="social_recent_1",
        sender="LinkedIn",
        sender_email="updates@linkedin.com",
        sender_domain="linkedin.com",
        subject="You have 3 new notifications on LinkedIn",
        snippet="See who viewed your profile",
        labels=["CATEGORY_SOCIAL"],
        date=now - timedelta(days=3),
    )
    res_social_recent = scorer.evaluate(social_recent)
    assert res_social_recent.is_protected is True
    assert res_social_recent.action == "PROTECTED"
    assert "Social" in res_social_recent.reason

    # 4. Expired Social update (21 days old) -> MUST BE TARGETED_TRASH
    social_old = create_sample_message(
        mid="social_old_1",
        sender="LinkedIn",
        sender_email="updates@linkedin.com",
        sender_domain="linkedin.com",
        subject="You have 3 new notifications on LinkedIn",
        snippet="See who viewed your profile",
        labels=["CATEGORY_SOCIAL"],
        date=now - timedelta(days=21),
    )
    res_social_old = scorer.evaluate(social_old)
    assert res_social_old.is_protected is False
    assert res_social_old.action == "TARGETED_TRASH"
    assert res_social_old.score == 1.0
    assert "Social" in res_social_old.reason

    # 5. Recent Purchase order update (6 days old) -> MUST BE PROTECTED
    purchase_recent = create_sample_message(
        mid="purch_recent_1",
        sender="Amazon.com",
        sender_email="auto-confirm@amazon.com",
        sender_domain="amazon.com",
        subject="Your Amazon.com order #102-392019 has shipped",
        snippet="Track your package for your order",
        labels=["CATEGORY_PURCHASES"],
        date=now - timedelta(days=6),
    )
    res_purch_recent = scorer.evaluate(purchase_recent)
    assert res_purch_recent.is_protected is True
    assert res_purch_recent.action == "PROTECTED"
    assert "Purchases" in res_purch_recent.reason

    # 6. Expired Purchase order update (30 days old) -> MUST BE TARGETED_TRASH
    purchase_old = create_sample_message(
        mid="purch_old_1",
        sender="Amazon.com",
        sender_email="auto-confirm@amazon.com",
        sender_domain="amazon.com",
        subject="Your Amazon.com order #102-392019 has shipped",
        snippet="Track your package for your order",
        labels=["CATEGORY_PURCHASES"],
        date=now - timedelta(days=30),
    )
    res_purch_old = scorer.evaluate(purchase_old)
    assert res_purch_old.is_protected is False
    assert res_purch_old.action == "TARGETED_TRASH"
    assert res_purch_old.score == 1.0
    assert "Purchases" in res_purch_old.reason

    # 7. Starred purchase email (40 days old) -> MUST REMAIN PROTECTED
    purchase_starred = create_sample_message(
        mid="purch_starred_1",
        sender="Amazon.com",
        sender_email="auto-confirm@amazon.com",
        sender_domain="amazon.com",
        subject="Your Amazon.com order confirmation",
        snippet="Order details",
        is_starred=True,
        labels=["CATEGORY_PURCHASES"],
        date=now - timedelta(days=40),
    )
    res_starred = scorer.evaluate(purchase_starred)
    assert res_starred.is_protected is True
    assert res_starred.action == "PROTECTED"

    # 8. Tax form / bank statement (50 days old) -> MUST REMAIN PROTECTED (Exempt)
    bank_doc = create_sample_message(
        mid="bank_doc_1",
        sender="Bank",
        sender_email="statements@mybank.com",
        sender_domain="mybank.com",
        subject="Your annual 1099 tax form and bank statement",
        snippet="Download your official tax document",
        labels=["CATEGORY_PURCHASES"],
        date=now - timedelta(days=50),
    )
    res_bank = scorer.evaluate(bank_doc)
    assert res_bank.is_protected is False or res_bank.action != "TARGETED_TRASH"
    assert "Expired Category" not in res_bank.reason

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
    test_category_expiration_promotions_social_purchases()
    print("All engine, security alert, and category lifecycle tests passed successfully!")
