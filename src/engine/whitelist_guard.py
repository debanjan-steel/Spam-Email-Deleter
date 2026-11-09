"""Whitelist Guard: Absolute immunity layer to protect critical emails.
Includes expiration rules for ephemeral security and sign-in alert notices.
"""
from datetime import datetime, timezone
import email.utils
from typing import List, Optional, Tuple
from src.config_loader import WhitelistConfig
from src.connectors.gmail_connector import EmailMessage

# Keywords and compound phrases indicating account sign-in, login, or security alert notifications
SECURITY_ALERT_KEYWORDS = [
    # Sign-in & Login alerts across all platforms (GitHub, Google, Microsoft, Apple, Steam, etc.)
    "security alert",
    "critical security alert",
    "security notification",
    "recent security activity",
    "new sign-in",
    "new sign in",
    "new login",
    "new log-in",
    "new device signed in",
    "new device logged in",
    "new device was used to sign in",
    "new device was used to log in",
    "device was used to sign in",
    "device was used to log in",
    "access from new",
    "access from a new",
    "unusual sign-in",
    "unusual login",
    "suspicious sign-in",
    "suspicious login",
    "unrecognized sign-in",
    "unrecognized login",
    "sign-in attempt",
    "login attempt",
    "successful sign-in",
    "successful login",
    "you just logged in",
    "you just signed in",
    "you've logged in",
    "you've signed in",
    "did you just log in",
    "did you just sign in",
    "someone logged in",
    "someone signed in",
    "was used to sign in",
    "was used to log in",
    "logged in from",
    "signed in from",
    "signed into your",
    "logged into your",
    "login verification",
    "sign-in verification",
    # Password & Verification alerts
    "password changed",
    "password was changed",
    "password reset successful",
    "2-step verification turned",
    "2-step verification was",
    "two-step verification",
    "2-factor authentication",
    "two-factor authentication",
    "verification code",
    "one-time password",
    "one-time passcode",
    "steam guard code",
    "security code",
    "account recovered",
    "recovery phone changed",
    "recovery email changed",
    "review recent activity",
    "someone added you to an account",
    "access granted to",
]

# Known security / auth senders across major platforms
KNOWN_AUTH_SENDERS = [
    "accounts.google.com",
    "google.com",
    "accountprotection.microsoft.com",
    "appleid@id.apple.com",
    "github.com",
    "steampowered.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "facebookmail.com",
    "dropbox.com",
    "slack.com",
    "discord.com",
    "spotify.com",
    "netflix.com",
    "amazon.com",
    "gitlab.com",
    "bitbucket.org",
]

# Exclusions to strictly prevent false matches on transactional, financial, and dev repo notifications
ALERT_EXCLUSIONS = [
    "invoice", "receipt", "billing", "order confirmation",
    "payment received", "payment confirmation", "bank statement",
    "tax document", "subscription renewed", "subscription confirmation",
    "promo code", "discount code", "coupon",
    "pull request", "issue #", "new issue", "merged #", "pushed to",
    "created a branch", "release v", "workflow run"
]

def get_alert_provider_name(message: EmailMessage) -> str:
    """Extracts a friendly brand/provider name for the security alert notice."""
    sender_lower = (message.sender_email or "").lower()
    domain_lower = (message.sender_domain or "").lower()
    subject_lower = (message.subject or "").lower()

    if "github" in sender_lower or "github" in domain_lower or "[github]" in subject_lower:
        return "GitHub"
    if "google" in sender_lower or "google" in domain_lower:
        return "Google"
    if "microsoft" in sender_lower or "microsoft" in domain_lower:
        return "Microsoft"
    if "apple" in sender_lower or "apple" in domain_lower:
        return "Apple"
    if "steam" in sender_lower or "steampowered" in domain_lower:
        return "Steam"
    if "discord" in sender_lower or "discord" in domain_lower:
        return "Discord"
    if "linkedin" in sender_lower or "linkedin" in domain_lower:
        return "LinkedIn"
    if "twitter" in sender_lower or "x.com" in domain_lower:
        return "X (Twitter)"
    if "facebook" in sender_lower or "facebookmail" in domain_lower or "meta" in domain_lower:
        return "Facebook / Meta"
    if "dropbox" in sender_lower or "dropbox" in domain_lower:
        return "Dropbox"
    if "slack" in sender_lower or "slack" in domain_lower:
        return "Slack"
    if "amazon" in sender_lower or "amazon" in domain_lower:
        return "Amazon"
    if "spotify" in sender_lower or "spotify" in domain_lower:
        return "Spotify"
    if "netflix" in sender_lower or "netflix" in domain_lower:
        return "Netflix"

    if message.sender_domain:
        return message.sender_domain
    return message.sender or "Account Service"

def is_security_alert(message: EmailMessage) -> bool:
    """Detects whether an email is an automated account security or sign-in alert.
    
    Covers Google, GitHub, Microsoft, Apple, Steam, Discord, and any other platform
    sending login/sign-in notifications, 2FA codes, or security alerts.
    """
    sender_lower = (message.sender_email or "").lower()
    domain_lower = (message.sender_domain or "").lower()
    subject_lower = (message.subject or "").lower()
    content_lower = f"{subject_lower} {(message.snippet or '').lower()}"

    # 1. Strict Exclusions: receipts, invoices, financial billing, and developer PR/issue notifications
    for excl in ALERT_EXCLUSIONS:
        if excl in content_lower:
            return False

    # 2. Check if sender is a recognized authentication/security domain
    is_auth_sender = any(auth_domain in sender_lower or auth_domain in domain_lower for auth_domain in KNOWN_AUTH_SENDERS)

    # 3. Check for security/sign-in phrases
    has_alert_phrase = any(kw in content_lower for kw in SECURITY_ALERT_KEYWORDS)
    if is_auth_sender and has_alert_phrase:
        return True

    # 4. Check subject line for unmistakable sign-in / login phrases from ANY provider
    for phrase in [
        "security alert", "critical security alert", "security notification", "recent security activity",
        "new sign-in", "new sign in", "new login", "new log-in",
        "new device signed in", "new device logged in", "was used to sign in", "was used to log in",
        "you just logged in", "you just signed in", "you've logged in", "you've signed in",
        "did you just log in", "did you just sign in", "someone logged in", "someone signed in",
        "unusual sign-in", "unusual login", "suspicious sign-in", "suspicious login",
        "unrecognized sign-in", "unrecognized login", "access from new", "access from a new",
        "sign-in attempt", "login attempt", "successful sign-in", "successful login",
    ]:
        if phrase in subject_lower:
            return True

    return False

# Social media notification domains
SOCIAL_DOMAINS = [
    "facebookmail.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "tiktok.com", "pinterest.com", "reddit.com",
    "threads.net", "snapchat.com", "youtube.com", "quora.com",
    "medium.com", "tumblr.com", "twitch.tv"
]

# Purchase and order confirmation keywords
PURCHASE_PHRASES = [
    "order confirmation", "order confirmed", "your order of", "your order #",
    "order #", "order receipt", "purchase receipt", "receipt for your purchase",
    "your purchase of", "payment confirmation", "payment received",
    "shipment update", "shipped", "tracking number", "track your package",
    "out for delivery", "package delivered", "delivered today", "delivered to your",
    "delivery confirmation", "shipping confirmation", "item dispatched",
    "order status", "your amazon.com order", "your ebay order"
]

# Critical financial, invoice, and legal documents that must NEVER be auto-expired under purchases
FINANCIAL_TAX_EXCLUSIONS = [
    "invoice", "tax form", "tax document", "1099", "w-2", "w2", "bank statement",
    "salary", "paystub", "payroll", "legal notice", "court", "subpoena",
    "insurance policy", "mortgage", "loan statement"
]

def get_message_ephemeral_category(message: EmailMessage) -> Optional[str]:
    """Determines if a message belongs to an ephemeral category: 'promotions', 'social', or 'purchases'.
    
    Excludes critical financial and legal documents (e.g. tax documents, bank statements).
    """
    subject_lower = (message.subject or "").lower()
    snippet_lower = (message.snippet or "").lower()
    content_lower = f"{subject_lower} {snippet_lower}"
    sender_lower = (message.sender_email or "").lower()
    domain_lower = (message.sender_domain or "").lower()

    # Never treat tax documents, bank statements, or payroll as ephemeral
    for excl in FINANCIAL_TAX_EXCLUSIONS:
        if excl in content_lower:
            return None

    # 1. Check direct Gmail labels
    msg_labels = [str(l).upper() for l in (message.labels or [])]
    for lbl in msg_labels:
        if "PROMOTION" in lbl:
            return "promotions"
        if "SOCIAL" in lbl:
            return "social"
        if "PURCHASE" in lbl:
            return "purchases"

    # 2. Social network domains
    if any(s_dom in domain_lower or s_dom in sender_lower for s_dom in SOCIAL_DOMAINS):
        return "social"

    # 3. Purchases / Orders
    if any(phrase in content_lower for phrase in PURCHASE_PHRASES):
        return "purchases"

    # 4. Promotional indicators (List-Unsubscribe header or strong marketing keywords)
    if message.has_list_unsubscribe:
        return "promotions"

    for promo_kw in ["sale", "% off", "discount", "special offer", "newsletter", "weekly digest", "deal of the day"]:
        if promo_kw in subject_lower:
            return "promotions"

    return None

def get_message_age_days(message: EmailMessage) -> Optional[float]:
    """Calculates email age in fractional days from current UTC time."""
    msg_date = message.date
    if not msg_date and message.date_str:
        try:
            msg_date = email.utils.parsedate_to_datetime(message.date_str)
        except Exception:
            msg_date = None

    if not msg_date:
        return None

    now = datetime.now(timezone.utc)
    if msg_date.tzinfo is None:
        msg_date = msg_date.replace(tzinfo=timezone.utc)
    else:
        msg_date = msg_date.astimezone(timezone.utc)

    diff = (now - msg_date).total_seconds()
    return max(0.0, diff / 86400.0)

class WhitelistGuard:
    """Enforces absolute immunity rules. Protected emails are NEVER deleted."""

    def __init__(
        self,
        config: WhitelistConfig,
        expire_security_alerts: bool = True,
        security_alerts_retention_days: int = 14,
        expire_categories: bool = True,
        categories_retention_days: int = 14,
        expired_categories: Optional[List[str]] = None,
    ):
        self.config = config
        self.expire_security_alerts = expire_security_alerts
        self.security_alerts_retention_days = security_alerts_retention_days
        self.expire_categories = expire_categories
        self.categories_retention_days = categories_retention_days
        self.expired_categories = expired_categories or ["promotions", "social", "purchases"]
        self._normalize()

    def _normalize(self) -> None:
        """Pre-processes strings for fast case-insensitive lookups."""
        self.senders_set = {s.strip().lower() for s in self.config.protected_senders if s.strip()}
        self.domains_list = [d.strip().lower() for d in self.config.protected_domains if d.strip()]
        self.keywords_list = [k.strip().lower() for k in self.config.protected_keywords if k.strip()]

    def update_config(self, config: WhitelistConfig) -> None:
        self.config = config
        self._normalize()

    def check_protection(self, message: EmailMessage) -> Tuple[bool, str]:
        """Checks if an email is immune from deletion.
        
        Returns:
            (is_protected, reason)
        """
        flags = self.config.protection_flags

        # 1. Starred check (User explicitly starred/flagged - absolute immunity)
        if flags.protect_starred and message.is_starred:
            return True, "Protected: Starred / Flagged by user"

        # Special Safeguard: Ephemeral Security & Sign-In Alerts Expiration
        # Automated login notices and security alerts (from Google, GitHub, Microsoft, Apple, etc.)
        # are critical when recent, but become obsolete after the retention period.
        if self.expire_security_alerts and is_security_alert(message):
            age_days = get_message_age_days(message)
            if age_days is not None and age_days > self.security_alerts_retention_days:
                # Expired security alert: Intentionally NOT protected by domain whitelist!
                return False, ""
            else:
                # Recent security alert: Absolute immunity within retention window
                provider = get_alert_provider_name(message)
                age_str = f"{int(age_days)}d old" if age_days is not None else "recent"
                return True, f"Protected: Recent {provider} sign-in alert ({age_str}, within {self.security_alerts_retention_days}-day safety window)"

        # Special Safeguard: Ephemeral Category Expiration (Promotion, Social, Purchases)
        # Promotional newsletters, social updates, and purchases/order notifications
        # are kept for the retention period (14 days) and expire thereafter.
        if self.expire_categories:
            cat = get_message_ephemeral_category(message)
            if cat and cat in self.expired_categories:
                age_days = get_message_age_days(message)
                if age_days is not None and age_days > self.categories_retention_days:
                    # Expired category email: Intentionally NOT protected by domain whitelist!
                    return False, ""
                else:
                    age_str = f"{int(age_days)}d old" if age_days is not None else "recent"
                    return True, f"Protected: Recent {cat.capitalize()} email ({age_str}, within {self.categories_retention_days}-day safety window)"

        # 2. Important label check
        if flags.protect_important and message.is_important:
            return True, "Protected: Marked Important by Gmail"

        # 3. Direct sender whitelist check
        if message.sender_email in self.senders_set:
            return True, f"Protected: Whitelisted sender ({message.sender_email})"

        # 4. Domain whitelist check (e.g. .gov, .edu, google.com)
        for dom in self.domains_list:
            if dom.startswith("."):
                if message.sender_domain.endswith(dom):
                    return True, f"Protected: Whitelisted domain extension ({dom})"
            else:
                if message.sender_domain == dom or message.sender_domain.endswith("." + dom):
                    return True, f"Protected: Whitelisted domain ({dom})"

        # 5. Critical transactional keywords check (2FA, receipt, password reset, etc.)
        content_to_check = f"{message.subject} {message.snippet}".lower()
        for kw in self.keywords_list:
            if kw in content_to_check:
                return True, f"Protected: Contains vital keyword '{kw}'"

        return False, ""

