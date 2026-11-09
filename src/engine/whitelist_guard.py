"""Whitelist Guard: Absolute immunity layer to protect critical emails.
Includes expiration rules for ephemeral security and sign-in alert notices.
"""
from datetime import datetime, timezone
import email.utils
from typing import Optional, Tuple
from src.config_loader import WhitelistConfig
from src.connectors.gmail_connector import EmailMessage

SECURITY_ALERT_KEYWORDS = [
    "security alert",
    "critical security alert",
    "new sign-in",
    "recent security activity",
    "password changed",
    "password was changed",
    "2-step verification turned",
    "2-step verification was",
    "two-step verification",
    "verification code",
    "account recovered",
    "access granted to",
    "suspicious sign-in",
    "new device signed in",
    "security notification",
    "recovery phone changed",
    "recovery email changed",
    "unrecognized sign-in",
    "review recent activity",
    "someone added you",
]

def is_security_alert(message: EmailMessage) -> bool:
    """Detects whether an email is an automated account security or sign-in alert.
    
    Covers Google security alerts as well as other major providers (Apple, Microsoft, GitHub).
    """
    sender_lower = (message.sender_email or "").lower()
    domain_lower = (message.sender_domain or "").lower()
    subject_lower = (message.subject or "").lower()
    content_lower = f"{subject_lower} {(message.snippet or '').lower()}"

    # Exclude receipts, invoices, orders, and financial/billing emails
    for excl in ["invoice", "receipt", "billing", "order confirmation", "payment received", "payment confirmation", "bank statement", "tax document", "subscription"]:
        if excl in content_lower:
            return False

    is_security_sender = (
        "accounts.google.com" in sender_lower or
        "google.com" in domain_lower or
        sender_lower.startswith("no-reply@accounts.google.com") or
        "accountprotection.microsoft.com" in sender_lower or
        "appleid@id.apple.com" in sender_lower or
        sender_lower in ("no-reply@github.com", "notifications@github.com")
    )

    has_security_keyword = any(kw in content_lower for kw in SECURITY_ALERT_KEYWORDS)
    if is_security_sender and has_security_keyword:
        return True

    # Check for unmistakable alert subjects even if sender format slightly varies
    if any(phrase in subject_lower for phrase in [
        "security alert", "critical security alert", "new sign-in on", "new sign-in from", "recent security activity"
    ]):
        return True

    return False

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
    ):
        self.config = config
        self.expire_security_alerts = expire_security_alerts
        self.security_alerts_retention_days = security_alerts_retention_days
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

        # Special Safeguard: Ephemeral Security Alerts Expiration
        # Google sign-in alerts and security notifications are critical when recent,
        # but become obsolete after the retention period.
        if self.expire_security_alerts and is_security_alert(message):
            age_days = get_message_age_days(message)
            if age_days is not None and age_days > self.security_alerts_retention_days:
                # Expired security alert: Intentionally NOT protected by domain whitelist!
                return False, ""
            else:
                # Recent security alert: Absolute immunity within retention window
                age_str = f"{int(age_days)}d old" if age_days is not None else "recent"
                return True, f"Protected: Recent security alert ({age_str}, within {self.security_alerts_retention_days}-day safety window)"

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

