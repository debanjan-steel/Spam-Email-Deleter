"""Whitelist Guard: Absolute immunity layer to protect critical emails.
"""
from typing import Tuple
from src.config_loader import WhitelistConfig
from src.connectors.gmail_connector import EmailMessage

class WhitelistGuard:
    """Enforces absolute immunity rules. Protected emails are NEVER deleted."""

    def __init__(self, config: WhitelistConfig):
        self.config = config
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

        # 1. Starred check
        if flags.protect_starred and message.is_starred:
            return True, "Protected: Starred / Flagged by user"

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

