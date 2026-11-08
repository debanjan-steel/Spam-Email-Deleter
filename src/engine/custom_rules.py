"""Custom Rules Matcher: Matches user-defined manual deletion criteria.
"""
from datetime import datetime, timezone
from typing import Tuple
from src.config_loader import CustomRulesConfig
from src.connectors.gmail_connector import EmailMessage

class CustomRulesMatcher:
    """Matches emails against user-defined manual deletion rules."""

    def __init__(self, config: CustomRulesConfig):
        self.config = config
        self._normalize()

    def _normalize(self) -> None:
        self.senders_set = {s.strip().lower() for s in self.config.targeted_senders if s.strip()}
        self.domains_list = [d.strip().lower() for d in self.config.targeted_domains if d.strip()]
        self.keywords_list = [k.strip().lower() for k in self.config.targeted_subject_keywords if k.strip()]

    def update_config(self, config: CustomRulesConfig) -> None:
        self.config = config
        self._normalize()

    def check_match(self, message: EmailMessage) -> Tuple[bool, str]:
        """Checks if an email matches any manual deletion rule.
        
        Returns:
            (is_matched, reason)
        """
        # 1. Exact sender match
        if message.sender_email in self.senders_set:
            return True, f"Manual Rule: Sender blacklisted ({message.sender_email})"

        # 2. Domain match
        for dom in self.domains_list:
            if message.sender_domain == dom or message.sender_domain.endswith("." + dom):
                return True, f"Manual Rule: Domain blacklisted ({dom})"

        # 3. Targeted subject keywords
        subject_lower = message.subject.lower()
        for kw in self.keywords_list:
            if kw in subject_lower:
                return True, f"Manual Rule: Subject matched '{kw}'"

        # 4. Optional age rule for promotions
        if self.config.delete_promotions_older_than_days and message.date:
            is_promo = "CATEGORY_PROMOTIONS" in message.labels
            if is_promo:
                now = datetime.now(timezone.utc)
                msg_date = message.date
                if msg_date.tzinfo is None:
                    msg_date = msg_date.replace(tzinfo=timezone.utc)
                days_old = (now - msg_date).days
                if days_old > self.config.delete_promotions_older_than_days:
                    return True, f"Manual Rule: Promotional email older than {self.config.delete_promotions_older_than_days} days ({days_old}d old)"

        return False, ""

