"""Spam Scorer and Unified Decision Engine.
Evaluates emails across Whitelist, Manual Targeted Rules, and Automated Spam Heuristics.
"""
from dataclasses import dataclass
from typing import List, Optional

from src.config_loader import DetectionSettings
from src.connectors.gmail_connector import EmailMessage
from src.engine.custom_rules import CustomRulesMatcher
from src.engine.whitelist_guard import WhitelistGuard

@dataclass
class ClassificationResult:
    message_id: str
    thread_id: str
    subject: str
    sender: str
    sender_email: str
    date_str: str
    score: float
    action: str  # "PROTECTED", "TARGETED_TRASH", "SPAM_TRASH", "SAFE"
    reason: str
    is_protected: bool
    labels: List[str]

# Common heuristic spam indicators
SPAM_TRIGGER_PHRASES = [
    "claim your prize", "congratulations you won", "you have won",
    "exclusive offer", "act now", "limited time offer",
    "unclaimed reward", "free gift", "crypto investment",
    "earn money fast", "wire transfer", "risk free",
    "meet singles", "pre-approved loan", "urgent account update",
    "click here immediately", "casino bonus", "cash bonus"
]

class SpamScorer:
    """Evaluates emails and assigns confidence scores and target actions."""

    def __init__(
        self,
        whitelist_guard: WhitelistGuard,
        custom_rules: CustomRulesMatcher,
        detection_settings: DetectionSettings,
    ):
        self.whitelist_guard = whitelist_guard
        self.custom_rules = custom_rules
        self.settings = detection_settings

    def evaluate(self, message: EmailMessage) -> ClassificationResult:
        """Runs the 3-tier safety and classification pipeline on an email."""

        # TIER 1: Check Absolute Immunity Whitelist (NEVER TOUCH)
        is_protected, prot_reason = self.whitelist_guard.check_protection(message)
        if is_protected:
            return ClassificationResult(
                message_id=message.id,
                thread_id=message.thread_id,
                subject=message.subject,
                sender=message.sender,
                sender_email=message.sender_email,
                date_str=message.date_str,
                score=0.0,
                action="PROTECTED",
                reason=prot_reason,
                is_protected=True,
                labels=message.labels,
            )

        # TIER 2: Check User-Defined Manual Targeted Rules (Manual Blacklist)
        is_manual, manual_reason = self.custom_rules.check_match(message)
        if is_manual:
            return ClassificationResult(
                message_id=message.id,
                thread_id=message.thread_id,
                subject=message.subject,
                sender=message.sender,
                sender_email=message.sender_email,
                date_str=message.date_str,
                score=1.0,
                action="TARGETED_TRASH",
                reason=manual_reason,
                is_protected=False,
                labels=message.labels,
            )

        # TIER 3: Automated Spam Heuristic Scoring
        score = 0.0
        reasons = []

        # 1. Existing Gmail SPAM classification
        if "SPAM" in message.labels:
            score += 0.80
            reasons.append("Flagged by Gmail's built-in spam filter")

        # 2. Authentication header inspection (SPF, DKIM, DMARC)
        if self.settings.check_auth_headers and message.auth_results:
            auth_lower = message.auth_results.lower()
            if "spf=fail" in auth_lower or "received-spf: fail" in auth_lower:
                score += 0.35
                reasons.append("SPF authentication failed (possible sender spoof)")
            if "dkim=fail" in auth_lower:
                score += 0.35
                reasons.append("DKIM signature failed")
            if "dmarc=fail" in auth_lower:
                score += 0.30
                reasons.append("DMARC verification failed")
            if "spf=pass" in auth_lower and "dkim=pass" in auth_lower:
                score -= 0.15

        # 3. List-Unsubscribe presence (bulk commercial or newsletter)
        if self.settings.check_unsubscribe_header and message.has_list_unsubscribe:
            score += 0.20
            reasons.append("Contains List-Unsubscribe bulk marketing header")

        # 4. Trigger phrases in subject and snippet
        content = f"{message.subject} {message.snippet}".lower()
        matched_triggers = [p for p in SPAM_TRIGGER_PHRASES if p in content]
        if matched_triggers:
            score += min(0.40, len(matched_triggers) * 0.15)
            reasons.append(f"Spam phrases detected: {', '.join(matched_triggers[:2])}")

        # Clamp score between 0.0 and 1.0
        final_score = max(0.0, min(1.0, round(score, 2)))

        if final_score >= self.settings.spam_threshold:
            action = "SPAM_TRASH"
            reason_str = " | ".join(reasons) if reasons else f"Spam score {final_score:.2f} exceeded threshold"
        else:
            action = "SAFE"
            reason_str = f"Spam score {final_score:.2f} is below threshold ({self.settings.spam_threshold})"

        return ClassificationResult(
            message_id=message.id,
            thread_id=message.thread_id,
            subject=message.subject,
            sender=message.sender,
            sender_email=message.sender_email,
            date_str=message.date_str,
            score=final_score,
            action=action,
            reason=reason_str,
            is_protected=False,
            labels=message.labels,
        )
