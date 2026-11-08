"""Configuration loader and manager for Spam Email Deleter.
Handles loading and persisting config.yaml, whitelist.yaml, and custom_rules.yaml.
"""
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

class GeneralSettings(BaseModel):
    trash_only: bool = True
    batch_size: int = 50
    max_emails_to_scan: int = 200
    audit_logging: bool = True

class DetectionSettings(BaseModel):
    spam_threshold: float = 0.75
    check_auth_headers: bool = True
    check_unsubscribe_header: bool = True
    use_ai_fallback: bool = False
    ai_model: str = "gemini-2.5-flash"

class StorageSettings(BaseModel):
    audit_db_path: str = "audit_log.db"

class AppConfig(BaseModel):
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)

class ProtectionFlags(BaseModel):
    protect_starred: bool = True
    protect_important: bool = True
    protect_replied_threads: bool = True

class WhitelistConfig(BaseModel):
    protection_flags: ProtectionFlags = Field(default_factory=ProtectionFlags)
    protected_senders: List[str] = Field(default_factory=list)
    protected_domains: List[str] = Field(default_factory=list)
    protected_keywords: List[str] = Field(default_factory=list)

class CustomRulesConfig(BaseModel):
    targeted_senders: List[str] = Field(default_factory=list)
    targeted_domains: List[str] = Field(default_factory=list)
    targeted_subject_keywords: List[str] = Field(default_factory=list)
    delete_promotions_older_than_days: Optional[int] = None

class ConfigManager:
    """Manages application configurations and persistence."""

    def __init__(self, config_dir: Path = CONFIG_DIR):
        self.config_dir = config_dir
        self.config_path = self.config_dir / "config.yaml"
        self.whitelist_path = self.config_dir / "whitelist.yaml"
        self.custom_rules_path = self.config_dir / "custom_rules.yaml"

        self.app_config = self.load_app_config()
        self.whitelist = self.load_whitelist()
        self.custom_rules = self.load_custom_rules()

    def _read_yaml(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data or {}

    def _write_yaml(self, path: Path, data: Dict[str, Any]) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def load_app_config(self) -> AppConfig:
        raw = self._read_yaml(self.config_path)
        return AppConfig(**raw)

    def save_app_config(self, config: AppConfig) -> None:
        self.app_config = config
        self._write_yaml(self.config_path, config.model_dump())

    def load_whitelist(self) -> WhitelistConfig:
        raw = self._read_yaml(self.whitelist_path)
        return WhitelistConfig(**raw)

    def save_whitelist(self, whitelist: WhitelistConfig) -> None:
        self.whitelist = whitelist
        self._write_yaml(self.whitelist_path, whitelist.model_dump())

    def load_custom_rules(self) -> CustomRulesConfig:
        raw = self._read_yaml(self.custom_rules_path)
        return CustomRulesConfig(**raw)

    def save_custom_rules(self, rules: CustomRulesConfig) -> None:
        self.custom_rules = rules
        self._write_yaml(self.custom_rules_path, rules.model_dump())

    def reload_all(self) -> None:
        self.app_config = self.load_app_config()
        self.whitelist = self.load_whitelist()
        self.custom_rules = self.load_custom_rules()

