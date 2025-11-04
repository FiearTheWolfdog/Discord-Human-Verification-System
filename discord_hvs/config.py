"""Configuration utilities for Discord Human Verification System."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List
import json
import re


CONFIG_FILE_NAME = "config.json"


@dataclass(slots=True)
class Config:
    """Represents persisted admin preferences for the verification bot."""

    bot_token: str = ""
    guild_id: int = 0
    verification_channel_id: int = 0
    role_ids: List[int] = field(default_factory=list)
    remove_role_ids: List[int] = field(default_factory=list)
    command_name: str = "verify"
    auto_start_bot: bool = False
    windows_startup: bool = False
    moderation_enabled: bool = False
    moderation_whitelist_role_ids: List[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Construct configuration from a raw dictionary with basic validation."""
        return cls(
            bot_token=str(data.get("bot_token", "")),
            guild_id=int(data.get("guild_id", 0) or 0),
            verification_channel_id=int(data.get("verification_channel_id", 0) or 0),
            role_ids=[int(role_id) for role_id in data.get("role_ids", []) if role_id],
            remove_role_ids=[int(role_id) for role_id in data.get("remove_role_ids", []) if role_id],
            command_name=str(data.get("command_name", "verify") or "verify").strip().lower(),
            auto_start_bot=bool(data.get("auto_start_bot", False)),
            windows_startup=bool(data.get("windows_startup", False)),
            moderation_enabled=bool(data.get("moderation_enabled", False)),
            moderation_whitelist_role_ids=[
                int(role_id) for role_id in data.get("moderation_whitelist_role_ids", []) if role_id
            ],
        )

    @classmethod
    def load(cls, path: Path) -> "Config":
        """Load configuration from disk or return defaults when missing."""
        if not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return cls.from_dict(payload)

    def save(self, path: Path) -> None:
        """Persist configuration to disk in JSON format."""
        payload = asdict(self)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def validate(self) -> Dict[str, str]:
        """Return mapping of field name to error text when input is incomplete."""
        issues: Dict[str, str] = {}
        if not self.bot_token:
            issues["bot_token"] = "Bot token is required."
        if self.guild_id <= 0:
            issues["guild_id"] = "Guild ID must be a positive integer."
        if self.verification_channel_id <= 0:
            issues["verification_channel_id"] = "Channel ID must be a positive integer."
        if not self.role_ids and not self.remove_role_ids:
            issues["role_ids"] = "Configure at least one role to assign or remove."

        if not COMMAND_NAME_PATTERN.fullmatch(self.command_name):
            issues["command_name"] = (
                "Command name must be 1-32 characters using lowercase letters, numbers, hyphen, or underscore."
            )
        return issues


COMMAND_NAME_PATTERN = re.compile(r"^[a-z0-9\-_]{1,32}$")


def get_config_path(base_path: Path | None = None) -> Path:
    """Resolve the configuration file path relative to the workspace root."""
    base = base_path or Path.cwd()
    return base / CONFIG_FILE_NAME
