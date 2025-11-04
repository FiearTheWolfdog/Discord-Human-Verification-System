"""Audit logging utilities for Discord Human Verification System."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List


AUDIT_FILE_NAME = "audit_log.jsonl"


@dataclass(slots=True)
class AuditEntry:
    """Represents a single verification attempt outcome."""

    timestamp: str
    user_id: int
    user_name: str
    status: str
    detail: str = ""

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditEntry":
        return cls(
            timestamp=str(payload.get("timestamp", "")),
            user_id=int(payload.get("user_id", 0) or 0),
            user_name=str(payload.get("user_name", "")),
            status=str(payload.get("status", "")),
            detail=str(payload.get("detail", "")),
        )


class AuditStore:
    """Thread-safe persistence layer for audit entries."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, entry: AuditEntry) -> None:
        payload = json.dumps(asdict(entry), ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(payload + "\n")

    def record(self, *, user_id: int, user_name: str, status: str, detail: str = "") -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            user_id=user_id,
            user_name=user_name,
            status=status,
            detail=detail,
        )
        self.append(entry)

    def read_entries(self) -> List[AuditEntry]:
        with self._lock:
            entries: List[AuditEntry] = []
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    entries.append(AuditEntry.from_dict(payload))
        return entries


def get_audit_path(base_path: Path | None = None) -> Path:
    """Return the path where audit logs are stored."""
    base = base_path or Path.cwd()
    return base / AUDIT_FILE_NAME


__all__ = ["AuditEntry", "AuditStore", "get_audit_path"]
