"""Helpers for managing Windows startup registration for Discord HVS."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


AUTOSTART_SCRIPT_NAME = "DiscordHVS_AutoStart.bat"


def get_startup_directory() -> Path:
    """Return the user's Windows Startup folder path."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA environment variable is not set")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


class WindowsStartupManager:
    """Creates or removes a batch file to launch the app when Windows boots."""

    def __init__(self, *, working_dir: Path, launcher: Path, args: Iterable[str] = ()) -> None:
        self.working_dir = working_dir
        self.launcher = launcher
        self.args = list(args)
        self.startup_dir = get_startup_directory()
        self.script_path = self.startup_dir / AUTOSTART_SCRIPT_NAME

    def is_registered(self) -> bool:
        return self.script_path.exists()

    def register(self) -> None:
        self.startup_dir.mkdir(parents=True, exist_ok=True)
        quoted_args = " ".join(f'"{arg}"' for arg in self.args)
        bat_lines = [
            "@echo off",
            f'cd /d "{self.working_dir}"',
            f'start "" "{self.launcher}" {quoted_args}'.rstrip(),
        ]
        with self.script_path.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(bat_lines) + "\n")

    def unregister(self) -> None:
        if self.script_path.exists():
            self.script_path.unlink()


__all__ = ["WindowsStartupManager", "get_startup_directory", "AUTOSTART_SCRIPT_NAME"]
