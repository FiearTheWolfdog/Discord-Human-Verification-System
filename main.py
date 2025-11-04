"""Entry point for running the Discord Human Verification System GUI."""
from __future__ import annotations

from pathlib import Path
import sys

from discord_hvs.gui import launch_gui


if __name__ == "__main__":
    if getattr(sys, "frozen", False):  # Running from PyInstaller bundle
        workspace_dir = Path(sys.executable).resolve().parent
    else:
        workspace_dir = Path(__file__).resolve().parent
    launch_gui(workspace_dir)
