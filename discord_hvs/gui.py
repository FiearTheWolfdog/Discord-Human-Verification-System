"""Tkinter GUI for configuring and controlling the Discord HVS bot."""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from typing import Any

from .audit import AuditStore, get_audit_path
from .bot_app import BotController
from .config import Config, get_config_path
from .startup import WindowsStartupManager


COPILOT_PALETTE = {
    "bg": "#0d1117",
    "fg": "#c9d1d9",
    "accent": "#58a6ff",
    "accent_fg": "#0d1117",
    "accent_hover": "#79c0ff",
    "entry_bg": "#161b22",
    "entry_border": "#30363d",
    "button_bg": "#238636",
    "button_hover": "#2ea043",
    "button_fg": "#ffffff",
    "danger_bg": "#d73a49",
    "log_bg": "#0d1117",
}

TITLE_FONT = ("Tahoma", 16, "bold")
SUBTITLE_FONT = ("Tahoma", 11)
LABEL_FONT = ("Tahoma", 10)
BUTTON_FONT = ("Tahoma", 10, "bold")


class DiscordHVSApp:
    """Main GUI application window."""

    def __init__(self, root: tk.Tk, workspace: Path) -> None:
        self.root = root
        self.root.title("Discord Human Verification System")
        self.root.geometry("820x820")
        self.root.resizable(False, False)
        self.root.configure(bg=COPILOT_PALETTE["bg"])
        self.root.option_add("*Font", "Tahoma 10")

        self.workspace = workspace
        self.config_path = get_config_path(workspace)
        self.config = Config.load(self.config_path)
        self.audit_store = AuditStore(get_audit_path(workspace))

        self.launcher_path, self.launcher_args = self._resolve_launch_command()
        self.startup_manager: WindowsStartupManager | None
        self._startup_manager_error: str | None = None
        try:
            self.startup_manager = WindowsStartupManager(
                working_dir=self.workspace,
                launcher=self.launcher_path,
                args=self.launcher_args,
            )
        except Exception as exc:
            self.startup_manager = None
            self._startup_manager_error = str(exc)

        self.token_var = tk.StringVar(value=self.config.bot_token)
        self.guild_var = tk.StringVar(value=str(self.config.guild_id or ""))
        self.channel_var = tk.StringVar(value=str(self.config.verification_channel_id or ""))
        self.command_name_var = tk.StringVar(value=self.config.command_name)
        self.roles_var = tk.StringVar(value=", ".join(str(r) for r in self.config.role_ids))
        self.remove_roles_var = tk.StringVar(value=", ".join(str(r) for r in self.config.remove_role_ids))
        self.moderation_enabled_var = tk.BooleanVar(value=self.config.moderation_enabled)
        self.moderation_whitelist_var = tk.StringVar(
            value=", ".join(str(r) for r in self.config.moderation_whitelist_role_ids)
        )
        self.auto_start_bot_var = tk.BooleanVar(value=self.config.auto_start_bot)
        self.windows_startup_var = tk.BooleanVar(value=self.config.windows_startup)
        self.status_var = tk.StringVar(value="Bot is stopped.")

        self._secret_controls: list[dict[str, Any]] = []
        self.log_widget: ScrolledText | None = None
        self.start_button: tk.Button | None = None
        self.stop_button: tk.Button | None = None
        self._audit_window: tk.Toplevel | None = None

        self._build_layout()
        self._reset_secret_fields()

        self.bot_controller = BotController(
            config_provider=self._get_current_config,
            log_callback=self._append_log_from_thread,
            state_callback=self._update_state_from_thread,
            audit_store=self.audit_store,
        )

        self._synchronize_windows_startup_on_load()
        self.root.after(250, self._auto_start_if_enabled)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_layout(self) -> None:
        padding = {"padx": 10, "pady": 5}

        header = tk.Label(
            self.root,
            text="Discord HVS",
            font=TITLE_FONT,
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
        )
        header.pack(pady=(15, 5))

        subtitle = tk.Label(
            self.root,
            text="Discord Human Verification System",
            font=SUBTITLE_FONT,
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
        )
        subtitle.pack(pady=(0, 15))

        form_frame = tk.Frame(self.root, bg=COPILOT_PALETTE["bg"])
        form_frame.pack(fill=tk.X, padx=20)
        form_frame.grid_columnconfigure(1, weight=1)

        tk.Label(
            form_frame,
            text="Bot Token:",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=0, column=0, sticky=tk.W, **padding)
        token_entry = tk.Entry(
            form_frame,
            textvariable=self.token_var,
            width=60,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        token_entry.grid(row=0, column=1, sticky=tk.W, **padding)
        self._add_secret_toggle(form_frame, token_entry, row=0)

        tk.Label(
            form_frame,
            text="Guild ID:",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=1, column=0, sticky=tk.W, **padding)
        guild_entry = tk.Entry(
            form_frame,
            textvariable=self.guild_var,
            width=25,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        guild_entry.grid(row=1, column=1, sticky=tk.W, **padding)
        self._add_secret_toggle(form_frame, guild_entry, row=1)

        tk.Label(
            form_frame,
            text="Verification Channel ID:",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=2, column=0, sticky=tk.W, **padding)
        channel_entry = tk.Entry(
            form_frame,
            textvariable=self.channel_var,
            width=25,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        channel_entry.grid(row=2, column=1, sticky=tk.W, **padding)
        self._add_secret_toggle(form_frame, channel_entry, row=2)

        tk.Label(
            form_frame,
            text="Slash Command Name:",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=3, column=0, sticky=tk.W, **padding)
        command_entry = tk.Entry(
            form_frame,
            textvariable=self.command_name_var,
            width=25,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        command_entry.grid(row=3, column=1, sticky=tk.W, **padding)

        tk.Label(
            form_frame,
            text="Role IDs to Assign (comma separated):",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=4, column=0, sticky=tk.W, **padding)
        roles_entry = tk.Entry(
            form_frame,
            textvariable=self.roles_var,
            width=40,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        roles_entry.grid(row=4, column=1, sticky=tk.W, **padding)

        tk.Label(
            form_frame,
            text="Roles to Remove (optional):",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
        ).grid(row=5, column=0, sticky=tk.W, **padding)
        remove_roles_entry = tk.Entry(
            form_frame,
            textvariable=self.remove_roles_var,
            width=40,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        remove_roles_entry.grid(row=5, column=1, sticky=tk.W, **padding)

        moderation_frame = tk.LabelFrame(
            self.root,
            text="Channel Moderation (optional)",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
            labelanchor="n",
        )
        moderation_frame.configure(highlightbackground=COPILOT_PALETTE["entry_border"], highlightcolor=COPILOT_PALETTE["accent"], bd=2)
        moderation_frame.pack(fill=tk.X, padx=20, pady=(10, 0))

        toggle = tk.Checkbutton(
            moderation_frame,
            text="Delete non-whitelisted messages in the verification channel",
            variable=self.moderation_enabled_var,
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            activebackground=COPILOT_PALETTE["bg"],
            activeforeground=COPILOT_PALETTE["accent"],
            selectcolor=COPILOT_PALETTE["entry_bg"],
            font=LABEL_FONT,
            anchor="w",
        )
        toggle.pack(fill=tk.X, padx=10, pady=(10, 5))

        whitelist_label = tk.Label(
            moderation_frame,
            text="Whitelist Role IDs (comma separated):",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
            anchor="w",
        )
        whitelist_label.pack(fill=tk.X, padx=10, pady=(0, 2))

        whitelist_entry = tk.Entry(
            moderation_frame,
            textvariable=self.moderation_whitelist_var,
            width=50,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            highlightbackground=COPILOT_PALETTE["entry_border"],
            highlightcolor=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
        )
        whitelist_entry.pack(fill=tk.X, padx=10, pady=(0, 10))

        automation_frame = tk.LabelFrame(
            self.root,
            text="Automation (optional)",
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            font=LABEL_FONT,
            labelanchor="n",
        )
        automation_frame.configure(highlightbackground=COPILOT_PALETTE["entry_border"], highlightcolor=COPILOT_PALETTE["accent"], bd=2)
        automation_frame.pack(fill=tk.X, padx=20, pady=(10, 0))

        auto_start_check = tk.Checkbutton(
            automation_frame,
            text="Start the bot automatically when this application opens",
            variable=self.auto_start_bot_var,
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            activebackground=COPILOT_PALETTE["bg"],
            activeforeground=COPILOT_PALETTE["accent"],
            selectcolor=COPILOT_PALETTE["entry_bg"],
            font=LABEL_FONT,
            anchor="w",
        )
        auto_start_check.pack(fill=tk.X, padx=10, pady=(10, 5))

        windows_startup_state = tk.NORMAL if self.startup_manager is not None else tk.DISABLED
        windows_startup_check = tk.Checkbutton(
            automation_frame,
            text="Launch Discord HVS automatically when Windows starts",
            variable=self.windows_startup_var,
            bg=COPILOT_PALETTE["bg"],
            fg=COPILOT_PALETTE["fg"],
            activebackground=COPILOT_PALETTE["bg"],
            activeforeground=COPILOT_PALETTE["accent"],
            selectcolor=COPILOT_PALETTE["entry_bg"],
            font=LABEL_FONT,
            anchor="w",
            state=windows_startup_state,
        )
        windows_startup_check.pack(fill=tk.X, padx=10, pady=(0, 5))

        if self.startup_manager is None:
            info = tk.Label(
                automation_frame,
                text=(
                    "Windows startup registration is unavailable on this system."
                    if self._startup_manager_error is None
                    else f"Startup registration unavailable: {self._startup_manager_error}"
                ),
                bg=COPILOT_PALETTE["bg"],
                fg="#f87171",
                font=("Tahoma", 9),
                wraplength=640,
                justify=tk.LEFT,
            )
            info.pack(fill=tk.X, padx=10, pady=(0, 10))

        button_frame = tk.Frame(self.root, bg=COPILOT_PALETTE["bg"])
        button_frame.pack(fill=tk.X, padx=20, pady=(10, 0))

        save_button = tk.Button(
            button_frame,
            text="Save Settings",
            command=self._on_save_clicked,
            bg=COPILOT_PALETTE["button_bg"],
            fg=COPILOT_PALETTE["button_fg"],
            activebackground=COPILOT_PALETTE["button_hover"],
            activeforeground=COPILOT_PALETTE["button_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
        )
        save_button.pack(side=tk.LEFT, padx=5)

        self.start_button = tk.Button(
            button_frame,
            text="Start Bot",
            command=self._on_start_clicked,
            bg=COPILOT_PALETTE["accent"],
            fg=COPILOT_PALETTE["accent_fg"],
            activebackground=COPILOT_PALETTE["accent_hover"],
            activeforeground=COPILOT_PALETTE["button_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
        )
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(
            button_frame,
            text="Stop Bot",
            command=self._on_stop_clicked,
            state=tk.DISABLED,
            bg=COPILOT_PALETTE["danger_bg"],
            fg=COPILOT_PALETTE["button_fg"],
            activebackground="#f78166",
            activeforeground=COPILOT_PALETTE["button_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)

        audit_button = tk.Button(
            button_frame,
            text="Audit",
            command=self._on_audit_clicked,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            activebackground=COPILOT_PALETTE["accent"],
            activeforeground=COPILOT_PALETTE["accent_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
        )
        audit_button.pack(side=tk.RIGHT, padx=5)

        status_label = tk.Label(
            self.root,
            textvariable=self.status_var,
            fg=COPILOT_PALETTE["accent"],
            bg=COPILOT_PALETTE["bg"],
            font=LABEL_FONT,
        )
        status_label.pack(fill=tk.X, padx=25, pady=(10, 5))

        self.log_widget = ScrolledText(
            self.root,
            height=14,
            state=tk.DISABLED,
            bg=COPILOT_PALETTE["log_bg"],
            fg=COPILOT_PALETTE["fg"],
            insertbackground=COPILOT_PALETTE["accent"],
            relief=tk.FLAT,
            borderwidth=1,
        )
        self.log_widget.configure(highlightbackground=COPILOT_PALETTE["entry_border"], highlightcolor=COPILOT_PALETTE["accent"])
        self.log_widget.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

    def _append_log(self, message: str) -> None:
        if self.log_widget is None:
            return
        self.log_widget.configure(state=tk.NORMAL)
        self.log_widget.insert(tk.END, message + "\n")
        self.log_widget.see(tk.END)
        self.log_widget.configure(state=tk.DISABLED)

    def _append_log_from_thread(self, message: str) -> None:
        self.root.after(0, lambda: self._append_log(message))

    def _update_state_from_thread(self, running: bool) -> None:
        self.root.after(0, lambda: self._set_running_state(running))

    def _set_running_state(self, running: bool) -> None:
        if self.start_button is None or self.stop_button is None:
            return
        if running:
            self.status_var.set("Bot is running. Use Stop to shut it down safely.")
            self.start_button.configure(state=tk.DISABLED)
            self.stop_button.configure(state=tk.NORMAL)
        else:
            self.status_var.set("Bot is stopped.")
            self.start_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)

    def _parse_role_ids(self, raw: str) -> list[int]:
        ids: list[int] = []
        for chunk in raw.split(","):
            value = chunk.strip()
            if not value:
                continue
            try:
                ids.append(int(value))
            except ValueError:
                raise ValueError(f"Role ID '{value}' is not a valid integer") from None
        return ids

    def _collect_form_config(self) -> Config:
        role_text = self.roles_var.get()
        role_ids = self._parse_role_ids(role_text)
        remove_role_text = self.remove_roles_var.get()
        remove_role_ids = self._parse_role_ids(remove_role_text)
        whitelist_text = self.moderation_whitelist_var.get()
        whitelist_role_ids = self._parse_role_ids(whitelist_text)
        command_name = self.command_name_var.get().strip().lower()

        config = Config(
            bot_token=self.token_var.get().strip(),
            guild_id=int(self.guild_var.get().strip() or 0),
            verification_channel_id=int(self.channel_var.get().strip() or 0),
            role_ids=role_ids,
            remove_role_ids=remove_role_ids,
            command_name=command_name,
            auto_start_bot=self.auto_start_bot_var.get(),
            windows_startup=self.windows_startup_var.get() if self.startup_manager is not None else False,
            moderation_enabled=self.moderation_enabled_var.get(),
            moderation_whitelist_role_ids=whitelist_role_ids,
        )
        return config

    def _display_validation_errors(self, issues: dict[str, str]) -> None:
        lines = [f"- {field}: {error}" for field, error in issues.items()]
        messagebox.showerror("Validation Error", "\n".join(lines))

    def _on_save_clicked(self) -> None:
        try:
            config = self._collect_form_config()
        except ValueError as exc:
            messagebox.showerror("Invalid Input", str(exc))
            return

        issues = config.validate()
        if issues:
            self._display_validation_errors(issues)
            return

        self.config = config
        try:
            config.save(self.config_path)
        except OSError as exc:
            messagebox.showerror("Save Failed", f"Unable to write config file: {exc}")
            return

        self._ensure_windows_startup(self.config.windows_startup)
        self._reset_secret_fields()
        messagebox.showinfo("Settings Saved", "Configuration updated successfully.")

    def _on_start_clicked(self) -> None:
        if self.bot_controller.is_running():
            messagebox.showinfo("Already Running", "The bot is already active.")
            return

        try:
            config = self._collect_form_config()
        except ValueError as exc:
            messagebox.showerror("Invalid Input", str(exc))
            return

        issues = config.validate()
        if issues:
            self._display_validation_errors(issues)
            return

        self.config = config
        try:
            config.save(self.config_path)
        except OSError as exc:
            messagebox.showerror("Save Failed", f"Unable to write config file: {exc}")
            return

        self._ensure_windows_startup(self.config.windows_startup)
        self._reset_secret_fields()
        try:
            self.bot_controller.start()
        except RuntimeError as exc:
            messagebox.showerror("Bot Error", str(exc))

    def _on_stop_clicked(self) -> None:
        self.bot_controller.stop()

    def _on_close(self) -> None:
        if self.bot_controller.is_running():
            if not messagebox.askyesno("Quit", "The bot is still running. Stop and exit?"):
                return
            self.bot_controller.stop()
        if self._audit_window is not None and self._audit_window.winfo_exists():
            self._audit_window.destroy()
            self._audit_window = None
        self.root.destroy()

    def _get_current_config(self) -> Config:
        return self.config

    def _on_audit_clicked(self) -> None:
        if self._audit_window is not None and self._audit_window.winfo_exists():
            self._audit_window.lift()
            self._audit_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        window.title("Verification Audit Log")
        window.geometry("720x420")
        window.configure(bg=COPILOT_PALETTE["bg"])
        window.transient(self.root)
        window.grab_set()
        self._audit_window = window

        listbox = tk.Listbox(
            window,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            selectbackground=COPILOT_PALETTE["accent"],
            selectforeground=COPILOT_PALETTE["accent_fg"],
            highlightthickness=0,
            font=("Tahoma", 9),
            activestyle="none",
        )
        scrollbar = tk.Scrollbar(window, orient=tk.VERTICAL, command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)

        window.grid_rowconfigure(0, weight=1)
        window.grid_columnconfigure(0, weight=1)

        listbox.grid(row=0, column=0, sticky="nsew", padx=(15, 0), pady=15)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 15), pady=15)

        button_frame = tk.Frame(window, bg=COPILOT_PALETTE["bg"])
        button_frame.grid(row=1, column=0, columnspan=2, pady=(0, 15))

        def populate() -> None:
            listbox.delete(0, tk.END)
            entries = self.audit_store.read_entries()
            if not entries:
                listbox.insert(tk.END, "No verification attempts recorded yet.")
                return
            for entry in reversed(entries):
                detail = f" – {entry.detail}" if entry.detail else ""
                line = f"{entry.timestamp} | {entry.user_name} ({entry.user_id}) -> {entry.status}{detail}"
                listbox.insert(tk.END, line)

        refresh_button = tk.Button(
            button_frame,
            text="Refresh",
            command=populate,
            bg=COPILOT_PALETTE["button_bg"],
            fg=COPILOT_PALETTE["button_fg"],
            activebackground=COPILOT_PALETTE["button_hover"],
            activeforeground=COPILOT_PALETTE["button_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
            width=10,
        )
        refresh_button.pack(side=tk.LEFT, padx=10)

        def close_window() -> None:
            win = self._audit_window
            self._audit_window = None
            if win is not None and win.winfo_exists():
                win.destroy()

        close_button = tk.Button(
            button_frame,
            text="Close",
            command=close_window,
            bg=COPILOT_PALETTE["danger_bg"],
            fg=COPILOT_PALETTE["button_fg"],
            activebackground="#f78166",
            activeforeground=COPILOT_PALETTE["button_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=BUTTON_FONT,
            width=10,
        )
        close_button.pack(side=tk.LEFT, padx=10)

        window.protocol("WM_DELETE_WINDOW", close_window)
        populate()

    def _ensure_windows_startup(self, desired: bool, *, show_error: bool = True) -> None:
        if self.startup_manager is None:
            self.windows_startup_var.set(False)
            self.config.windows_startup = False
            return

        try:
            if desired:
                self.startup_manager.register()
            else:
                self.startup_manager.unregister()
        except Exception as exc:
            if show_error:
                messagebox.showerror("Startup Registration Failed", str(exc))
            current = self.startup_manager.is_registered()
            self.windows_startup_var.set(current)
            self.config.windows_startup = current
            self._append_log(f"Windows startup registration update failed: {exc}")
        else:
            current = self.startup_manager.is_registered()
            self.windows_startup_var.set(current)
            self.config.windows_startup = current

    def _synchronize_windows_startup_on_load(self) -> None:
        if self.startup_manager is None:
            self.windows_startup_var.set(False)
            self.config.windows_startup = False
            return
        # Ensure registration matches saved preference without surfacing dialogs.
        self._ensure_windows_startup(self.config.windows_startup, show_error=False)
        current = self.startup_manager.is_registered()
        self.windows_startup_var.set(current)
        self.config.windows_startup = current

    def _auto_start_if_enabled(self) -> None:
        if not self.config.auto_start_bot:
            return
        if self.bot_controller.is_running():
            return
        issues = self.config.validate()
        if issues:
            issue_keys = ", ".join(issues.keys())
            self._append_log(
                f"Auto-start skipped because configuration is incomplete ({issue_keys})."
            )
            return
        try:
            self.bot_controller.start()
            self._append_log("Auto-starting bot per saved settings.")
        except RuntimeError as exc:
            self._append_log(f"Auto-start aborted: {exc}")
        except Exception as exc:  # pragma: no cover - defensive logging
            self._append_log(f"Unexpected error during auto-start: {exc}")

    def _add_secret_toggle(self, parent: tk.Widget, entry: tk.Entry, *, row: int) -> None:
        control: dict[str, Any] = {"visible": False, "entry": entry}
        entry.configure(show="•")

        def toggle_visibility() -> None:
            control["visible"] = not control["visible"]
            entry.configure(show="" if control["visible"] else "•")
            button.configure(text="Hide" if control["visible"] else "Show")

        button = tk.Button(
            parent,
            text="Show",
            command=toggle_visibility,
            bg=COPILOT_PALETTE["entry_bg"],
            fg=COPILOT_PALETTE["fg"],
            activebackground=COPILOT_PALETTE["accent"],
            activeforeground=COPILOT_PALETTE["accent_fg"],
            relief=tk.FLAT,
            bd=0,
            highlightbackground=COPILOT_PALETTE["bg"],
            font=LABEL_FONT,
            width=6,
        )
        button.grid(row=row, column=2, sticky=tk.W, padx=(0, 10), pady=5)

        control["button"] = button
        self._secret_controls.append(control)

    def _reset_secret_fields(self) -> None:
        for control in self._secret_controls:
            entry: tk.Entry = control["entry"]
            button: tk.Button = control["button"]
            control["visible"] = False
            entry.configure(show="•")
            button.configure(text="Show")

    def _resolve_launch_command(self) -> tuple[Path, list[str]]:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve(), []
        python_exe = Path(sys.executable).resolve()
        main_script = (self.workspace / "main.py").resolve()
        return python_exe, [str(main_script)]


def launch_gui(workspace: Path) -> None:
    root = tk.Tk()
    app = DiscordHVSApp(root, workspace)
    root.mainloop()


__all__ = ["launch_gui", "DiscordHVSApp"]
