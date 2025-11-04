"""Discord bot runtime for the Human Verification System."""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Callable, Iterable, List, Optional

import discord
from discord import app_commands
from discord.ext import commands

from .audit import AuditStore
from .captcha import generate_code
from .config import Config


class GuiLogHandler(logging.Handler):
    """Logging handler that delegates records to a GUI callback."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        super().__init__()
        self._callback = callback

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - GUI side-effect
        message = self.format(record)
        try:
            self._callback(message)
        except Exception:  # pragma: no cover - defensive; GUI should remain stable
            self.handleError(record)


class CaptchaModal(discord.ui.Modal):
    """Modal dialog that collects captcha input from a Discord user."""

    def __init__(
        self,
        *,
        code: str,
        bot: commands.Bot,
        member: discord.Member,
        target_roles: Iterable[discord.Role],
        roles_to_remove: Iterable[discord.Role],
        command_name: str,
        logger: logging.Logger,
        audit_store: AuditStore,
    ) -> None:
        title = f"Enter the code: {code}"
        super().__init__(title=title[:45])  # Discord clamps modal titles to 45 chars
        self.expected = code.upper()
        self.bot = bot
        self.member = member
        self.target_roles = list(target_roles)
        self.roles_to_remove = list(roles_to_remove)
        self.command_display = f"/{command_name}"
        self.logger = logger
        self.audit_store = audit_store

        self.answer_box = discord.ui.TextInput(
            label="Re-type the code above",
            placeholder="Type the verification code",
            min_length=4,
            max_length=12,
            required=True,
        )
        self.add_item(self.answer_box)

    async def on_submit(self, interaction: discord.Interaction) -> None:  # pragma: no cover - Discord callback
        response = self.answer_box.value.strip().upper()
        if response != self.expected:
            await interaction.response.send_message(
                f"❌ Verification failed. Please run `{self.command_display}` again and try a new challenge.",
                ephemeral=True,
            )
            self.logger.info("User %s failed captcha attempt", interaction.user)
            self._record_audit("denied", "Captcha mismatch")
            return

        roles_to_add = [role for role in self.target_roles if role not in self.member.roles]
        roles_to_remove_now = [role for role in self.roles_to_remove if role in self.member.roles]

        if not roles_to_add and not roles_to_remove_now:
            await interaction.response.send_message(
                "✅ You are already verified and have the required role(s).",
                ephemeral=True,
            )
            self._record_audit("already_verified", "Roles already assigned and no removals pending")
            return

        added_roles: List[discord.Role] = []
        if roles_to_add:
            try:
                await self.member.add_roles(
                    *roles_to_add,
                    reason="Discord HVS captcha verification",
                )
                added_roles = roles_to_add
            except discord.Forbidden:
                await interaction.response.send_message(
                    "⚠️ Verification failed because I lack permission to assign the configured role(s).",
                    ephemeral=True,
                )
                self.logger.error(
                    "Missing permissions to assign roles %s to %s", roles_to_add, self.member
                )
                role_names = ", ".join(role.name for role in roles_to_add)
                self._record_audit("denied", f"Missing permissions for roles: {role_names}")
                return

        removed_roles: List[discord.Role] = []
        if roles_to_remove_now:
            try:
                await self.member.remove_roles(
                    *roles_to_remove_now,
                    reason="Discord HVS captcha verification",
                )
                removed_roles = roles_to_remove_now
            except discord.Forbidden:
                await interaction.response.send_message(
                    "⚠️ Verification succeeded, but I lack permission to remove the configured role(s).",
                    ephemeral=True,
                )
                self.logger.error(
                    "Missing permissions to remove roles %s from %s",
                    roles_to_remove_now,
                    self.member,
                )
                removed_names = ", ".join(role.name for role in roles_to_remove_now)
                added_names = ", ".join(role.name for role in added_roles)
                detail = ""
                if added_names:
                    detail += f"Assigned roles: {added_names}. "
                detail += f"Failed to remove roles: {removed_names}"
                self._record_audit("partial", detail)
                return

        added_names = ", ".join(role.name for role in added_roles)
        removed_names = ", ".join(role.name for role in removed_roles)

        message_parts = ["✅ Successfully verified."]
        if added_names:
            message_parts.append(f"Assigned: {added_names}.")
        if removed_names:
            message_parts.append(f"Removed: {removed_names}.")
        final_message = " ".join(message_parts)

        await interaction.response.send_message(final_message, ephemeral=True)
        self.logger.info(
            "User %s verified (added roles: %s, removed roles: %s)",
            self.member,
            added_roles,
            removed_roles,
        )
        detail_fragments = []
        if added_names:
            detail_fragments.append(f"Assigned roles: {added_names}")
        if removed_names:
            detail_fragments.append(f"Removed roles: {removed_names}")
        detail = "; ".join(detail_fragments) if detail_fragments else "Verified"
        self._record_audit("granted", detail)

    async def on_error(  # pragma: no cover - Discord callback
        self,
        interaction: discord.Interaction,
        error: Exception,
    ) -> None:
        await interaction.response.send_message(
            "⚠️ Something went wrong while verifying you. Please try again.",
            ephemeral=True,
        )
        self.logger.exception("Captcha modal error", exc_info=error)
        self._record_audit("error", f"Modal error: {error}")

    def _record_audit(self, status: str, detail: str = "") -> None:
        try:
            self.audit_store.record(
                user_id=self.member.id,
                user_name=str(self.member),
                status=status,
                detail=detail,
            )
        except Exception:  # pragma: no cover - defensive logging
            self.logger.exception("Failed to record audit entry for %s", self.member)


def create_bot(config: Config, logger: logging.Logger, audit_store: AuditStore) -> commands.Bot:
    """Build and configure the Discord bot instance."""
    intents = discord.Intents.default()
    intents.members = True  # Needed to read and assign member roles
    intents.message_content = True  # Required for moderation monitoring

    bot = commands.Bot(command_prefix=commands.when_mentioned_or("!"), intents=intents)
    bot.hvs_config = config  # type: ignore[attr-defined]
    bot.hvs_logger = logger  # type: ignore[attr-defined]

    guild_object = discord.Object(id=config.guild_id)

    @bot.event
    async def on_ready() -> None:  # pragma: no cover - Discord callback
        logger.info("Bot connected as %s", bot.user)

    @bot.event
    async def on_message(message: discord.Message) -> None:  # pragma: no cover - Discord callback
        cfg: Config = bot.hvs_config  # type: ignore[attr-defined]
        log: logging.Logger = bot.hvs_logger  # type: ignore[attr-defined]

        if message.guild is None:
            await bot.process_commands(message)
            return

        if not cfg.moderation_enabled:
            await bot.process_commands(message)
            return

        if message.channel.id != cfg.verification_channel_id:
            await bot.process_commands(message)
            return

        if message.author.bot:
            await bot.process_commands(message)
            return

        author_roles = getattr(message.author, "roles", [])
        is_whitelisted = any(role.id in cfg.moderation_whitelist_role_ids for role in author_roles)

        if is_whitelisted:
            await bot.process_commands(message)
            return

        try:
            await message.delete()
            log.info("Deleted message from %s in verification channel", message.author)
        except discord.Forbidden:
            log.error("Missing permission to delete messages in channel %s", message.channel.id)
        except discord.HTTPException as exc:
            log.warning("Failed to delete message in channel %s: %s", message.channel.id, exc)

        await bot.process_commands(message)

    async def verify_callback(interaction: discord.Interaction) -> None:  # pragma: no cover - Discord callback
        cfg: Config = bot.hvs_config  # type: ignore[attr-defined]
        log: logging.Logger = bot.hvs_logger  # type: ignore[attr-defined]
        slash_display = f"/{cfg.command_name}"

        def record(status: str, detail: str = "") -> None:
            try:
                audit_store.record(
                    user_id=getattr(interaction.user, "id", 0),
                    user_name=str(interaction.user),
                    status=status,
                    detail=detail,
                )
            except Exception:
                log.exception("Failed to record audit event for %s", interaction.user)

        if interaction.channel_id != cfg.verification_channel_id:
            await interaction.response.send_message(
                f"ℹ️ Please use the designated verification channel for `{slash_display}`.",
                ephemeral=True,
            )
            record("denied", "Command used in incorrect channel")
            return

        guild = interaction.guild
        member = interaction.user
        if guild is None or not isinstance(member, discord.Member):
            await interaction.response.send_message(
                "⚠️ Verification is only available inside the target server.",
                ephemeral=True,
            )
            record("error", "Interaction missing guild/member context")
            return

        role_objects: List[discord.Role] = []
        remove_role_objects: List[discord.Role] = []
        for role_id in cfg.role_ids:
            role = guild.get_role(role_id)
            if role is not None:
                role_objects.append(role)
            else:
                log.warning("Configured role %s was not found in guild %s", role_id, guild.id)
        for role_id in cfg.remove_role_ids:
            role = guild.get_role(role_id)
            if role is not None:
                remove_role_objects.append(role)
            else:
                log.warning("Configured removal role %s was not found in guild %s", role_id, guild.id)

        if not role_objects and not remove_role_objects:
            await interaction.response.send_message(
                "⚠️ No valid roles are configured for verification. Contact an administrator.",
                ephemeral=True,
            )
            record("denied", "No valid roles configured")
            return

        roles_missing = [role for role in role_objects if role not in member.roles]
        roles_to_remove_now = [role for role in remove_role_objects if role in member.roles]

        if not roles_missing and not roles_to_remove_now:
            await interaction.response.send_message(
                "✅ You are already verified!",
                ephemeral=True,
            )
            record("already_verified", "Roles already present and no removals needed")
            return

        code = generate_code()
        modal = CaptchaModal(
            code=code,
            bot=bot,
            member=member,
            target_roles=role_objects,
            roles_to_remove=remove_role_objects,
            command_name=cfg.command_name,
            logger=log,
            audit_store=audit_store,
        )
        await interaction.response.send_modal(modal)
        log.info("Captcha issued to user %s", member)
        record("challenge", "Captcha challenge issued")

    verify_command = app_commands.Command(
        name=config.command_name,
        description="Verify and gain access to the server",
        callback=verify_callback,
    )
    bot.tree.add_command(verify_command, guild=guild_object)

    async def setup_hook() -> None:
        await bot.tree.sync(guild=guild_object)
        logger.info("Slash commands synced to guild %s", config.guild_id)

    bot.setup_hook = setup_hook  # type: ignore[method-assign]
    return bot


class BotController:
    """Lifecycle manager that runs the Discord bot inside a background thread."""

    def __init__(
        self,
        *,
        config_provider: Callable[[], Config],
        log_callback: Callable[[str], None],
        state_callback: Callable[[bool], None],
        audit_store: AuditStore,
    ) -> None:
        self._config_provider = config_provider
        self._log_callback = log_callback
        self._state_callback = state_callback
        self._audit_store = audit_store
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._bot: Optional[commands.Bot] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Bot is already running")

        self._thread = threading.Thread(target=self._run, name="DiscordHVSBot", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._bot or not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._shutdown_bot(), self._loop).result(timeout=10)
        if self._thread:
            self._thread.join(timeout=10)
        self._thread = None
        self._bot = None
        self._loop = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        config = self._config_provider()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        gui_handler = GuiLogHandler(self._log_callback)
        gui_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
        logger = logging.getLogger("discord_hvs.bot")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.addHandler(gui_handler)

        discord_logger = logging.getLogger("discord")
        discord_logger.setLevel(logging.WARNING)
        discord_logger.handlers.clear()
        discord_logger.addHandler(gui_handler)

        bot = create_bot(config, logger, self._audit_store)
        self._bot = bot
        self._state_callback(True)

        try:
            loop.run_until_complete(bot.start(config.bot_token))
        except Exception as exc:  # pragma: no cover - runtime safeguard
            logger.exception("Bot crashed", exc_info=exc)
        finally:
            if not bot.is_closed():
                loop.run_until_complete(bot.close())
            logger.info("Bot stopped")
            self._state_callback(False)
            loop.stop()
            loop.close()

    async def _shutdown_bot(self) -> None:
        if self._bot is None:
            return
        await self._bot.close()
