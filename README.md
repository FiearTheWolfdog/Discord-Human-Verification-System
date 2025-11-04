# Discord Human Verification System

The Discord Human Verification System (HVS) lets server administrators configure a verification flow that assigns roles only to verified members. Administrators manage settings through a desktop GUI, while members verify themselves via a `/verify` slash command inside Discord.

## Features

- GUI to configure bot token, guild ID, verification channel, and role IDs
- Optional role removal list to drop onboarding roles during verification
- Optional verification-channel moderation: auto-delete messages from non-whitelisted roles
- Slash command name configurable (defaults to `/verify`)
- Automation helpers: auto-start the bot when the GUI launches and optional Windows startup registration
- Config persists to `config.json`
- `/verify` command issues a short captcha challenge using Discord modals
- Automatically assigns configured roles to members that answer correctly
- Logging pane inside the GUI for runtime insight
- Audit viewer window listing each verification attempt and outcome

## Getting Started

### Creating and Adding Your Discord Bot

1. Visit the [Discord Developer Portal](https://discord.com/developers/applications) and sign in.
2. Click **New Application**, give it a name (e.g., `Discord HVS`), and create the application.
3. In the sidebar, open **Bot**, then click **Add Bot**. Confirm when prompted.
4. Under the bot settings:
   - Toggle **Privileged Gateway Intents** for *Server Members Intent* and (if using moderation) *Message Content Intent*.
   - Copy the **Bot Token**—you will paste this into the GUI later.
5. Still in the developer portal, open **OAuth2 → URL Generator**:
   - Select the **bot** and **applications.commands** scopes.
   - In **Bot Permissions**, choose at least: `Read Messages/View Channels`, `Send Messages`, `Manage Roles`, and (if moderation is enabled) `Manage Messages`.
   - Copy the generated URL and open it in your browser, then pick the server where you want the bot to live.
6. Back in Discord, confirm the bot appears in the server member list.
7. Gather the required IDs:
   - Right-click the server icon → **Copy Server ID** (requires Developer Mode in Discord settings).
   - Right-click the verification channel → **Copy Channel ID**.
   - Right-click each role that should be assigned/removed → **Copy Role ID**.
8. Paste these values into the Discord HVS GUI, save, and start the bot.

### Running the Executable Safely

- Before launching the EXE, create a dedicated folder (for example `DiscordHVS_Runtime`) and move `DiscordHVS.exe` into it.
- The application writes `config.json` and `audit_log.jsonl` next to the executable; keeping it in its own folder prevents clutter.
- Double-click the EXE (or run it from PowerShell) inside that dedicated folder to start the GUI.
- If you enable the moderation feature, ensure the bot has `Manage Messages` permission and the privileged *Message Content Intent* is toggled on in the Discord developer portal for your bot.
- When enabling the Windows startup option, the app creates/removes `DiscordHVS_AutoStart.bat` inside your Startup folder to control launch at sign-in.

### Slash Command Registration

On first start the bot will auto-sync the `/verify` command with the specified guild. Ensure the bot has the `applications.commands` scope and appropriate permissions to manage roles.

## Building a One-File Executable

The project ships with a helper script that produces a standalone Windows executable using PyInstaller.

1. (Optional) Create and activate a virtual environment, then install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. From the project root, run the build script:
   ```powershell
   pwsh scripts/build_exe.ps1
   ```
   Add `-Clean` to the command if you want to remove `dist/`, `build/`, and the PyInstaller spec file before rebuilding.
3. The single-file executable `DiscordHVS.exe` will be created in the `dist` directory.

### Install without EXE
1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. Run the GUI:
   ```powershell
   python main.py
   ```
3. Fill in your bot token, guild ID, verification channel ID, desired role IDs, and optionally the roles to remove after verification.
4. Set the **Slash Command Name** field if you want to use something other than `/verify`.
5. (Optional) Enable automation:
   - **Start Bot Automatically** will boot the bot each time the GUI opens (after validation passes).
   - **Launch at Windows Startup** writes a shortcut in your Startup folder, so the GUI launches whenever you sign in.
6. (Optional) Enable the moderation toggle to auto-delete chatter in the verification channel and list the role IDs allowed to post there.
7. Click **Save Settings**, then **Start Bot**.
8. In Discord, run your configured slash command (default `/verify`) inside the designated channel to trigger the captcha flow.
9. Click **Audit** in the GUI to review verification outcomes any time.

## Notes

- Captcha challenges are simple alphanumeric codes surfaced via a Discord modal. Members can re-run `/verify` to get a new code if they misspell it.
- The bot needs permission to read members and manage roles, plus access to the verification channel.
- Logs inside the GUI help diagnose issues (e.g., missing roles or permission errors).
