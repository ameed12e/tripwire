# Tripwire on Windows (PowerShell, from zero)

This guide takes a clean Windows 10/11 machine to a working decoy that sends a
Telegram alert. Every command runs in **PowerShell as your normal user**. Only
the optional auditing section at the end needs Administrator.

> Deploy Tripwire only on a computer you own or are authorized in writing to
> monitor.

## 1. Install Python and Git

Open **PowerShell** (Start menu, type `PowerShell`, press Enter) and run:

```powershell
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
```

Accept the prompts. Then **close PowerShell and open a new window** so the new
`PATH` is picked up. Check both tools:

```powershell
py --version     # Python 3.12.x
git --version    # git version 2.x
```

No `winget`? Install "App Installer" from the Microsoft Store, or download
the installers from <https://www.python.org/downloads/windows/> (tick
**"Add python.exe to PATH"**) and <https://git-scm.com/download/win>.

## 2. Get the code

```powershell
cd $HOME
git clone https://github.com/ameed12e/tripwire.git
cd tripwire
```

The project now lives in `C:\Users\<you>\tripwire`.

## 3. Create and activate a virtual environment

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Your prompt now starts with `(.venv)`.

**If activation fails** with *"running scripts is disabled on this system"*,
allow locally created scripts for your user (no Administrator needed), then
activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

To avoid changing the policy permanently, use
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` instead. That only
applies to the current window, so you have to repeat it in every new window.

## 4. Install Tripwire

```powershell
python -m pip install --upgrade pip
pip install -e .
tripwire --version
```

From now on, every new PowerShell window needs:

```powershell
cd $HOME\tripwire
.\.venv\Scripts\Activate.ps1
```

## 5. Initialize

```powershell
tripwire init
```

This creates:

| What | Exact path |
|---|---|
| Config | `C:\Users\<you>\.config\tripwire\config.yaml` |
| Secrets (`.env`) | `C:\Users\<you>\.local\share\tripwire\.env` |
| Encrypted incident DB | `C:\Users\<you>\.local\share\tripwire\tripwire.db` |
| Decoy manifest | `C:\Users\<you>\.local\share\tripwire\manifest.json` |

`<you>` is your Windows user name, i.e. the folder `$HOME` (`$env:USERPROFILE`)
points to. To keep the config somewhere else, set `$env:TRIPWIRE_CONFIG` or
pass `--config` to every command.

The `.env` holds `TRIPWIRE_FERNET_KEY`, which decrypts your incidents. **Back it
up** somewhere safe, and never commit or share it. Your profile folder is already
readable only by you, Administrators and SYSTEM.

## 6. Connect Telegram

1. In Telegram, open **@BotFather**, send `/newbot`, follow the prompts and copy
   the token (`123456789:AA...`).
2. Open a chat with your new bot and press **Start**. A bot cannot message you
   until you do this.
3. Get your chat ID: message **@userinfobot**. It replies with your numeric ID.

Then run:

```powershell
tripwire setup-telegram
```

* **Bot token**: paste it with **Ctrl+V** or a **right-click**, then press
  Enter. **Nothing appears on screen while you paste or type.** This is
  intentional, the token is never echoed or logged.
* **Chat ID**: type the number from @userinfobot.

Tripwire checks the token with Telegram and sends a test message to your chat.
If both checks pass, it writes `TRIPWIRE_TELEGRAM_TOKEN` and
`TRIPWIRE_TELEGRAM_CHAT_ID` to `C:\Users\<you>\.local\share\tripwire\.env` and
sets `enabled: true` on the Telegram alert in
`C:\Users\<you>\.config\tripwire\config.yaml`. If a check fails, nothing is saved.

You can run `setup-telegram` again at any time to change the token or chat.

## 7. Plant a decoy

```powershell
tripwire plant --list
tripwire plant passwords "$HOME\Documents" --label "Documents password list"
```

Type `y` to confirm. This creates `C:\Users\<you>\Documents\passwords.txt`.
`tripwire status` shows every planted decoy.

## 8. Watch

```powershell
tripwire watch
```

Leave this window open: Tripwire only alerts while it is running. Press
**Ctrl+C** to stop it.

## 9. Test it

**What Windows can detect.** On Windows, the file watcher sees a decoy being
**changed, renamed, moved or deleted**. It does **not** see a file simply
being *opened and read*, e.g. in Notepad. To get an alert when a decoy is merely
opened, use a beacon decoy (9b).

### 9a. File decoy: open it and change it

Open a **second** PowerShell window and run:

```powershell
notepad "$HOME\Documents\passwords.txt"
```

Notepad opens the file. This alone does **not** alert. Now type any character
and press **Ctrl+S**. Within a few seconds a Telegram message arrives
(*"Decoy modified: Documents password list ..."*), and the `watch` window logs the event. Deleting or
renaming the file in Explorer also triggers an alert.

The same test without Notepad:

```powershell
Add-Content -Path "$HOME\Documents\passwords.txt" -Value " "
```

### 9b. Beacon decoy: alert on open

A beacon decoy loads a tiny image from your Tripwire server when it is opened.
For a local test the server runs on this PC at `http://127.0.0.1:8080`, which is
the default public URL from `tripwire init`.

1. Stop `tripwire watch` (Ctrl+C) and plant an HTML beacon:

   ```powershell
   tripwire plant beacon-html "$HOME\Desktop" --label "Desktop recovery codes"
   ```

2. Run the server and the file watcher in one process:

   ```powershell
   tripwire serve --with-collectors
   ```

   If Windows Defender Firewall asks for permission, you can click **Cancel**.
   The server only listens on `127.0.0.1`.

3. Double-click `Account-Recovery-Codes.html` on your Desktop. When your browser
   opens it, the image request hits the server and a *"Beacon opened: Desktop recovery codes ..."* alert arrives
   in Telegram.

For beacons to fire on *other* devices, `tripwire serve` must be reachable at a
public HTTPS URL (pass it to `tripwire init --public-url`). See the README.
Telegram only shows the "Open report" button for `https://` URLs.

### Check the result

```powershell
tripwire incidents
tripwire incidents --show <id>
```

## 10. Clean up

```powershell
tripwire plant --remove-all
```

This deletes every decoy Tripwire planted that is unchanged. Use `--force` to
also delete decoys you edited during testing.

## Optional: Windows auditing (Event ID 4663) — needs Administrator

Windows can record **who opened a file** in the Security event log (Event ID
4663, *"An attempt was made to access an object"*). This works even for plain
reads that the Tripwire watcher cannot see.

> **Tripwire does not read the Security log yet.** These steps give you an extra
> record in Event Viewer. They do not send Telegram alerts.

Every step below needs an **elevated** PowerShell: right-click PowerShell and
choose **Run as administrator**. Reading or changing audit settings (a SACL) and
reading the Security log both require Administrator rights.

1. Turn on success auditing for the *File System* subcategory. The GUID form
   works on every display language:

   ```powershell
   auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable
   auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"
   ```

2. Add an audit rule to the decoy itself. Replace `<you>` with your user name,
   because `$HOME` in an elevated window may point to a different account:

   ```powershell
   $path = "C:\Users\<you>\Documents\passwords.txt"
   $acl  = Get-Acl -Path $path -Audit
   $rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData", "Success")
   $acl.AddAuditRule($rule)
   Set-Acl -Path $path -AclObject $acl
   ```

3. Open the decoy (as any user), then read the events:

   ```powershell
   Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663 } -MaxEvents 50 |
     Where-Object { $_.Message -like '*passwords.txt*' } |
     Format-List TimeCreated, Message
   ```

   Each event names the account (*Subject*) and the program (*Process Name*)
   that opened the file. You can also look in Event Viewer → Windows Logs →
   Security, filtered on ID 4663.

Expect some noise: Windows Search, antivirus scans and Explorer previews also
read files. To undo, run `auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:disable`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `py` or `git` not found | Open a new PowerShell window after installing. |
| `tripwire` not found | Activate the venv: `.\.venv\Scripts\Activate.ps1` |
| `running scripts is disabled` | See the ExecutionPolicy step in section 3. |
| `config file not found` | Run `tripwire init` first. |
| `bot token rejected by Telegram` | Copy the token again from @BotFather (`/mybots` → API Token). |
| `chat not found` | Open your bot in Telegram and press **Start**, then check the chat ID. |
| No alert when opening a `.txt` decoy | Expected on Windows (see section 9). Change the file, or use a beacon decoy. |
| Old token still used | A `TRIPWIRE_TELEGRAM_TOKEN` environment variable overrides `.env`. Remove it with `Remove-Item Env:TRIPWIRE_TELEGRAM_TOKEN` (and from System Properties → Environment Variables if you set it there). |
