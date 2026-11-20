# Windows Privilege Escalation Checker

Standalone PowerShell enumeration script for Windows privilege escalation. Built for OSCP and pentest engagements.

**Enumerate-only** — shows findings and exploit steps but does **not** execute them.

## Usage

```powershell
# Standard scan (as low-priv user)
powershell -ep bypass -f WinPrivEsc-Checker.ps1

# Extended scan (slower, deeper file search + extra checks)
powershell -ep bypass -f WinPrivEsc-Checker.ps1 -Extended

# Admin mode — already have admin? Skip privesc noise, focus on loot & lateral movement
powershell -ep bypass -f WinPrivEsc-Checker.ps1 -Admin
```

No internet, no external tools, no APIs required.

## Modes

### Default (no flags)
Full privilege escalation scan: finds writable services, unquoted paths, DLL hijacking, UAC bypasses, kernel exploits, and more.

### `-Extended`
Everything in the default scan plus deeper file searches, known DLL hijack binaries, writable registry keys, and processes running as other users.

### `-Admin`
Post-exploitation mode for when you already have admin. **Skips all privesc checks** (services, scheduled tasks, UAC, DLL hijack, autoruns, kernel/CVE) and focuses on:

- All credentials (histories, stored creds, AutoLogon, PuTTY/WinSCP, browser data, WiFi keys)
- Full PowerShell + CMD history of every user, printed inline
- SAM/SYSTEM + LSASS dump reminders with commands
- DPAPI master keys and credential blobs for all users
- Interesting files across all profiles (`.kdbx`, `.ppk`, `.pem`, `.rdp`, `.sql`, `.env`, etc.)
- Non-default files in `C:\`, `C:\Temp`, `C:\Backups`, `C:\Scripts`, etc.
- Scheduled tasks by non-system accounts
- Active logon sessions and RDP saved connections
- Recently run programs (UserAssist, ROT13 decoded)
- Full domain enumeration: all users with password ages, Domain/Enterprise/Schema Admins members, Kerberoastable + ASREProastable users, constrained/unconstrained delegation, domain trusts, GPOs, DNS zones, computer accounts
- Network, defenses, MSSQL, mapped shares

## What It Checks

| Section | Description |
|---------|-------------|
| **§0 Orientation** | OS info, user context, integrity level, group memberships, token privileges |
| **§1 Credential Wins** | Stored creds, AutoLogon, PowerShell + CMD (Clink/Cmder) history of every user profile (always HIGH when non-empty, full contents printed), PuTTY/WinSCP/mRemoteNG/FileZilla sessions, WiFi keys, DPAPI blobs, browser data |
| **§2 File Search** | Unattend/sysprep files, SAM/SYSTEM backups, shadow copies, KeePass DBs, private keys, web configs, GPP cpassword |
| **§3 UAC** | UAC configuration, AlwaysInstallElevated, WSUS over HTTP |
| **§4 Services** | Unquoted paths, writable binaries/directories, modifiable DACLs, service registry keys |
| **§5 Scheduled Tasks** | Writable task binaries and directories |
| **§6 PATH/DLL Hijacking** | Writable PATH directories, known DLL hijack targets |
| **§7 Software & MSSQL** | Installed software with known cred storage, writable install dirs, MSSQL sysadmin/impersonation/linked servers/xp_cmdshell |
| **§8 Autoruns** | Writable autorun binaries, registry keys, startup folders |
| **§9 Network** | Listening ports, interfaces, ARP table (pivot detection) |
| **§10 Defenses** | Defender status & exclusions, AppLocker, PS logging, language mode |
| **§11 Kernel/CVE** | Patch level, HiveNightmare, PrintNightmare, Potato attacks, EternalBlue |
| **§12 Misc & Domain** | Mapped shares, writable staging dirs, Kerberoasting, ASREProasting, delegation, LAPS |
| **§13 Admin Extras** | *(only with `-Admin`)* All local users, SAM/LSASS dump commands, DPAPI keys, interesting files, non-default files, scheduled tasks by user accounts, logon sessions, RDP connections, UserAssist, domain users + groups + computers + GPOs + DNS + trusts |

## Output

Findings are color-coded by severity:

- 🟢 **Green (`+`)** — Actionable privilege escalation path
- 🟡 **Yellow (`>`)** — Lateral movement opportunity
- 🟡 **Yellow (`!`)** — Medium-severity warning
- ⚪ **Gray (`-`)** — Background info

Each actionable finding includes copy-pasteable exploit commands.

## Requirements

- PowerShell 2.0+
- No admin privileges needed (runs as current user)
- Works offline

## Disclaimer

For authorized security testing, CTF challenges, and educational purposes only. Always obtain proper authorization before running on any system.
