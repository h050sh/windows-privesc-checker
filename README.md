# Windows Privilege Escalation Checker

Standalone PowerShell enumeration script for Windows privilege escalation. Built for OSCP and pentest engagements.

**Enumerate-only** — shows findings and exploit steps but does **not** execute them.

## Usage

```powershell
# Standard scan
powershell -ep bypass -f WinPrivEsc-Checker.ps1

# Extended scan (slower, deeper file search + extra checks)
powershell -ep bypass -f WinPrivEsc-Checker.ps1 -Extended
```

No internet, no external tools, no APIs required.

## What It Checks

| Section | Description |
|---------|-------------|
| **§0 Orientation** | OS info, user context, integrity level, group memberships, token privileges |
| **§1 Credential Wins** | Stored creds, AutoLogon, PS history, PuTTY/WinSCP/mRemoteNG/FileZilla sessions, WiFi keys, DPAPI blobs, browser data |
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
