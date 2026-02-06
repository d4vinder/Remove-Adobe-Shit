# =========================
# Admin check
# =========================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdmin)) {
    Write-Host "Please run PowerShell as Administrator." -ForegroundColor Red
    Write-Host "Right-click Start -> Windows Terminal (Admin) -> then run the script again."
    exit 1
}

# =========================
# Desktop Known Folder FIX
# =========================
function Get-DesktopPath {
    # Uses Windows Known Folder: Desktop
    # GUID: {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
    $code = @"
using System;
using System.Runtime.InteropServices;

public static class KnownFolder {
  [DllImport("shell32.dll")]
  private static extern int SHGetKnownFolderPath(ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

  public static string GetDesktop() {
    Guid desktop = new Guid("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
    IntPtr pPath;
    int hr = SHGetKnownFolderPath(ref desktop, 0, IntPtr.Zero, out pPath);
    if (hr != 0) Marshal.ThrowExceptionForHR(hr);
    string path = Marshal.PtrToStringUni(pPath);
    Marshal.FreeCoTaskMem(pPath);
    return path;
  }
}
"@

    try {
        Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue | Out-Null
        $p = [KnownFolder]::GetDesktop()
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path $p)) { return $p }
    } catch { }

    # Fallbacks (best-effort)
    $fallbacks = @(
        (Join-Path $env:USERPROFILE "Desktop"),
        (Join-Path $env:USERPROFILE "OneDrive\Desktop")
    )
    foreach ($f in $fallbacks) {
        if (Test-Path $f) { return $f }
    }

    # Last resort: user profile
    return $env:USERPROFILE
}

# =========================
# Globals / Setup
# =========================
$Global:TimeStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$Global:DesktopPath = Get-DesktopPath
$Global:BaseDir   = Join-Path $Global:DesktopPath "AdobeCleanup_$($Global:TimeStamp)"
$Global:BackupDir = Join-Path $Global:BaseDir "RegistryBackups"
$Global:QuarantineDir = Join-Path $Global:BaseDir "Quarantine"
$Global:LogPath = Join-Path $Global:BaseDir "AdobeCleanup.log"
$Global:Counter = 0

function Ensure-Dir([string]$Path) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
Ensure-Dir $Global:BaseDir
Ensure-Dir $Global:BackupDir
Ensure-Dir $Global:QuarantineDir

function Write-Log([string]$Message) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $line = "[$ts] $Message"
    Write-Host $line
    Add-Content -Path $Global:LogPath -Value $line
}

Write-Log "=== Adobe Cleanup Started ==="
Write-Log "DesktopPath resolved to: $Global:DesktopPath"
Write-Log "BaseDir: $Global:BaseDir"

# =========================
# Matching terms
# =========================
$Global:MatchTermsBase = @(
    "Adobe", "Creative Cloud", "CCXProcess", "CoreSync",
    "Adobe Desktop Service", "AdobeGC", "Genuine", "Acrobat",
    "Premiere", "AfterFX", "After Effects", "Photoshop", "Illustrator",
    "Lightroom", "InDesign", "Bridge", "CEP", "OOBE"
)
$Global:MatchTermsAggressive = @(
    "AAM", "CCLibrary", "AGS", "AGM", "AdobeUpdate", "ARM", "FLEXnet"
)

function Matches-Terms([string]$Text, [switch]$Aggressive) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $terms = @()
    $terms += $Global:MatchTermsBase
    if ($Aggressive) { $terms += $Global:MatchTermsAggressive }
    foreach ($t in $terms) {
        if ($Text -like "*$t*") { return $true }
    }
    return $false
}

# =========================
# Safe move/delete helpers
# =========================
function Get-UniqueStamp {
    $Global:Counter++
    $ms = (Get-Date).ToString("yyyyMMdd_HHmmss_fff")
    return "{0}_{1:0000}" -f $ms, $Global:Counter
}

function Safe-RemoveItem([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    try {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted: $Path"
        return $true
    } catch {
        Write-Log "FAILED delete: $Path :: $($_.Exception.Message)"
        return $false
    }
}

function Safe-MoveToQuarantine([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    try {
        $leaf = Split-Path $Path -Leaf
        $stamp = Get-UniqueStamp
        $dest = Join-Path $Global:QuarantineDir ("{0}_{1}" -f $leaf, $stamp)
        Move-Item -Path $Path -Destination $dest -Force -ErrorAction Stop
        Write-Log "Quarantined: $Path -> $dest"
        return $true
    } catch {
        Write-Log "FAILED quarantine: $Path :: $($_.Exception.Message)"
        return $false
    }
}

# =========================
# Registry export + delete (VERIFIED)
# =========================
function Convert-ToRegExePath([string]$RegProviderPath) {
    $p = $RegProviderPath

    if ($p -like "Microsoft.PowerShell.Core\Registry::*") {
        $p = $p -replace '^Microsoft\.PowerShell\.Core\\', ''
    }

    if ($p -like "Registry::*") {
        $p = $p -replace "^Registry::HKEY_LOCAL_MACHINE", "HKLM"
        $p = $p -replace "^Registry::HKEY_CURRENT_USER",  "HKCU"
        return $p
    }

    $p = $p -replace "^HKLM:", "HKLM"
    $p = $p -replace "^HKCU:", "HKCU"
    return $p
}

function Export-RegKeyVerified([string]$RegProviderPath) {
    $regExePath = Convert-ToRegExePath $RegProviderPath
    $safeName = ($regExePath -replace '[\\/:*?"<>| ]','_')
    $outFile = Join-Path $Global:BackupDir "$safeName`_$((Get-UniqueStamp)).reg"

    Write-Log "Exporting registry key: $regExePath -> $outFile"
    & reg.exe export "$regExePath" "$outFile" /y | Out-Null
    $exit = $LASTEXITCODE

    if ($exit -ne 0) {
        Write-Log "EXPORT FAILED (exit $exit): $regExePath"
        return $null
    }
    if (-not (Test-Path $outFile)) {
        Write-Log "EXPORT FAILED (no file created): $regExePath"
        return $null
    }
    $len = (Get-Item $outFile).Length
    if ($len -lt 200) {
        Write-Log "EXPORT FAILED (file too small: $len bytes): $regExePath"
        return $null
    }

    Write-Log "Export verified OK ($len bytes): $outFile"
    return $outFile
}

function Safe-RemoveRegKeyVerified([string]$RegProviderPath) {
    if (-not (Test-Path $RegProviderPath)) { return $false }

    $backup = Export-RegKeyVerified $RegProviderPath
    if ($null -eq $backup) {
        Write-Log "Skipping delete because backup failed: $RegProviderPath"
        return $false
    }

    try {
        Remove-Item -Path $RegProviderPath -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted registry key: $RegProviderPath"
        return $true
    } catch {
        Write-Log "FAILED delete registry key: $RegProviderPath :: $($_.Exception.Message)"
        Write-Log "Backup available at: $backup"
        return $false
    }
}

function Safe-RemoveRegValue([string]$RegProviderPath, [string]$ValueName) {
    try {
        Remove-ItemProperty -Path $RegProviderPath -Name $ValueName -Force -ErrorAction Stop
        Write-Log "Deleted registry value: $RegProviderPath -> $ValueName"
        return $true
    } catch {
        Write-Log "FAILED delete registry value: $RegProviderPath -> $ValueName :: $($_.Exception.Message)"
        return $false
    }
}

# =========================
# Services / tasks / processes
# =========================
function Stop-AdobeProcesses {
    $procHints = @("Adobe", "CCX", "CoreSync", "CreativeCloud", "Acrobat", "CEP", "AdobeGC", "AGM", "AGS")
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $n = $_.Name
        foreach ($t in $procHints) { if ($n -like "*$t*") { return $true } }
        return $false
    }
    foreach ($p in $procs) {
        try {
            Write-Log "Stopping process: $($p.Name) (PID $($p.Id))"
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
        } catch {
            Write-Log "FAILED stopping process: $($p.Name) :: $($_.Exception.Message)"
        }
    }
}

function Disable-ServiceSafe([string]$ServiceName) {
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    try { Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
}

function Delete-ServiceSafe([string]$ServiceName) {
    Disable-ServiceSafe $ServiceName
    try {
        Write-Log "Deleting service via sc.exe: $ServiceName"
        & sc.exe delete "$ServiceName" | Out-Null
        $exit = $LASTEXITCODE
        if ($exit -ne 0) {
            Write-Log "FAILED service delete (exit $exit): $ServiceName"
            return $false
        }
        return $true
    } catch {
        Write-Log "FAILED service delete: $ServiceName :: $($_.Exception.Message)"
        return $false
    }
}

# =========================
# Inventory / Report
# =========================
function Get-AdobeInventory([switch]$Aggressive) {
    Write-Log "--- Collecting report ---"

    $UninstallRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $Installed = foreach ($root in $UninstallRoots) {
        Get-ItemProperty $root -ErrorAction SilentlyContinue |
            Where-Object { Matches-Terms $_.DisplayName -Aggressive:$Aggressive } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, PSPath
    }

    $Services = Get-CimInstance Win32_Service |
        Where-Object { (Matches-Terms $_.Name -Aggressive:$Aggressive) -or (Matches-Terms $_.DisplayName -Aggressive:$Aggressive) } |
        Select-Object Name, DisplayName, State, StartMode, PathName

    $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { (Matches-Terms $_.TaskName -Aggressive:$Aggressive) -or (Matches-Terms $_.TaskPath -Aggressive:$Aggressive) } |
        Select-Object TaskName, TaskPath, State

    $RunKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    $StartupRegFindings = @()
    foreach ($rk in $RunKeys) {
        if (Test-Path $rk) {
            $props = (Get-ItemProperty $rk -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object {
                    [PSCustomObject]@{
                        RegPath   = $rk
                        ValueName = $_.Name
                        ValueData = [string]$_.Value
                    }
                }
            $StartupRegFindings += $props | Where-Object {
                (Matches-Terms $_.ValueName -Aggressive:$Aggressive) -or
                (Matches-Terms $_.ValueData -Aggressive:$Aggressive)
            }
        }
    }

    $StartupFolders = @(
        [PSCustomObject]@{ Name="UserStartup";   Path=(Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup") },
        [PSCustomObject]@{ Name="CommonStartup"; Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" }
    )

    $StartupFolderFindings = @()
    foreach ($sf in $StartupFolders) {
        if (Test-Path $sf.Path) {
            $StartupFolderFindings += Get-ChildItem $sf.Path -Force -ErrorAction SilentlyContinue |
                Where-Object { Matches-Terms $_.Name -Aggressive:$Aggressive } |
                Select-Object @{n="Folder";e={$sf.Path}}, Name, FullName
        }
    }

    $FolderTargets = @(
        "C:\Program Files\Adobe",
        "C:\Program Files (x86)\Adobe",
        "C:\Program Files\Common Files\Adobe",
        "C:\ProgramData\Adobe",
        (Join-Path $env:LOCALAPPDATA "Adobe"),
        (Join-Path $env:APPDATA "Adobe"),
        (Join-Path $env:LOCALAPPDATA "Adobe\OOBE")
    )
    if ($Aggressive) {
        $FolderTargets += @(
            (Join-Path $env:APPDATA "Adobe\CEP"),
            "C:\Program Files\Common Files\Adobe\AdobeGCClient"
        )
    }
    $FoldersFound = $FolderTargets | Where-Object { Test-Path $_ } | ForEach-Object { [PSCustomObject]@{ Path=$_ } }

    $RegKeyTargets = @(
        "HKCU:\Software\Adobe",
        "HKCU:\Software\Adobe Systems Incorporated",
        "HKLM:\SOFTWARE\Adobe",
        "HKLM:\SOFTWARE\Adobe Systems Incorporated",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe Systems Incorporated"
    )
    $RegKeysFound = $RegKeyTargets | Where-Object { Test-Path $_ } | ForEach-Object { [PSCustomObject]@{ RegKey=$_ } }

    [PSCustomObject]@{
        Installed = $Installed
        Services  = $Services
        Tasks     = $Tasks
        StartupRegFindings    = $StartupRegFindings
        StartupFolderFindings = $StartupFolderFindings
        FoldersFound = $FoldersFound
        RegKeysFound = $RegKeysFound
    }
}

function Save-Report($inv) {
    $inv.Installed | Sort-Object DisplayName | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "InstalledApps.txt")
    $inv.Services  | Sort-Object Name        | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "Services.txt")
    $inv.Tasks     | Sort-Object TaskName    | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "ScheduledTasks.txt")
    $inv.StartupRegFindings | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "StartupRegistry.txt")
    $inv.StartupFolderFindings | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "StartupFolders.txt")
    $inv.FoldersFound | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "FoldersFound.txt")
    $inv.RegKeysFound | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $Global:BaseDir "RegistryKeysFound.txt")

    Write-Host ""
    Write-Host "=== REPORT SUMMARY ===" -ForegroundColor Cyan
    Write-Host ("Installed entries : {0}" -f ($inv.Installed.Count))
    Write-Host ("Services          : {0}" -f ($inv.Services.Count))
    Write-Host ("Scheduled tasks   : {0}" -f ($inv.Tasks.Count))
    Write-Host ("Startup (registry): {0}" -f ($inv.StartupRegFindings.Count))
    Write-Host ("Startup (folders) : {0}" -f ($inv.StartupFolderFindings.Count))
    Write-Host ("Folders found     : {0}" -f ($inv.FoldersFound.Count))
    Write-Host ("Registry keys     : {0}" -f ($inv.RegKeysFound.Count))
    Write-Host ""
    Write-Host "Saved to: $Global:BaseDir" -ForegroundColor Yellow
    Write-Host ""
    Write-Log "Report saved to: $Global:BaseDir"
}

# =========================
# Menu
# =========================
function Prompt-YesNo([string]$Question, [bool]$DefaultYes = $false) {
    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $ans = Read-Host "$Question $suffix"
        if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }
        switch ($ans.Trim().ToLower()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { Write-Host "Please type Y or N." -ForegroundColor DarkYellow }
        }
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "Adobe Cleanup - Choose an option" -ForegroundColor Cyan
    Write-Host "1) Report only (no changes)"
    Write-Host "2) Safe cleanup (Quarantine files, disable services, remove tasks/startup, delete Adobe registry keys ONLY when export is verified)"
    Write-Host "3) Deeper cleanup (DELETE files instead of quarantine + everything in option 2)"
    Write-Host "4) Nuclear (Option 3 + DELETE Adobe services via sc.exe delete)"
    Write-Host "5) Exit"
    Write-Host ""
    return (Read-Host "Enter 1-5")
}

# =========================
# Actions
# =========================
function Run-Cleanup {
    param(
        [switch]$Aggressive,
        [switch]$DeleteFiles,
        [switch]$DeleteServices
    )

    $inv = Get-AdobeInventory -Aggressive:$Aggressive
    Save-Report $inv

    $confirm = Prompt-YesNo "Proceed with cleanup actions now?" $false
    if (-not $confirm) {
        Write-Log "User cancelled after report."
        Write-Host "Cancelled. Report kept at: $Global:BaseDir" -ForegroundColor Yellow
        return
    }

    Write-Log "User confirmed cleanup."
    Write-Log "Mode: DeleteFiles=$DeleteFiles DeleteServices=$DeleteServices Aggressive=$Aggressive"

    # Stop processes first
    Stop-AdobeProcesses

    # Services
    foreach ($svc in $inv.Services) {
        Write-Log "Service: $($svc.Name) ($($svc.DisplayName))"
        if ($DeleteServices) {
            [void](Delete-ServiceSafe $svc.Name)
        } else {
            Disable-ServiceSafe $svc.Name
        }
    }

    # Scheduled tasks
    foreach ($t in $inv.Tasks) {
        try {
            Write-Log "Deleting scheduled task: $($t.TaskPath)$($t.TaskName)"
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
        } catch {
            Write-Log "FAILED delete task: $($t.TaskPath)$($t.TaskName) :: $($_.Exception.Message)"
        }
    }

    # Startup registry values
    foreach ($s in $inv.StartupRegFindings) {
        Safe-RemoveRegValue -RegProviderPath $s.RegPath -ValueName $s.ValueName | Out-Null
    }

    # Startup folder items
    foreach ($sf in $inv.StartupFolderFindings) {
        if ($DeleteFiles) { [void](Safe-RemoveItem $sf.FullName) }
        else { [void](Safe-MoveToQuarantine $sf.FullName) }
    }

    # Folders
    foreach ($f in $inv.FoldersFound) {
        if ($DeleteFiles) { [void](Safe-RemoveItem $f.Path) }
        else { [void](Safe-MoveToQuarantine $f.Path) }
    }

    # Registry keys (verified export before delete)
    foreach ($rk in $inv.RegKeysFound) {
        [void](Safe-RemoveRegKeyVerified $rk.RegKey)
    }

    Write-Log "=== Cleanup complete. Reboot recommended. ==="
    Write-Host ""
    Write-Host "DONE. Reboot recommended." -ForegroundColor Green
    Write-Host "Log + report + registry backups: $Global:BaseDir" -ForegroundColor Yellow
    if (-not $DeleteFiles) {
        Write-Host "Quarantine (rollback for files): $Global:QuarantineDir" -ForegroundColor Yellow
    }
}

# =========================
# Main flow
# =========================
Write-Host ""
Write-Host "Adobe Cleanup will FIRST generate a report (and logs) in this folder:" -ForegroundColor Cyan
Write-Host "  $Global:BaseDir" -ForegroundColor Yellow
Write-Host ""
Write-Host "Tip: If your Desktop is OneDrive-redirected, it will still appear on the Desktop you see in Explorer." -ForegroundColor DarkGray
Write-Host ""

$useAggressive = Prompt-YesNo "Use Aggressive matching? (Finds more, may include some non-Adobe leftovers)" $false

while ($true) {
    $sel = Show-Menu
    switch ($sel) {
        "1" {
            $inv = Get-AdobeInventory -Aggressive:$useAggressive
            Save-Report $inv
        }
        "2" {
            Run-Cleanup -Aggressive:$useAggressive -DeleteFiles:$false -DeleteServices:$false
        }
        "3" {
            $warn = Prompt-YesNo "This will DELETE files instead of quarantining. Continue?" $false
            if ($warn) { Run-Cleanup -Aggressive:$useAggressive -DeleteFiles:$true -DeleteServices:$false }
        }
        "4" {
            $warn1 = Prompt-YesNo "This will DELETE files (no quarantine). Continue?" $false
            if (-not $warn1) { break }
            $warn2 = Prompt-YesNo "This will also DELETE matched services (sc.exe delete). Continue?" $false
            if ($warn2) { Run-Cleanup -Aggressive:$useAggressive -DeleteFiles:$true -DeleteServices:$true }
        }
        "5" {
            Write-Log "User exited."
            break
        }
        default {
            Write-Host "Please choose 1-5." -ForegroundColor DarkYellow
        }
    }
}
