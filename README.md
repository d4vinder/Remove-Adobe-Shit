# Remove-Adobe-Shit (Windows) — Report → Confirm → Remove

A safety-first PowerShell cleanup script for Windows that helps you **find and remove Adobe/Creative Cloud remnants** with a **novice-friendly menu** and a **report-first workflow**.

It was built to avoid the classic “oops, I deleted something important” outcome by:

- Generating a **full report first**
- Asking for **explicit confirmation** before any removal
- Creating **verified registry exports** before deleting registry keys
- Supporting a safer **Quarantine** mode for file/folder removals (rollback-friendly)

---

## Features

- ✅ **Novice-friendly menu** (no parameters required)
- ✅ **Report-only mode** (no changes)
- ✅ **Safe cleanup mode**
  - Quarantines matched files/folders instead of deleting
  - Disables matched services
  - Removes matched scheduled tasks and startup entries
  - Deletes matched registry keys **only after verified export**
- ✅ **Deeper/Nuclear options**
  - Delete files instead of quarantine
  - Optionally delete services using `sc.exe delete`
- ✅ **Stops likely Adobe processes** first (reduces locked file failures)
- ✅ **Strong safety checks**
  - **Registry export verification:** checks exit code + file existence + file size
  - **Quarantine filename collision protection:** milliseconds + counter
- ✅ **Logging**
  - Writes a readable log file for every run

---

## Where does it save the report?

The script saves output into a timestamped folder on your **actual Windows Desktop path**, even if your Desktop is OneDrive-redirected.

Example output folder:

- `Desktop\AdobeCleanup_YYYYMMDD_HHMMSS\`

Inside you’ll find:

- `InstalledApps.txt`
- `Services.txt`
- `ScheduledTasks.txt`
- `StartupRegistry.txt`
- `StartupFolders.txt`
- `FoldersFound.txt`
- `RegistryKeysFound.txt`
- `AdobeCleanup.log`
- `RegistryBackups\` (verified `.reg` exports)
- `Quarantine\` (if using quarantine mode)

---

## Requirements

- Windows 10/11
- PowerShell 5.1+ (Windows built-in) or PowerShell 7+
- **Must run as Administrator**

> Tip: Right-click Start → **Windows Terminal (Admin)**

---

## Usage

### 1) Download / Clone

Place `AdobeCleanup.ps1` on your machine.

### 2) Run as Administrator

Open **Windows Terminal (Admin)** or PowerShell (Admin), then:

```powershell
cd "C:\path\to\script"
powershell -ExecutionPolicy Bypass -File .\Remove-Adobe-Shit.ps1
