# Windows Defender Disabler Tool

<!-- Language Switch / 语言切换 -->
**[🇨🇳 中文](README.md) | 🇺🇸 English**

---

## 📋 Project Overview

This is a powerful Windows Defender complete disabling tool that provides phased execution options to thoroughly turn off all Windows Defender protection features.

## 📁 File Description

- `Disable-Windows-Defender.ps1` - Main PowerShell disabling script
- `Disable-Windows-Defender-Run.bat` - Batch launcher file (automatically requests administrator privileges)
- `Enable-Windows-Defender.ps1` - PowerShell enabling script (restore Defender functionality)
- `Enable-Windows-Defender-Run.bat` - Batch launcher file for the enabling script
- `PsExec.exe` - Official Microsoft tool for system-level privilege operations

## 🚀 Usage Instructions

### Method 1: Using Batch Files (Recommended)
Double-click to run `Disable-Windows-Defender-Run.bat`, which will automatically request administrator privileges and execute the script.

### Method 2: Running PowerShell Script Directly
Open PowerShell as administrator and execute:
```powershell
.\Disable-Windows-Defender.ps1
```

### Phased Execution Options
```powershell
# Execute Phase 1 only (Basic disable)
.\Disable-Windows-Defender.ps1 -Phase1

# Execute Phase 2 only (Services and registry)
.\Disable-Windows-Defender.ps1 -Phase2

# Execute Phase 3 only (Advanced settings and cleanup)
.\Disable-Windows-Defender.ps1 -Phase3

# Execute all phases
.\Disable-Windows-Defender.ps1 -All
```

## 🔄 Enable/Restore Windows Defender

### Method 1: Using Batch Files (Recommended)
Double-click to run `Enable-Windows-Defender-Run.bat`, which will automatically request administrator privileges and execute the enabling script.

### Method 2: Running PowerShell Script Directly
Open PowerShell as administrator and execute:
```powershell
.\Enable-Windows-Defender.ps1 -All
```

### Phased Enabling Options
```powershell
# Execute Phase 1 only (Enable basic functions)
.\Enable-Windows-Defender.ps1 -Phase1

# Execute Phase 2 only (Enable services and registry)
.\Enable-Windows-Defender.ps1 -Phase2

# Execute Phase 3 only (Enable advanced settings)
.\Enable-Windows-Defender.ps1 -Phase3

# Enable all functions
.\Enable-Windows-Defender.ps1 -All
```

## ⚠️ Important Warnings

1. **Administrator Privileges Required** - The script must be run as administrator
2. **System Compatibility** - Compatible with Windows 10/11 systems
3. **Security Risk** - Disabling Windows Defender will reduce system security, ensure you have other security measures
4. **Reversible Operation** - Complete enabling scripts are provided to restore all Defender functions
5. **Backup Recommendation** - It's recommended to create a system restore point before use

## 🛠️ System Requirements

- Windows 10/11
- PowerShell 5.0+
- Administrator privileges

## ✅ Testing Status

- **Windows 11 24H2** - ✅ Tested and working
- **Other versions** - ❓ Compatibility unknown, use with caution

## 📄 Disclaimer

This tool is for educational and testing purposes only. Users assume all risks of use. It's recommended to create a system restore point before use.
