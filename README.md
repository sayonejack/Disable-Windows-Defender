# Windows Defender 禁用工具 / Windows Defender Disabler Tool

<!-- Language Switch / 语言切换 -->
**[🇨🇳 中文](#中文版本) | [🇺🇸 English](#english-version)**

---

## 中文版本

### 📋 项目简介

这是一个功能强大的Windows Defender完全禁用工具，提供分阶段执行选项，能够彻底关闭Windows Defender的所有防护功能。

### 📁 文件说明

- `Disable-Windows-Defender.ps1` - 主要的PowerShell禁用脚本
- `Disable-Windows-Defender-Run.bat` - 批处理启动文件（自动获取管理员权限）
- `Enable-Windows-Defender.ps1` - PowerShell启用脚本（恢复Defender功能）
- `Enable-Windows-Defender-Run.bat` - 启用脚本的批处理启动文件
- `PsExec.exe` - 微软官方工具，用于系统级权限操作

### 🚀 使用方法

#### 方法一：使用批处理文件（推荐）
直接双击运行 `Disable-Windows-Defender-Run.bat`，会自动请求管理员权限并执行脚本。

#### 方法二：直接运行PowerShell脚本
以管理员身份打开PowerShell，执行：
```powershell
.\Disable-Windows-Defender.ps1
```

#### 分阶段执行选项
```powershell
# 仅执行第一阶段（基础禁用）
.\Disable-Windows-Defender.ps1 -Phase1

# 仅执行第二阶段（服务和注册表）
.\Disable-Windows-Defender.ps1 -Phase2

# 仅执行第三阶段（高级设置和清理）
.\Disable-Windows-Defender.ps1 -Phase3

# 执行所有阶段
.\Disable-Windows-Defender.ps1 -All
```

### 🔄 启用/恢复 Windows Defender

#### 方法一：使用批处理文件（推荐）
直接双击运行 `Enable-Windows-Defender-Run.bat`，会自动请求管理员权限并执行启用脚本。

#### 方法二：直接运行PowerShell脚本
以管理员身份打开PowerShell，执行：
```powershell
.\Enable-Windows-Defender.ps1 -All
```

#### 分阶段启用选项
```powershell
# 仅执行第一阶段（启用基础功能）
.\Enable-Windows-Defender.ps1 -Phase1

# 仅执行第二阶段（启用服务和注册表）
.\Enable-Windows-Defender.ps1 -Phase2

# 仅执行第三阶段（启用高级设置）
.\Enable-Windows-Defender.ps1 -Phase3

# 启用所有功能
.\Enable-Windows-Defender.ps1 -All
```

### ⚠️ 重要提醒

1. **管理员权限必需** - 脚本必须以管理员身份运行
2. **系统兼容性** - 适用于Windows 10/11系统
3. **安全风险** - 禁用Windows Defender会降低系统安全性，请确保有其他安全措施
4. **可逆操作** - 提供了完整的启用脚本来恢复所有Defender功能
5. **备份建议** - 建议在使用前创建系统还原点

### 🛠️ 系统要求

- Windows 10/11
- PowerShell 5.0+
- 管理员权限

### ✅ 测试状态

- **Windows 11 24H2** - ✅ 测试通过
- **其他版本** - ❓ 兼容性未知，请谨慎使用

### 📄 免责声明

此工具仅供学习和测试目的使用，使用者需自行承担使用风险。建议在使用前创建系统还原点。

---

## English Version

### 📋 Project Overview

This is a powerful Windows Defender complete disabling tool that provides phased execution options to thoroughly turn off all Windows Defender protection features.

### 📁 File Description

- `Disable-Windows-Defender.ps1` - Main PowerShell disabling script
- `Disable-Windows-Defender-Run.bat` - Batch launcher file (automatically requests administrator privileges)
- `Enable-Windows-Defender.ps1` - PowerShell enabling script (restore Defender functionality)
- `Enable-Windows-Defender-Run.bat` - Batch launcher file for the enabling script
- `PsExec.exe` - Official Microsoft tool for system-level privilege operations

### 🚀 Usage Instructions

#### Method 1: Using Batch Files (Recommended)
Double-click to run `Disable-Windows-Defender-Run.bat`, which will automatically request administrator privileges and execute the script.

#### Method 2: Running PowerShell Script Directly
Open PowerShell as administrator and execute:
```powershell
.\Disable-Windows-Defender.ps1
```

#### Phased Execution Options
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

### 🔄 Enable/Restore Windows Defender

#### Method 1: Using Batch Files (Recommended)
Double-click to run `Enable-Windows-Defender-Run.bat`, which will automatically request administrator privileges and execute the enabling script.

#### Method 2: Running PowerShell Script Directly
Open PowerShell as administrator and execute:
```powershell
.\Enable-Windows-Defender.ps1 -All
```

#### Phased Enabling Options
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

### ⚠️ Important Warnings

1. **Administrator Privileges Required** - The script must be run as administrator
2. **System Compatibility** - Compatible with Windows 10/11 systems
3. **Security Risk** - Disabling Windows Defender will reduce system security, ensure you have other security measures
4. **Reversible Operation** - Complete enabling scripts are provided to restore all Defender functions
5. **Backup Recommendation** - It's recommended to create a system restore point before use

### 🛠️ System Requirements

- Windows 10/11
- PowerShell 5.0+
- Administrator privileges

### ✅ Testing Status

- **Windows 11 24H2** - ✅ Tested and working
- **Other versions** - ❓ Compatibility unknown, use with caution

### 📄 Disclaimer

This tool is for educational and testing purposes only. Users assume all risks of use. It's recommended to create a system restore point before use.
