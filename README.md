# Windows Defender 禁用工具

## 📋 项目简介

这是一个功能强大的Windows Defender完全禁用工具，提供分阶段执行选项，能够彻底关闭Windows Defender的所有防护功能。

## 📁 文件说明

- `Disable-Windows-Defender.ps1` - 主要的PowerShell禁用脚本
- `Disable-Windows-Defender-Run.bat` - 批处理启动文件（自动获取管理员权限）
- `PsExec.exe` - 微软官方工具，用于系统级权限操作

## 🚀 使用方法

### 方法一：使用批处理文件（推荐）
直接双击运行 `Disable-Windows-Defender-Run.bat`，会自动请求管理员权限并执行脚本。

### 方法二：直接运行PowerShell脚本
以管理员身份打开PowerShell，执行：
```powershell
.\Disable-Windows-Defender.ps1
```

### 分阶段执行选项
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

## ⚠️ 重要提醒

1. **管理员权限必需** - 脚本必须以管理员身份运行
2. **系统兼容性** - 适用于Windows 10/11系统
3. **安全风险** - 禁用Windows Defender会降低系统安全性，请确保有其他安全措施
4. **不可逆操作** - 部分操作可能难以撤销，请谨慎使用

## 🛠️ 系统要求

- Windows 10/11
- PowerShell 5.0+
- 管理员权限

## ✅ 测试状态

- **Windows 11 24H2** - ✅ 测试通过
- **其他版本** - ❓ 兼容性未知，请谨慎使用

## 📄 免责声明

此工具仅供学习和测试目的使用，使用者需自行承担使用风险。建议在使用前创建系统还原点。
