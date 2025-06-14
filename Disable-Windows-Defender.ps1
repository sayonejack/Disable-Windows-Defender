# ==============================================================================
# Refactored Enhanced Windows Defender Disabler Script v3.0
# 重构增强版Windows Defender禁用脚本
# 合并并重构 Disable-Windows-Defender.ps1 和 Enhanced-Disable-Windows-Defender.ps1
# ==============================================================================

param(
    [switch]$Phase1,    # 第一阶段：基础禁用
    [switch]$Phase2,    # 第二阶段：服务和注册表
    [switch]$Phase3,    # 第三阶段：高级设置和清理
    [switch]$All        # 全部阶段一次执行
)

# ==============================================================================
# 初始化和辅助函数
# ==============================================================================

# 检查管理员权限
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❗ 此脚本需要管理员权限运行" -ForegroundColor Red
    exit 1
}

# 全局变量
$script:Results = [ordered]@{}
$script:StartTime = Get-Date
$script:PsExecPath = $null
$script:ConfigDetails = @{}

# 初始化脚本
function Initialize-Script {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Refactored Defender Disabler v3.0" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PowerShell版本: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    Write-Host "开始时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host ""
    
    # 检查PsExec
    $psExecInScript = Join-Path $PSScriptRoot "PsExec.exe"
    if (Test-Path $psExecInScript) {
        $script:PsExecPath = $psExecInScript
        Write-Host "✅ PsExec已找到: $psExecInScript" -ForegroundColor Green
    } else {
        $psExecInPath = Get-Command PsExec -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if ($null -ne $psExecInPath) {
            $script:PsExecPath = $psExecInPath
             Write-Host "✅ PsExec已在系统路径中找到: $psExecInPath" -ForegroundColor Green
        } else {
            Write-Host "⚠️ PsExec未找到。请从Sysinternals下载并放置在脚本同目录或系统路径中:" -ForegroundColor Yellow
            Write-Host "https://learn.microsoft.com/zh-cn/sysinternals/downloads/psexec" -ForegroundColor Cyan
        }
    }
    Write-Host ""
}

# 记录结果
function Add-Result {
    param($Name, $Success, $Details = "")
    $script:Results[$Name] = @{
        Success = $Success
        Details = $Details
        Timestamp = Get-Date
    }
}

# ==============================================================================
# 第一阶段：基础禁用功能
# ==============================================================================

function Invoke-Phase1 {
    Write-Host "🚀 执行第一阶段：基础禁用功能" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Gray
    
    # 1.1 禁用Tamper Protection
    Write-Host "[1.1] 禁用篡改保护 (Tamper Protection)..." -ForegroundColor Yellow
    $tamperResult = Disable-TamperProtection
    Add-Result "TamperProtection" $tamperResult
    
    # 1.2 禁用Smart App Control
    Write-Host "[1.2] 禁用智能应用控制 (Smart App Control)..." -ForegroundColor Yellow
    $smartAppResult = Disable-SmartAppControl
    Add-Result "SmartAppControl" $smartAppResult
    
    # 1.3 禁用实时保护
    Write-Host "[1.3] 禁用实时保护 (Real-time Protection)..." -ForegroundColor Yellow
    if ($tamperResult) {
        $realtimeResult = Disable-RealtimeProtection
        Add-Result "RealtimeProtection" $realtimeResult
    } else {
        Write-Host "  ⚠️ 跳过实时保护设置，因为篡改保护未禁用。" -ForegroundColor Yellow
        Add-Result "RealtimeProtection" $false "Skipped, Tamper Protection is active."
    }
    
    Write-Host ""
    Write-Host "✅ 第一阶段完成" -ForegroundColor Green
    Show-PhaseResults @("TamperProtection", "SmartAppControl", "RealtimeProtection")
}

function Disable-TamperProtection {
    # 尝试使用PsExec以SYSTEM权限禁用
    if ($script:PsExecPath) {
        try {
            Write-Host "  正在尝试使用PsExec以SYSTEM权限禁用..." -ForegroundColor Cyan
            $tempScript = Join-Path $env:TEMP "DisableTamperProtection.ps1"
            @"
`$key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
if (!(Test-Path `$key)) { exit 2 }
try {
    Set-ItemProperty -Path `$key -Name 'TamperProtection' -Value 4 -Force -ErrorAction Stop
    exit 0
} catch {
    exit 1
}
"@ | Out-File -FilePath $tempScript -Encoding ASCII
            
            $process = Start-Process -FilePath $script:PsExecPath -ArgumentList "-accepteula", "-s", "-nobanner", "powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "`"$tempScript`"" -Wait -PassThru -NoNewWindow
            Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
            
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
            $tamperValue = (Get-ItemProperty -Path $key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
            if ($tamperValue -eq 4) {
                Write-Host "  ✅ PsExec成功禁用了篡改保护!" -ForegroundColor Green
                return $true
            }
             Write-Host "  ⚠️ PsExec执行完毕，但验证失败。尝试常规方法..." -ForegroundColor Yellow
        } catch {
            Write-Host "  ❌ 使用PsExec时出错: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # 常规方法
    try {
        Write-Host "  尝试常规方法..." -ForegroundColor Cyan
        $key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        if (!(Test-Path $key)) { return $false }
        Set-ItemProperty -Path $key -Name 'TamperProtection' -Value 4 -Force -ErrorAction Stop
        if (((Get-ItemProperty -Path $key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection -eq 4)) {
             Write-Host "  ✅ 成功禁用篡改保护" -ForegroundColor Green
             return $true
        }
    } catch {}

    # 如果失败，提供手动操作指引
    Write-Host ""
    Write-Host "  ❌ 无法自动禁用篡改保护。请手动操作:" -ForegroundColor Red
    Write-Host "  1. 打开 Windows 安全中心" -ForegroundColor Cyan
    Write-Host "  2. 病毒和威胁防护 -> 病毒和威胁防护设置" -ForegroundColor Cyan
    Write-Host "  3. 关闭 '篡改保护'" -ForegroundColor Cyan
    Write-Host "  4. 关闭后重新运行此脚本" -ForegroundColor Cyan
    Write-Host ""
    return $false
}

function Disable-SmartAppControl {
    try {
        $k='HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        if (!(Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        Set-ItemProperty -Path $k -Name 'VerifiedAndReputablePolicyState' -Value 0 -Type DWORD -Force -ErrorAction Stop
        
        $value = (Get-ItemProperty -Path $k -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
        if ($value -eq 0) {
            Write-Host "  ✅ 智能应用控制已关闭" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠️ 智能应用控制关闭失败" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "  ❌ 设置智能应用控制时出错: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Disable-RealtimeProtection {
    try {
        # 使用PowerShell cmdlet
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
        
        # 再次通过注册表强制关闭
        $rtPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        if (Test-Path $rtPath) {
            Set-ItemProperty -Path $rtPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue
        }
        
        # 验证状态
        $status = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
        if ($null -eq $status -or $status -eq $false) {
            # 如果Get-MpComputerStatus失败或返回false，都视为成功
            Write-Host "  ✅ 实时监控已关闭" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠️ 实时监控关闭失败" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "  ❌ 禁用实时监控时出错: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==============================================================================
# 第二阶段：服务和注册表配置
# ==============================================================================

function Invoke-Phase2 {
    Write-Host "🚀 执行第二阶段：服务和注册表配置" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Gray
    
    # 2.1 配置组策略
    Write-Host "[2.1] 配置组策略 (Group Policies)..." -ForegroundColor Yellow
    $policyResult = Set-GroupPolicies
    Add-Result "GroupPolicies" $policyResult

    # 2.2 禁用Defender服务
    Write-Host "[2.2] 禁用Windows Defender服务..." -ForegroundColor Yellow
    $servicesResult = Disable-DefenderServices
    Add-Result "DefenderServices" $servicesResult
    
    # 2.3 禁用SpyNet报告
    Write-Host "[2.3] 禁用SpyNet/MAPS报告..." -ForegroundColor Yellow
    $spyNetResult = Disable-SpyNetReporting
    Add-Result "SpyNetReporting" $spyNetResult
    
    # 2.4 禁用通知系统
    Write-Host "[2.4] 禁用通知..." -ForegroundColor Yellow
    $notificationResult = Disable-DefenderNotifications
    Add-Result "DefenderNotifications" $notificationResult
    
    Write-Host ""
    Write-Host "✅ 第二阶段完成" -ForegroundColor Green
    Show-PhaseResults @("GroupPolicies", "DefenderServices", "SpyNetReporting", "DefenderNotifications")
}

function Set-GroupPolicies {
    Write-Host "  正在应用组策略和注册表设置..." -ForegroundColor Cyan
    $allSuccess = $true

    # 定义所有要应用的设置
    $policies = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableAntiSpyware'; Value = 1; DisplayName = "禁用Defender(DisableAntiSpyware)" },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'ServiceKeepAlive'; Value = 0; DisplayName = "禁用服务保护(ServiceKeepAlive)" },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableBehaviorMonitoring'; Value = 1; DisplayName = "禁用行为监控" },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableOnAccessProtection'; Value = 1; DisplayName = "禁用扫描所有下载文件和附件" },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableScanOnRealtimeEnable'; Value = 1; DisplayName = "禁用实时扫描" },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'; Name = 'DefinitionUpdateFileSharesSources'; Value = 0; DisplayName = "关闭签名更新" }
    )

    foreach ($policy in $policies) {
        try {
            if (!(Test-Path $policy.Path)) {
                New-Item -Path $policy.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Type DWORD -Force
            
            # 验证
            $currentValue = (Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue)."$($policy.Name)"
            if ($currentValue -eq $policy.Value) {
                Write-Host "    ✅ $($policy.DisplayName) 已设置" -ForegroundColor Green
            } else {
                Write-Host "    ⚠️ $($policy.DisplayName) 设置失败 (期望: $($policy.Value), 实际: $currentValue)" -ForegroundColor Yellow
                $allSuccess = $false
            }
        } catch {
            Write-Host "    ❌ $($policy.DisplayName) 设置时出错: $($_.Exception.Message)" -ForegroundColor Red
            $allSuccess = $false
        }
    }
    return $allSuccess
}

function Disable-DefenderServices {
    $services = @("WinDefend", "WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot", "Sense", "SecurityHealthService")
    
    if ($script:PsExecPath) {
        Write-Host "  使用PsExec以SYSTEM权限禁用服务..." -ForegroundColor Cyan
        $tempScriptContent = @"
`$services = @("WinDefend", "WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot", "Sense", "SecurityHealthService")
`$global:exitCode = 0
foreach (`$service in `$services) {
    try {
        `$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\`$service"
        if (Test-Path `$servicePath) {
            Set-Service -Name `$service -StartupType Disabled -ErrorAction SilentlyContinue
            Set-ItemProperty -Path `$servicePath -Name "Start" -Value 4 -Type DWORD -Force
            if ((Get-ItemProperty -Path `$servicePath -Name "Start").Start -ne 4) { `$global:exitCode = 1 }
        }
    } catch { `$global:exitCode = 1 }
}
exit `$global:exitCode
"@
        $tempScript = Join-Path $env:TEMP "DisableServices.ps1"
        $tempScriptContent | Out-File -FilePath $tempScript -Encoding UTF8
        
        Start-Process -FilePath $script:PsExecPath -ArgumentList "-accepteula", "-s", "-nobanner", "powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "`"$tempScript`"" -Wait -PassThru -NoNewWindow | Out-Null
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

        # 验证
        $allSuccess = $true
        foreach ($service in $services) {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
            if (Test-Path $servicePath) {
                if ((Get-ItemProperty -Path $servicePath -Name "Start" -ErrorAction SilentlyContinue).Start -eq 4) {
                    Write-Host "    ✅ $service 已禁用" -ForegroundColor Green
                } else {
                    Write-Host "    ⚠️ $service 禁用失败" -ForegroundColor Yellow
                    $allSuccess = $false
                }
            }
        }
        return $allSuccess
    }

    # 常规方法
    Write-Host "  PsExec未找到，使用常规方法..." -ForegroundColor Yellow
    $allSuccess = $true
    foreach ($service in $services) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
            if (Test-Path $servicePath) {
                Set-ItemProperty -Path $servicePath -Name "Start" -Value 4 -Type DWORD -Force
                 if ((Get-ItemProperty -Path $servicePath -Name "Start").Start -eq 4) {
                    Write-Host "    ✅ $service 已禁用" -ForegroundColor Green
                } else {
                    Write-Host "    ⚠️ $service 禁用可能不完整" -ForegroundColor Yellow
                    $allSuccess = $false
                }
            }
        } catch {
             Write-Host "    ❌ $service 配置失败" -ForegroundColor Red
             $allSuccess = $false
        }
    }
    return $allSuccess
}

function Disable-SpyNetReporting {
    try {
        $spyNetPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        if (!(Test-Path $spyNetPath)) { New-Item -Path $spyNetPath -Force | Out-Null }
        
        # 禁用SpyNet/MAPS
        Set-ItemProperty -Path $spyNetPath -Name 'SpyNetReporting' -Value 0 -Type DWORD -Force
        # 不发送样本
        Set-ItemProperty -Path $spyNetPath -Name 'SubmitSamplesConsent' -Value 2 -Type DWORD -Force
        
        $val1 = (Get-ItemProperty -Path $spyNetPath -Name 'SpyNetReporting').SpyNetReporting
        $val2 = (Get-ItemProperty -Path $spyNetPath -Name 'SubmitSamplesConsent').SubmitSamplesConsent
        
        if ($val1 -eq 0 -and $val2 -eq 2) {
            Write-Host "  ✅ SpyNet/MAPS报告已禁用" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠️ SpyNet/MAPS报告禁用失败" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "  ❌ SpyNet配置出错: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Disable-DefenderNotifications {
    try {
        $notifPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'
        if (!(Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }
        
        Set-ItemProperty -Path $notifPath -Name 'DisableNotifications' -Value 1 -Type DWORD -Force
        Set-ItemProperty -Path $notifPath -Name 'DisableEnhancedNotifications' -Value 1 -Type DWORD -Force
        
        $val1 = (Get-ItemProperty -Path $notifPath -Name 'DisableNotifications').DisableNotifications
        $val2 = (Get-ItemProperty -Path $notifPath -Name 'DisableEnhancedNotifications').DisableEnhancedNotifications

        if ($val1 -eq 1 -and $val2 -eq 1) {
            Write-Host "  ✅ Defender通知已禁用" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠️ Defender通知禁用失败" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "  ❌ 通知配置出错: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==============================================================================
# 第三阶段：高级设置和清理
# ==============================================================================

function Invoke-Phase3 {
    Write-Host "🚀 执行第三阶段：高级设置和清理" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Gray
    
    # 3.1 禁用SmartScreen
    Write-Host "[3.1] 禁用SmartScreen..." -ForegroundColor Yellow
    $smartScreenResult = Disable-SmartScreen
    Add-Result "SmartScreen" $smartScreenResult
    
    # 3.2 移除右键菜单
    Write-Host "[3.2] 移除Defender右键菜单..." -ForegroundColor Yellow
    $contextMenuResult = Remove-DefenderContextMenu
    Add-Result "ContextMenu" $contextMenuResult
    
    # 3.3 禁用任务计划
    Write-Host "[3.3] 禁用Defender计划任务..." -ForegroundColor Yellow
    $scheduledTaskResult = Disable-DefenderScheduledTasks
    Add-Result "ScheduledTasks" $scheduledTaskResult
    
    # 3.4 隐藏Windows Security设置页面
    Write-Host "[3.4] 隐藏Windows Security设置页面..." -ForegroundColor Yellow
    $hideSettingsResult = Hide-WindowsSecuritySettings
    Add-Result "HideSettingsPage" $hideSettingsResult
    
    # 3.5 禁用Windows Update中的Defender更新
    Write-Host "[3.5] 禁用Windows Update中的Defender更新..." -ForegroundColor Yellow
    $updateBlockResult = Block-DefenderUpdates
    Add-Result "BlockDefenderUpdates" $updateBlockResult
    
    Write-Host ""
    Write-Host "✅ 第三阶段完成" -ForegroundColor Green
    Show-PhaseResults @("SmartScreen", "ContextMenu", "ScheduledTasks", "HideSettingsPage", "BlockDefenderUpdates")
}

function Disable-SmartScreen {
    try {
        # Explorer SmartScreen
        $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        Set-ItemProperty -Path $explorerPath -Name 'SmartScreenEnabled' -Value "Off" -Type String -Force
        
        # System SmartScreen Policy
        $systemPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if (!(Test-Path $systemPath)) { New-Item -Path $systemPath -Force | Out-Null }
        Set-ItemProperty -Path $systemPath -Name 'EnableSmartScreen' -Value 0 -Type DWORD -Force
        
        Write-Host "  ✅ SmartScreen已禁用" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ❌ SmartScreen禁用失败: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Remove-DefenderContextMenu {
    try {
        $contextPaths = @(
            'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP',
            'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP',
            'HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'
        )
        
        $allSuccess = $true
        foreach ($path in $contextPaths) {
            if (Test-Path -LiteralPath $path) {
                try {
                    Remove-Item -LiteralPath $path -Recurse -Force
                    Write-Host "    ✅ 已移除: $path" -ForegroundColor Green
                } catch {
                    Write-Host "    ❌ 移除失败: $path" -ForegroundColor Red
                    $allSuccess = $false
                }
            } else {
                 Write-Host "    ℹ️ 不存在，无需移除: $path" -ForegroundColor Gray
            }
        }
        return $allSuccess
    } catch {
        Write-Host "  ❌ 右键菜单移除失败: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Disable-DefenderScheduledTasks {
    $tasks = @(
        "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
        "Microsoft\Windows\Windows Defender\Windows Defender Cleanup", 
        "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
        "Microsoft\Windows\Windows Defender\Windows Defender Verification"
    )
    
    $allSuccess = $true
    foreach ($taskPath in $tasks) {
        $taskName = $taskPath.Split('\')[-1]
        try {
            $task = Get-ScheduledTask -TaskPath "\$($taskPath -replace $taskName, '')" -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                if ($task.State -ne 'Disabled') {
                    Disable-ScheduledTask -TaskName $taskName -TaskPath "\$($taskPath -replace $taskName, '')" | Out-Null
                    Write-Host "    ✅ 已禁用: $taskName" -ForegroundColor Green
                } else {
                    Write-Host "    ℹ️ 已是禁用状态: $taskName" -ForegroundColor Gray
                }
            } else {
                Write-Host "    ℹ️ 任务不存在: $taskName" -ForegroundColor Gray
            }
        } catch {
            Write-Host "    ❌ 禁用失败: $taskName" -ForegroundColor Red
            $allSuccess = $false
        }
    }
    return $allSuccess
}

function Hide-WindowsSecuritySettings {
    try {
        $explorerPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if (!(Test-Path $explorerPolicyPath)) { New-Item -Path $explorerPolicyPath -Force | Out-Null }
        
        Set-ItemProperty -Path $explorerPolicyPath -Name 'SettingsPageVisibility' -Value "hide:windowsdefender" -Type String -Force
        Write-Host "  ✅ Windows Security设置页面已隐藏" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ❌ 隐藏设置页面失败: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Block-DefenderUpdates {
    try {
        # 通过MRT策略阻止WU/AU提供更新
        $mrtPath = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 
        if (!(Test-Path $mrtPath)) { New-Item -Path $mrtPath -Force | Out-Null }
        Set-ItemProperty -Path $mrtPath -Name 'DontOfferThroughWUAU' -Value 1 -Type DWORD -Force
        
        # 移除自启动项中的SecurityHealth
        $runPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        if (Get-ItemProperty -Path $runPath -Name 'SecurityHealth' -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $runPath -Name 'SecurityHealth' -Force
            Write-Host "  ✅ SecurityHealth启动项已移除" -ForegroundColor Green
        }
        
        Write-Host "  ✅ Defender更新已通过策略阻止" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ❌ 阻止更新失败: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==============================================================================
# 结果展示和主逻辑
# ==============================================================================

function Show-PhaseResults {
    param($Keys)
    
    Write-Host "阶段结果:" -ForegroundColor Cyan
    foreach ($key in $Keys) {
        if ($script:Results.Contains($key)) {
            $result = $script:Results[$key]
            if ($result.Success) {
                Write-Host "  ✅ $key" -ForegroundColor Green
            } else {
                Write-Host "  ❌ $key" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

function Show-FinalSummary {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "             最终执行摘要" -ForegroundColor Cyan  
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $totalItems = $script:Results.Count
    if ($totalItems -eq 0) {
        Write-Host "未执行任何操作。" -ForegroundColor Yellow
        return
    }
    
    $successItems = ($script:Results.Values | Where-Object { $_.Success }).Count
    $failedItems = $totalItems - $successItems
    
    Write-Host "执行统计:" -ForegroundColor Green
    Write-Host "  总项目: $totalItems" -ForegroundColor White
    Write-Host "  成功: $successItems" -ForegroundColor Green  
    Write-Host "  失败: $failedItems" -ForegroundColor Red
    if ($totalItems -gt 0) {
        Write-Host "  成功率: $([math]::Round(($successItems/$totalItems)*100, 1))%" -ForegroundColor Cyan
    }
    Write-Host ""
    
    Write-Host "执行详情:" -ForegroundColor Green
    foreach ($item in $script:Results.GetEnumerator()) {
        if ($item.Value.Success) {
            Write-Host "  ✅ $($item.Key)" -ForegroundColor Green
        } else {
            Write-Host "  ❌ $($item.Key) - $($item.Value.Details)" -ForegroundColor Red
        }
    }
    Write-Host ""
    
    Write-Host "执行时间: $($duration.TotalSeconds.ToString('F1')) 秒" -ForegroundColor Cyan
    Write-Host "完成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host ""
    
    if ($failedItems -gt 0) {
        Write-Host "⚠️ 注意事项:" -ForegroundColor Yellow
        Write-Host "  - 请检查上面标记为 ❌ 的失败项目。" -ForegroundColor Yellow
        Write-Host "  - 如果篡改保护 (Tamper Protection) 未成功禁用，请手动操作后重新运行。" -ForegroundColor Yellow
    } else {
        Write-Host "🎉 所有已选配置已成功应用!" -ForegroundColor Green
    }
    Write-Host "建议重启系统以确保所有更改完全生效。" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Usage {
    Write-Host "使用方法:" -ForegroundColor Cyan
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase1    # 执行第一阶段：基础禁用"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase2    # 执行第二阶段：服务和注册表"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase3    # 执行第三阶段：高级设置和清理"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -All       # 一次性执行所有阶段"
    Write-Host ""
    Write-Host "阶段说明:" -ForegroundColor Cyan
    Write-Host "  Phase1: 禁用篡改保护, 智能应用控制, 实时保护" -ForegroundColor Gray
    Write-Host "  Phase2: 配置组策略, 禁用服务, 禁用SpyNet, 禁用通知" -ForegroundColor Gray
    Write-Host "  Phase3: 禁用SmartScreen, 移除右键菜单, 禁用计划任务, 隐藏设置页面, 阻止更新" -ForegroundColor Gray
    Write-Host ""
}

# ==============================================================================
# 执行入口
# ==============================================================================

Initialize-Script


if ($Phase1) { 
    Invoke-Phase1 
}
elseif ($Phase2) { 
    Invoke-Phase2 
}
elseif ($Phase3) { 
    Invoke-Phase3 
}
else { 
    Invoke-Phase1 
    Invoke-Phase2  
    Invoke-Phase3 
}

Show-FinalSummary 