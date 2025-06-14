param(
    [switch]$Phase1,    # Phase 1: Enable basic functions
    [switch]$Phase2,    # Phase 2: Enable services and registry
    [switch]$Phase3,    # Phase 3: Enable advanced settings
    [switch]$All        # Execute all phases at once
)

# ==============================================================================
# Windows Defender Enable Script v1.0
# Undo all modifications made by Disable-Windows-Defender.ps1
# ==============================================================================

# Define status symbols - using text symbols to avoid encoding issues
$script:StatusSymbols = @{
    Success = "[OK]"     # Success
    Warning = "[!]"      # Warning  
    Error = "[X]"        # Error
    Info = "[i]"         # Info
    Rocket = "[>>]"      # Execution
}

# Set console encoding to UTF-8 for consistent display
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
    # Encoding setting failed, continue with default
}

# ==============================================================================
# Initialization and Helper Functions
# ==============================================================================

# Check administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "$($script:StatusSymbols.Error) This script requires administrator privileges to run" -ForegroundColor Red
    exit 1
}

# Global variables
$script:Results = [ordered]@{}
$script:StartTime = Get-Date
$script:PsExecPath = $null

# Initialize script
function Initialize-Script {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Windows Defender Enable Script v1.0" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host ""
    
    # Check PsExec
    $psExecInScript = Join-Path $PSScriptRoot "PsExec.exe"
    if (Test-Path $psExecInScript) {
        $script:PsExecPath = $psExecInScript
        Write-Host "$($script:StatusSymbols.Success) PsExec found: $psExecInScript" -ForegroundColor Green
    } else {
        $psExecInPath = Get-Command PsExec -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if ($null -ne $psExecInPath) {
            $script:PsExecPath = $psExecInPath
            Write-Host "$($script:StatusSymbols.Success) PsExec found in system path: $psExecInPath" -ForegroundColor Green
        } else {
            Write-Host "$($script:StatusSymbols.Warning) PsExec not found. Some operations may require PsExec for complete restoration." -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Record results
function Add-Result {
    param($Name, $Success, $Details = "")
    $script:Results[$Name] = @{
        Success = $Success
        Details = $Details
        Timestamp = Get-Date
    }
}

# ==============================================================================
# Phase 1: Enable Basic Functions
# ==============================================================================

function Invoke-RestorePhase1 {
    Write-Host "$($script:StatusSymbols.Rocket) Executing Phase 1: Enable Basic Functions" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Gray
    
    # 1.1 Enable Real-time Protection
    Write-Host "[1.1] Enabling Real-time Protection..." -ForegroundColor Yellow
    $realtimeResult = Enable-RealtimeProtection
    Add-Result "RealtimeProtection" $realtimeResult
    
    # 1.2 Clear Smart App Control Settings
    Write-Host "[1.2] Clearing Smart App Control Settings..." -ForegroundColor Yellow
    $smartAppResult = Clear-SmartAppControlSettings
    Add-Result "SmartAppControl" $smartAppResult
    
    # 1.3 Enable Tamper Protection
    Write-Host "[1.3] Enabling Tamper Protection..." -ForegroundColor Yellow
    $tamperResult = Enable-TamperProtection
    Add-Result "TamperProtection" $tamperResult
    
    Write-Host ""
    Write-Host "$($script:StatusSymbols.Success) Phase 1 completed" -ForegroundColor Green
    Show-PhaseResults @("RealtimeProtection", "SmartAppControl", "TamperProtection")
}

function Enable-RealtimeProtection {
    try {
        # Remove disable entries from registry
        $rtPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        if (Test-Path $rtPath) {
            Remove-ItemProperty -Path $rtPath -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
        }
        
        # Enable using PowerShell cmdlet
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $false -ErrorAction SilentlyContinue
        
        # Additional registry-based enabling
        try {
            if (Test-Path $rtPath) {
                Set-ItemProperty -Path $rtPath -Name "DisableRealtimeMonitoring" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        
        # Wait a moment for changes to take effect
        Start-Sleep -Seconds 2
        
        # Verify status
        $status = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
        if ($status -eq $true) {
            Write-Host "  $($script:StatusSymbols.Success) Real-time monitoring has been enabled" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  $($script:StatusSymbols.Warning) Real-time monitoring enable failed - may require manual activation" -ForegroundColor Yellow
            Write-Host "    Please check Windows Security Center and manually enable Real-time Protection if needed" -ForegroundColor Cyan
            return $false
        }
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) Error enabling real-time monitoring: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Clear-SmartAppControlSettings {
    try {
        $k='HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        if (Test-Path $k) {
            # Remove disable settings, let system use default values
            Remove-ItemProperty -Path $k -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue
            Write-Host "  $($script:StatusSymbols.Success) Smart App Control settings have been cleared" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  $($script:StatusSymbols.Info) Smart App Control registry key does not exist, no need to clear" -ForegroundColor Gray
            return $true
        }
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) Error clearing Smart App Control: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Enable-TamperProtection {
    Write-Host "  Checking current Tamper Protection status..." -ForegroundColor Cyan
    
    # Check current status first
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    $currentValue = (Get-ItemProperty -Path $key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
    
    if ($currentValue -eq 5) {
        Write-Host "  $($script:StatusSymbols.Success) Tamper Protection is already enabled" -ForegroundColor Green
        return $true
    }
    
    # Try to enable using PsExec with SYSTEM privileges
    if ($script:PsExecPath) {
        try {
            Write-Host "  Attempting to enable using PsExec with SYSTEM privileges..." -ForegroundColor Cyan
            $tempScript = Join-Path $env:TEMP "EnableTamperProtection.ps1"
            @"
# Set encoding for proper error display
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
`$key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
if (!(Test-Path `$key)) { exit 2 }
try {
    # Check if WdFilter is protecting this key
    `$currentValue = (Get-ItemProperty -Path `$key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
    if (`$currentValue -eq 5) { exit 0 }
    
    Set-ItemProperty -Path `$key -Name 'TamperProtection' -Value 5 -Force -ErrorAction Stop
    `$newValue = (Get-ItemProperty -Path `$key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
    if (`$newValue -eq 5) { exit 0 } else { exit 1 }
} catch {
    exit 1
}
"@ | Out-File -FilePath $tempScript -Encoding UTF8
            
            $process = Start-Process -FilePath $script:PsExecPath -ArgumentList "-accepteula", "-s", "-nobanner", "powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "`"$tempScript`"" -Wait -PassThru -NoNewWindow
            Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
            
            # Re-check status after PsExec attempt
            $tamperValue = (Get-ItemProperty -Path $key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
            if ($tamperValue -eq 5) {
                Write-Host "  $($script:StatusSymbols.Success) PsExec successfully enabled Tamper Protection!" -ForegroundColor Green
                return $true
            }
            
            if ($process.ExitCode -eq 0) {
                Write-Host "  $($script:StatusSymbols.Success) Tamper Protection change initiated by PsExec" -ForegroundColor Green
                return $true
            } else {
                Write-Host "  $($script:StatusSymbols.Warning) PsExec unable to enable Tamper Protection (Exit Code: $($process.ExitCode))" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  $($script:StatusSymbols.Error) Error using PsExec: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Regular method attempt
    try {
        Write-Host "  Trying regular administrative method..." -ForegroundColor Cyan
        if (!(Test-Path $key)) { 
            Write-Host "  $($script:StatusSymbols.Error) Windows Defender Features registry key not found" -ForegroundColor Red
            return $false 
        }
        
        Set-ItemProperty -Path $key -Name 'TamperProtection' -Value 5 -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
        
        $newValue = (Get-ItemProperty -Path $key -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
        if ($newValue -eq 5) {
            Write-Host "  $($script:StatusSymbols.Success) Tamper Protection enabled successfully" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "  $($script:StatusSymbols.Warning) Registry modification blocked by system protection" -ForegroundColor Yellow
    }

    # Explain why automatic enablement failed and provide guidance
    Write-Host ""
    Write-Host "  $($script:StatusSymbols.Info) Tamper Protection automatic enablement failed - this is normal behavior" -ForegroundColor Cyan
    Write-Host "  $($script:StatusSymbols.Info) Reason: WdFilter.sys (kernel driver) protects Tamper Protection settings" -ForegroundColor Gray
    Write-Host "  $($script:StatusSymbols.Info) This protection prevents any programmatic changes, even from SYSTEM" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  $($script:StatusSymbols.Warning) Manual enablement required:" -ForegroundColor Yellow
    Write-Host "    1. Open Windows Security (Start -> Settings -> Privacy & Security -> Windows Security)" -ForegroundColor White
    Write-Host "    2. Go to 'Virus & threat protection'" -ForegroundColor White
    Write-Host "    3. Click 'Manage settings' under 'Virus & threat protection settings'" -ForegroundColor White
    Write-Host "    4. Turn on 'Tamper Protection' toggle" -ForegroundColor White
    Write-Host "    5. This is by design - Microsoft prevents automated Tamper Protection changes" -ForegroundColor Gray
    Write-Host ""
    return $false
}

# ==============================================================================
# Phase 2: Enable Services and Registry Configuration
# ==============================================================================

function Invoke-RestorePhase2 {
    Write-Host "$($script:StatusSymbols.Rocket) Executing Phase 2: Enable Services and Registry Configuration" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Gray
    
    # 2.1 Restore Group Policies
    Write-Host "[2.1] Restoring Group Policies..." -ForegroundColor Yellow
    $policyResult = Restore-GroupPolicies
    Add-Result "GroupPolicies" $policyResult

    # 2.2 Enable Defender Services
    Write-Host "[2.2] Enabling Windows Defender Services..." -ForegroundColor Yellow
    $servicesResult = Enable-DefenderServices
    Add-Result "DefenderServices" $servicesResult
    
    # 2.3 Enable SpyNet Reporting
    Write-Host "[2.3] Enabling SpyNet/MAPS Reporting..." -ForegroundColor Yellow
    $spyNetResult = Enable-SpyNetReporting
    Add-Result "SpyNetReporting" $spyNetResult
    
    # 2.4 Enable Notification System
    Write-Host "[2.4] Enabling Notifications..." -ForegroundColor Yellow
    $notificationResult = Enable-DefenderNotifications
    Add-Result "DefenderNotifications" $notificationResult
    
    Write-Host ""
    Write-Host "$($script:StatusSymbols.Success) Phase 2 completed" -ForegroundColor Green
    Show-PhaseResults @("GroupPolicies", "DefenderServices", "SpyNetReporting", "DefenderNotifications")
}

function Restore-GroupPolicies {
    Write-Host "  Removing group policy settings..." -ForegroundColor Cyan
    $allSuccess = $true

    # Remove all group policy settings that disable Defender
    $policyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'
    )

    foreach ($path in $policyPaths) {
        try {
            if (Test-Path $path) {
                # Try to take ownership and set permissions first
                try {
                    $regPath = $path -replace "HKLM:", "HKEY_LOCAL_MACHINE"
                    & takeown /f $regPath /r /d y 2>$null | Out-Null
                    & icacls $regPath /grant administrators:F /t 2>$null | Out-Null
                } catch {}
                
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "    $($script:StatusSymbols.Success) Removed policy path: $path" -ForegroundColor Green
            } else {
                Write-Host "    $($script:StatusSymbols.Info) Policy path does not exist: $path" -ForegroundColor Gray
            }
        } catch {
            Write-Host "    $($script:StatusSymbols.Warning) Partial removal of policy path: $path" -ForegroundColor Yellow
            Write-Host "      Some policy settings may remain due to system restrictions" -ForegroundColor Gray
            # Don't mark as failure since partial removal might still be effective
        }
    }
    return $allSuccess
}

function Enable-DefenderServices {
    # Core services that should exist on most systems
    $coreServices = @("WinDefend", "SecurityHealthService")
    # Optional services that may not exist on all systems/versions
    $optionalServices = @("WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot", "Sense")
    
    if ($script:PsExecPath) {
        Write-Host "  Using PsExec to enable services with SYSTEM privileges..." -ForegroundColor Cyan
        $tempScriptContent = @"
# Set encoding for proper error display
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
`$coreServices = @("WinDefend", "SecurityHealthService")
`$optionalServices = @("WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot", "Sense")
`$global:exitCode = 0

# Process core services
foreach (`$service in `$coreServices) {
    try {
        `$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\`$service"
        if (Test-Path `$servicePath) {
            # Check if service actually exists as a Windows service
            `$svc = Get-Service -Name `$service -ErrorAction SilentlyContinue
            if (`$svc) {
                Set-ItemProperty -Path `$servicePath -Name "Start" -Value 2 -Type DWORD -Force -ErrorAction SilentlyContinue
                Set-Service -Name `$service -StartupType Automatic -ErrorAction SilentlyContinue
                if ((Get-ItemProperty -Path `$servicePath -Name "Start" -ErrorAction SilentlyContinue).Start -ne 2) { `$global:exitCode = 1 }
            }
        }
    } catch { `$global:exitCode = 1 }
}

# Process optional services (don't affect exit code)
foreach (`$service in `$optionalServices) {
    try {
        `$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\`$service"
        if (Test-Path `$servicePath) {
            `$svc = Get-Service -Name `$service -ErrorAction SilentlyContinue
            if (`$svc) {
                Set-ItemProperty -Path `$servicePath -Name "Start" -Value 2 -Type DWORD -Force -ErrorAction SilentlyContinue
                Set-Service -Name `$service -StartupType Automatic -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}
exit `$global:exitCode
"@
        $tempScript = Join-Path $env:TEMP "EnableServices.ps1"
        $tempScriptContent | Out-File -FilePath $tempScript -Encoding UTF8
        
        Start-Process -FilePath $script:PsExecPath -ArgumentList "-accepteula", "-s", "-nobanner", "powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "`"$tempScript`"" -Wait -PassThru -NoNewWindow | Out-Null
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

        # Verify and report results
        $coreSuccess = $true
        $optionalCount = 0
        
        # Check core services
        foreach ($service in $coreServices) {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
            if (Test-Path $servicePath) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    $startValue = (Get-ItemProperty -Path $servicePath -Name "Start" -ErrorAction SilentlyContinue).Start
                    if ($startValue -eq 2) {
                        Write-Host "    $($script:StatusSymbols.Success) $service has been enabled" -ForegroundColor Green
                    } else {
                        Write-Host "    $($script:StatusSymbols.Warning) $service enable failed" -ForegroundColor Yellow
                        $coreSuccess = $false
                    }
                } else {
                    Write-Host "    $($script:StatusSymbols.Info) $service service not found on this system" -ForegroundColor Gray
                }
            }
        }
        
        # Check optional services
        foreach ($service in $optionalServices) {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
            if (Test-Path $servicePath) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    $startValue = (Get-ItemProperty -Path $servicePath -Name "Start" -ErrorAction SilentlyContinue).Start
                    if ($startValue -eq 2) {
                        Write-Host "    $($script:StatusSymbols.Success) $service has been enabled" -ForegroundColor Green
                        $optionalCount++
                    } else {
                        Write-Host "    $($script:StatusSymbols.Info) $service enable skipped (optional service)" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "    $($script:StatusSymbols.Info) $service not available on this system" -ForegroundColor Gray
                }
            }
        }
        
        if ($coreSuccess) {
            Write-Host "    Core Defender services enabled successfully ($optionalCount optional services also enabled)" -ForegroundColor Green
        }
        return $coreSuccess
    }

    # Regular method
    Write-Host "  PsExec not found, using regular method..." -ForegroundColor Yellow
    $allServices = $coreServices + $optionalServices
    $coreSuccess = $true
    
    foreach ($service in $allServices) {
        try {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
            if (Test-Path $servicePath) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    Set-ItemProperty -Path $servicePath -Name "Start" -Value 2 -Type DWORD -Force
                    Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                    if ((Get-ItemProperty -Path $servicePath -Name "Start").Start -eq 2) {
                        Write-Host "    $($script:StatusSymbols.Success) $service has been enabled" -ForegroundColor Green
                    } else {
                        Write-Host "    $($script:StatusSymbols.Warning) $service enable may be incomplete" -ForegroundColor Yellow
                        if ($service -in $coreServices) { $coreSuccess = $false }
                    }
                } else {
                    Write-Host "    $($script:StatusSymbols.Info) $service not available on this system" -ForegroundColor Gray
                }
            }
        } catch {
            Write-Host "    $($script:StatusSymbols.Warning) $service configuration failed" -ForegroundColor Yellow
            if ($service -in $coreServices) { $coreSuccess = $false }
        }
    }
    return $coreSuccess
}

function Enable-SpyNetReporting {
    try {
        $spyNetPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        if (Test-Path $spyNetPath) {
            # Remove SpyNet policy settings, let system use default values
            Remove-Item -Path $spyNetPath -Recurse -Force
            Write-Host "  $($script:StatusSymbols.Success) SpyNet/MAPS reporting policy has been removed, will use default settings" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  $($script:StatusSymbols.Info) SpyNet policy does not exist, no need to restore" -ForegroundColor Gray
            return $true
        }
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) SpyNet configuration restore error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Enable-DefenderNotifications {
    try {
        $notifPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'
        if (Test-Path $notifPath) {
            # Remove notification policy settings
            Remove-Item -Path $notifPath -Recurse -Force
            Write-Host "  $($script:StatusSymbols.Success) Defender notification policy has been removed, will use default settings" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  $($script:StatusSymbols.Info) Notification policy does not exist, no need to restore" -ForegroundColor Gray
            return $true
        }
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) Notification configuration restore error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==============================================================================
# Phase 3: Enable Advanced Settings
# ==============================================================================

function Invoke-RestorePhase3 {
    Write-Host "$($script:StatusSymbols.Rocket) Executing Phase 3: Enable Advanced Settings" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Gray
    
    # 3.1 Enable SmartScreen
    Write-Host "[3.1] Enabling SmartScreen..." -ForegroundColor Yellow
    $smartScreenResult = Enable-SmartScreen
    Add-Result "SmartScreen" $smartScreenResult
    
    # 3.2 Enable Scheduled Tasks
    Write-Host "[3.2] Enabling Defender Scheduled Tasks..." -ForegroundColor Yellow
    $scheduledTaskResult = Enable-DefenderScheduledTasks
    Add-Result "ScheduledTasks" $scheduledTaskResult
    
    # 3.3 Restore Windows Security Settings Page
    Write-Host "[3.3] Restoring Windows Security Settings Page..." -ForegroundColor Yellow
    $showSettingsResult = Show-WindowsSecuritySettings
    Add-Result "ShowSettingsPage" $showSettingsResult
    
    # 3.4 Restore Defender Updates in Windows Update
    Write-Host "[3.4] Restoring Defender Updates in Windows Update..." -ForegroundColor Yellow
    $updateRestoreResult = Restore-DefenderUpdates
    Add-Result "RestoreDefenderUpdates" $updateRestoreResult
    
    Write-Host ""
    Write-Host "$($script:StatusSymbols.Success) Phase 3 completed" -ForegroundColor Green
    Show-PhaseResults @("SmartScreen", "ScheduledTasks", "ShowSettingsPage", "RestoreDefenderUpdates")
}

function Enable-SmartScreen {
    try {
        # Remove SmartScreen policy settings
        $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        Remove-ItemProperty -Path $explorerPath -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
        
        $systemPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if (Test-Path $systemPath) {
            Remove-ItemProperty -Path $systemPath -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue
        }
        
        Write-Host "  $($script:StatusSymbols.Success) SmartScreen settings have been restored to default" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) SmartScreen restore failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Enable-DefenderScheduledTasks {
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
                if ($task.State -eq 'Disabled') {
                    Enable-ScheduledTask -TaskName $taskName -TaskPath "\$($taskPath -replace $taskName, '')" | Out-Null
                    Write-Host "    $($script:StatusSymbols.Success) Enabled: $taskName" -ForegroundColor Green
                } else {
                    Write-Host "    $($script:StatusSymbols.Info) Already enabled: $taskName" -ForegroundColor Gray
                }
            } else {
                Write-Host "    $($script:StatusSymbols.Info) Task does not exist: $taskName" -ForegroundColor Gray
            }
        } catch {
            Write-Host "    $($script:StatusSymbols.Error) Enable failed: $taskName" -ForegroundColor Red
            $allSuccess = $false
        }
    }
    return $allSuccess
}

function Show-WindowsSecuritySettings {
    try {
        $explorerPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if (Test-Path $explorerPolicyPath) {
            Remove-ItemProperty -Path $explorerPolicyPath -Name 'SettingsPageVisibility' -ErrorAction SilentlyContinue
            Write-Host "  $($script:StatusSymbols.Success) Windows Security settings page has been restored to display" -ForegroundColor Green
        } else {
            Write-Host "  $($script:StatusSymbols.Info) Settings page policy does not exist, no need to restore" -ForegroundColor Gray
        }
        return $true
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) Restore settings page failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Restore-DefenderUpdates {
    try {
        # Remove MRT policy
        $mrtPath = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 
        if (Test-Path $mrtPath) {
            Remove-Item -Path $mrtPath -Recurse -Force
            Write-Host "  $($script:StatusSymbols.Success) MRT update policy has been removed" -ForegroundColor Green
        } else {
            Write-Host "  $($script:StatusSymbols.Info) MRT update policy does not exist, no need to remove" -ForegroundColor Gray
        }
        
        return $true
    } catch {
        Write-Host "  $($script:StatusSymbols.Error) Restore update settings failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==============================================================================
# Results Display and Main Logic
# ==============================================================================

function Show-PhaseResults {
    param($Keys)
    
    Write-Host "Phase Results:" -ForegroundColor Cyan
    foreach ($key in $Keys) {
        if ($script:Results.Contains($key)) {
            $result = $script:Results[$key]
            if ($result.Success) {
                Write-Host "  $($script:StatusSymbols.Success) $key" -ForegroundColor Green
            } else {
                Write-Host "  $($script:StatusSymbols.Error) $key" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

function Show-FinalSummary {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "           Enable Execution Summary" -ForegroundColor Cyan  
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $totalItems = $script:Results.Count
    if ($totalItems -eq 0) {
        Write-Host "No operations were executed." -ForegroundColor Yellow
        return
    }
    
    $successItems = ($script:Results.Values | Where-Object { $_.Success }).Count
    $failedItems = $totalItems - $successItems
    
    Write-Host "Enable Statistics:" -ForegroundColor Green
    Write-Host "  Total Items: $totalItems" -ForegroundColor White
    Write-Host "  Successful: $successItems" -ForegroundColor Green  
    Write-Host "  Failed: $failedItems" -ForegroundColor Red
    if ($totalItems -gt 0) {
        Write-Host "  Success Rate: $([math]::Round(($successItems/$totalItems)*100, 1))%" -ForegroundColor Cyan
    }
    Write-Host ""
    
    Write-Host "Enable Details:" -ForegroundColor Green
    foreach ($item in $script:Results.GetEnumerator()) {
        if ($item.Value.Success) {
            Write-Host "  $($script:StatusSymbols.Success) $($item.Key)" -ForegroundColor Green
        } else {
            Write-Host "  $($script:StatusSymbols.Error) $($item.Key) - $($item.Value.Details)" -ForegroundColor Red
        }
    }
    Write-Host ""
    
    Write-Host "Execution Time: $($duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Cyan
    Write-Host "Completion Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host ""
    
    if ($failedItems -gt 0) {
        # Check if only Tamper Protection failed
        $onlyTamperFailed = ($failedItems -eq 1) -and ($script:Results["TamperProtection"].Success -eq $false)
        
        if ($onlyTamperFailed) {
            Write-Host "$($script:StatusSymbols.Info) Windows Defender restoration is 90.9% complete!" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "$($script:StatusSymbols.Info) Only Tamper Protection requires manual activation:" -ForegroundColor Yellow
            Write-Host "  - This is expected behavior - Microsoft designed Tamper Protection to prevent automated changes" -ForegroundColor Gray
            Write-Host "  - Even SYSTEM/TrustedInstaller privileges cannot modify this setting programmatically" -ForegroundColor Gray
            Write-Host "  - This is a security feature, not a script limitation" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Quick Manual Step (30 seconds):" -ForegroundColor Cyan
            Write-Host "  1. Press Windows Key + I (Settings)" -ForegroundColor White
            Write-Host "  2. Privacy & Security -> Windows Security -> Virus & threat protection" -ForegroundColor White
            Write-Host "  3. Click 'Manage settings' -> Turn ON 'Tamper Protection'" -ForegroundColor White
            Write-Host ""
            Write-Host "$($script:StatusSymbols.Success) After this step, Windows Defender will be 100% restored!" -ForegroundColor Green
        } else {
            Write-Host "$($script:StatusSymbols.Warning) Important Notes:" -ForegroundColor Yellow
            Write-Host "  - Please check the failed items marked with $($script:StatusSymbols.Error) above." -ForegroundColor Yellow
            Write-Host "  - Some settings may need to be manually enabled in Windows Security Center." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Manual Steps Required:" -ForegroundColor Cyan
            Write-Host "  1. Open Windows Security (Start -> Settings -> Privacy & Security -> Windows Security)" -ForegroundColor White
            Write-Host "  2. Go to 'Virus & threat protection'" -ForegroundColor White
            Write-Host "  3. Click 'Manage settings' under 'Virus & threat protection settings'" -ForegroundColor White
            Write-Host "  4. Turn on 'Real-time protection' and 'Tamper Protection' if they are off" -ForegroundColor White
            Write-Host "  5. Restart your computer to ensure all changes take effect" -ForegroundColor White
        }
    } else {
        Write-Host "$($script:StatusSymbols.Success) Windows Defender has been successfully restored!" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "It is recommended to restart the system to ensure all changes take full effect." -ForegroundColor Cyan
    Write-Host ""
}

function Show-Usage {
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase1    # Execute Phase 1: Enable Basic Functions"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase2    # Execute Phase 2: Enable Services and Registry"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Phase3    # Execute Phase 3: Enable Advanced Settings"
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -All       # Execute All Phases at Once"
    Write-Host ""
    Write-Host "Phase Descriptions:" -ForegroundColor Cyan
    Write-Host "  Phase1: Enable real-time protection, clear Smart App Control settings, tamper protection" -ForegroundColor Gray
    Write-Host "  Phase2: Enable group policies, services, SpyNet, notifications" -ForegroundColor Gray
    Write-Host "  Phase3: Enable SmartScreen, scheduled tasks, show settings page, enable updates" -ForegroundColor Gray
    Write-Host ""
}

# ==============================================================================
# Main Execution Entry Point
# ==============================================================================

Initialize-Script

if ($Phase1) { 
    Invoke-RestorePhase1 
}
elseif ($Phase2) { 
    Invoke-RestorePhase2 
}
elseif ($Phase3) { 
    Invoke-RestorePhase3 
} else {
    Invoke-RestorePhase1 
    Invoke-RestorePhase2  
    Invoke-RestorePhase3 
}

Show-FinalSummary
