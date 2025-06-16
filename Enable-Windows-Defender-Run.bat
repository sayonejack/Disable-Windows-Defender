@echo off
setlocal enabledelayedexpansion
:: ==========================================================
:: System Encoding Detection and Console Setup
:: ==========================================================

:: Get current system code page
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_CP=%%i
set CURRENT_CP=%CURRENT_CP: =%

:: Display current encoding information
echo ==========================================================
echo  System Encoding Information
echo ==========================================================
echo Current Console Code Page: %CURRENT_CP%

:: Determine system language and set optimal encoding for PowerShell script
for /f "tokens=3" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language" /v InstallLanguage 2^>nul') do set LANG_ID=%%i
if "%LANG_ID%"=="0804" (
    echo System Language: Chinese Simplified ^(China^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains text symbols
) else if "%LANG_ID%"=="0404" (
    echo System Language: Chinese Traditional ^(Taiwan^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains text symbols
) else if "%LANG_ID%"=="0409" (
    echo System Language: English ^(United States^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains text symbols
) else (
    echo System Language: Other ^(ID: %LANG_ID%^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains text symbols
)

:: Set console encoding - PowerShell script contains UTF-8 characters (text symbols)
:: We need UTF-8 for proper display regardless of system language
echo Status: PowerShell script contains UTF-8 characters, setting console to UTF-8
echo Changing console encoding to UTF-8 for proper symbol display...
chcp 65001 >nul 2>&1
if !errorlevel! equ 0 (
    echo Success: Console encoding set to UTF-8
) else (
    echo Warning: Failed to change console encoding to UTF-8
    echo The PowerShell script will handle encoding internally
)

:: Display final encoding status
for /f "tokens=2 delims=:" %%i in ('chcp') do set FINAL_CP=%%i
set FINAL_CP=!FINAL_CP: =!
echo Final Console Code Page: !FINAL_CP!
echo ==========================================================
echo.

:: Set title after encoding setup
title Windows Defender Enable Tool

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    cd /d "%~dp0"
:--------------------------------------

echo ========================================
echo    Windows Defender Enable Tool
echo ========================================
echo.
echo This tool will enable all settings disabled by Disable-Windows-Defender.ps1
echo.

:MENU
echo Please select enable option:
echo [1] Enable Basic Functions (Real-time Protection, Clear Smart App Control, Tamper Protection)
echo [2] Enable Services and Registry (Group Policy, Services, SpyNet, Notifications)
echo [3] Enable Advanced Settings (SmartScreen, Scheduled Tasks, Settings Page, etc.)
echo [4] Full Enable (Recommended - Enable all settings) [DEFAULT]
echo [0] Exit
echo.
set /p choice=Please enter option (1-4, 0=Exit, Enter=Full Enable): 

if "%choice%"=="" goto ALL
if "%choice%"=="1" goto PHASE1
if "%choice%"=="2" goto PHASE2
if "%choice%"=="3" goto PHASE3
if "%choice%"=="4" goto ALL
if "%choice%"=="0" goto EXIT
echo Invalid selection, please try again
goto MENU

:PHASE1
echo.
echo ==========================================================
echo  Running Enable-Windows-Defender.ps1 -Phase1
echo ==========================================================
echo.
echo Executing Phase 1 enable...
:: Get current encoding for PowerShell execution
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_EXEC_CP=%%i
set CURRENT_EXEC_CP=!CURRENT_EXEC_CP: =!

:: Execute PowerShell script with UTF-8 encoding to handle text symbols
echo Executing PowerShell script with UTF-8 encoding for proper character display...
chcp 65001 >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; & '.\Enable-Windows-Defender.ps1' -Phase1}"
goto END

:PHASE2
echo.
echo ==========================================================
echo  Running Enable-Windows-Defender.ps1 -Phase2
echo ==========================================================
echo.
echo Executing Phase 2 enable...
:: Get current encoding for PowerShell execution
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_EXEC_CP=%%i
set CURRENT_EXEC_CP=!CURRENT_EXEC_CP: =!

:: Execute PowerShell script with UTF-8 encoding to handle text symbols
echo Executing PowerShell script with UTF-8 encoding for proper character display...
chcp 65001 >nul 2>&1
powershell.exe -NoProfile -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; & '.\Enable-Windows-Defender.ps1' -Phase2}"
goto END

:PHASE3
echo.
echo ==========================================================
echo  Running Enable-Windows-Defender.ps1 -Phase3
echo ==========================================================
echo.
echo Executing Phase 3 enable...
:: Get current encoding for PowerShell execution
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_EXEC_CP=%%i
set CURRENT_EXEC_CP=!CURRENT_EXEC_CP: =!

:: Execute PowerShell script with UTF-8 encoding to handle text symbols
echo Executing PowerShell script with UTF-8 encoding for proper character display...
chcp 65001 >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; & '.\Enable-Windows-Defender.ps1' -Phase3}"
goto END

:ALL
echo.
echo ==========================================================
echo  Running Enable-Windows-Defender.ps1 (All Phases)
echo ==========================================================
echo.
echo Executing full enable...
:: Get current encoding for PowerShell execution
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_EXEC_CP=%%i
set CURRENT_EXEC_CP=!CURRENT_EXEC_CP: =!

:: Execute PowerShell script with UTF-8 encoding to handle text symbols
echo Executing PowerShell script with UTF-8 encoding for proper character display...
chcp 65001 >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; & '.\Enable-Windows-Defender.ps1'}"
goto END

:END
echo.
echo ==========================================================
echo  Script execution has finished.
echo ==========================================================
echo.
echo Enable operation completed!
echo It is recommended to restart the system to ensure all changes take effect.
echo.
pause
goto MENU

:EXIT
echo.
echo Thank you for using Windows Defender Enable Tool!
echo.
pause
exit /b 0
