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
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains emoji characters
) else if "%LANG_ID%"=="0404" (
    echo System Language: Chinese Traditional ^(Taiwan^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains emoji characters
) else if "%LANG_ID%"=="0409" (
    echo System Language: English ^(United States^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains emoji characters
) else (
    echo System Language: Other ^(ID: %LANG_ID%^)
    echo PowerShell Script Encoding: UTF-8 ^(65001^) - Contains emoji characters
)

:: Set console encoding - PowerShell script contains UTF-8 characters (emojis)
:: We need UTF-8 for proper display regardless of system language
echo Status: PowerShell script contains UTF-8 characters, setting console to UTF-8
echo Changing console encoding to UTF-8 for proper emoji display...
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
title Windows Defender Disable Tool

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

REM Execute the PowerShell script
echo.
echo ==========================================================
echo  Running Disable-Windows-Defender.ps1
echo ==========================================================
echo.

:: Get current encoding for PowerShell execution
for /f "tokens=2 delims=:" %%i in ('chcp') do set CURRENT_EXEC_CP=%%i
set CURRENT_EXEC_CP=!CURRENT_EXEC_CP: =!

:: Execute PowerShell script with UTF-8 encoding to handle emoji characters
echo Executing PowerShell script with UTF-8 encoding for proper character display...
echo Setting PowerShell execution policy to RemoteSigned...
chcp 65001 >nul 2>&1
powershell.exe -NoProfile -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; & '.\Disable-Windows-Defender.ps1'}"

echo.
echo ==========================================================
echo  Script execution has finished.
echo ==========================================================
echo.
pause
exit