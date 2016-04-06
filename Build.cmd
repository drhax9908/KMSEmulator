@echo off
setlocal EnableExtensions
setlocal EnableDelayedExpansion
pushd "%~dp0"
reg.exe query "hklm\software\microsoft\Windows NT\currentversion" /v buildlabex | find /i "amd64" >nul 2>&1
if %errorlevel% equ 0 set xOS=x64
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set xOS=x86

if "%xOS%"=="x86" (
cd /D "%PROGRAMFILES%\MSBuild\12.0\Bin\
) ELSE (
cd /D "%PROGRAMFILES(x86)%\MSBuild\12.0\Bin\
)

REM Build x86 Release
MSBuild "%~dp0KMSEmulator.sln" /p:configuration="Release" /p:platform="Win32"

REM Build x64 Release
MSBuild "%~dp0KMSEmulator.sln" /p:configuration="Release" /p:platform="x64"

REM Clean Solution of Junk Files
call "%~dp0Clean.cmd"