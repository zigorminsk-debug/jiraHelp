@echo off
setlocal
title Build KerioCertManager.exe (Windows x64 GUI)
echo Building standalone Windows x64 GUI executable KerioCertManager.exe...
rem Встроенная инструкция: ui\FAQ.md обязан совпадать с корневым FAQ.md
copy /Y "..\FAQ.md" "ui\FAQ.md" >nul
if %errorLevel% neq 0 (
    echo [ERROR] FAQ.md not found — the built-in instruction would be stale.
    exit /b 1
)
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-H=windowsgui -s -w" -o KerioCertManager.exe .
if %errorLevel% neq 0 (
    echo [ERROR] Build failed! Ensure Go 1.22+ is installed.
    exit /b 1
)
echo [OK] Successfully built KerioCertManager.exe!
endlocal
