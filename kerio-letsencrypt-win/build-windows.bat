@echo off
setlocal
title Build KerioCertManager.exe (Windows x64 GUI)
echo Building standalone Windows x64 GUI executable KerioCertManager.exe...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-H=windowsgui -s -w" -o KerioCertManager.exe .
if %errorLevel% neq 0 (
    echo [ERROR] Build failed! Ensure Go 1.22+ is installed.
    exit /b 1
)
echo [OK] Successfully built KerioCertManager.exe!
endlocal
