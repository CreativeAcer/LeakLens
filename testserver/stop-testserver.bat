@echo off
chcp 65001 >nul

set RUNTIME=
where docker >nul 2>&1 && set RUNTIME=docker
if "%RUNTIME%"=="" (
    where podman >nul 2>&1 && set RUNTIME=podman
)

if "%RUNTIME%"=="" (
    echo  [ERROR] Neither Docker nor Podman found.
    pause
    exit /b 1
)

echo  [*] Stopping test server...
%RUNTIME% rm -f leaklens-testserver

echo  [OK] Test server stopped.
pause
