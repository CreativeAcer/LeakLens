@echo off
title LeakLens - Test File Server
chcp 65001 >nul

echo.
echo  =========================================================
echo   LeakLens - Test File Server
echo   Samba share with intentionally unsafe files for testing
echo  =========================================================
echo.

:: --- Check Docker or Podman --------------------------------------------------
set RUNTIME=
where docker >nul 2>&1 && set RUNTIME=docker
if "%RUNTIME%"=="" (
    where podman >nul 2>&1 && set RUNTIME=podman
)

if "%RUNTIME%"=="" (
    echo  [ERROR] Neither Docker nor Podman found in PATH.
    echo  Install Docker Desktop: https://www.docker.com/products/docker-desktop
    echo  or Podman Desktop:      https://podman.io
    echo.
    pause
    exit /b 1
)

echo  [OK] Using %RUNTIME%

:: --- Build image -------------------------------------------------------------
echo.
echo  [*] Building test server image...
%RUNTIME% build -t leaklens-testserver "%~dp0testserver"
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Build failed.
    pause
    exit /b 1
)
echo  [OK] Image built

:: --- Stop existing container if running -------------------------------------
%RUNTIME% rm -f leaklens-testserver >nul 2>&1

:: --- Start container ---------------------------------------------------------
echo.
echo  [*] Starting test file server...
%RUNTIME% run -d ^
    --name leaklens-testserver ^
    -p 4445:4445 ^
    leaklens-testserver

if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Failed to start container.
    pause
    exit /b 1
)

echo.
echo  ---------------------------------------------------------
echo   Test server running on port 4445!
echo.
echo   Mount the share first, then scan the mapped drive:
echo.
echo     net use Z: \\127.0.0.1\testshare /user:guest "" ^
echo       /p:no ^/port:4445
echo.
echo   Then point LeakLens at:  Z:\
echo.
echo   Run stop-testserver.bat to shut it down.
echo  ---------------------------------------------------------
echo.
pause
