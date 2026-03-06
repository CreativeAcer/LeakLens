@echo off
setlocal enabledelayedexpansion

REM Relaunch with cmd /k so the window stays open no matter what happens.
if not defined LEAKLENS_STARTED (
    set LEAKLENS_STARTED=1
    cmd /k ""%~f0""
    exit /b
)

REM Set UTF-8 console so any subprocess output does not corrupt cmd parsing
chcp 65001 >nul

title LeakLens - Test File Server
echo.
echo  =========================================================
echo   LeakLens - Test File Server
echo   Samba share with intentionally unsafe files for testing
echo  =========================================================
echo.

REM Check for Docker or Podman
set RUNTIME=
where docker >nul 2>&1
if !ERRORLEVEL! EQU 0 set RUNTIME=docker
if not defined RUNTIME (
    where podman >nul 2>&1
    if !ERRORLEVEL! EQU 0 set RUNTIME=podman
)
if not defined RUNTIME (
    echo  [ERROR] Neither Docker nor Podman found in PATH.
    echo  Install Docker Desktop: https://www.docker.com/products/docker-desktop
    echo  or Podman Desktop:      https://podman.io
    goto :fail
)
echo  [OK] Using !RUNTIME!

REM Build image
echo.
echo  [*] Building test server image...
!RUNTIME! build -t leaklens-testserver "%~dp0"
if !ERRORLEVEL! NEQ 0 (
    echo.
    echo  [ERROR] Build failed.
    goto :fail
)
echo  [OK] Image built

REM Stop existing container if running
!RUNTIME! rm -f leaklens-testserver >nul 2>&1

REM Start container
echo.
echo  [*] Starting test file server...
!RUNTIME! run -d --name leaklens-testserver -p 4445:4445 leaklens-testserver
if !ERRORLEVEL! NEQ 0 (
    echo.
    echo  [ERROR] Failed to start container.
    goto :fail
)

echo.
echo  ---------------------------------------------------------
echo   Test server running on port 4445
echo.
echo   In LeakLens, open the SMB modal and enter:
echo     Host: 127.0.0.1:4445
echo     Leave username and password blank
echo   Then click Discover Shares and select testshare.
echo.
echo   Run stop-testserver.bat to shut it down.
echo  ---------------------------------------------------------
goto :done

:fail
echo.
echo  =========================================================
echo   Startup failed. Read the output above for details.
echo  =========================================================

:done
echo.
echo  Press any key to close this window...
pause >nul
exit
