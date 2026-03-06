@echo off
title LeakLens
chcp 65001 >nul
echo.
echo  =========================================================
echo   LeakLens - Credential Exposure Scanner
echo  =========================================================
echo.

:: --- Locate Python ─────────────────────────────────────────────────────────
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON=py
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set PYTHON=python
    ) else (
        echo  [ERROR] Python is not installed or not in PATH.
        echo.
        echo  Please install Python 3.11+ from https://www.python.org
        echo  Make sure to check "Add Python to PATH" during installation.
        echo.
        pause
        exit /b 1
    )
)

:: --- Check Python version (require 3.11+) ──────────────────────────────────
for /f "tokens=2 delims= " %%v in ('%PYTHON% --version 2^>^&1') do set PY_VER_FULL=%%v
for /f "tokens=1,2 delims=." %%a in ("%PY_VER_FULL%") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if %PY_MAJOR% LSS 3 (
    echo  [ERROR] Python 3.11 or higher is required. Found: %PY_VER_FULL%
    echo.
    pause
    exit /b 1
)
if %PY_MAJOR% EQU 3 if %PY_MINOR% LSS 11 (
    echo  [ERROR] Python 3.11 or higher is required. Found: %PY_VER_FULL%
    echo.
    pause
    exit /b 1
)
echo  [OK] Python %PY_VER_FULL% found

:: --- Ensure pip is available ────────────────────────────────────────────────
%PYTHON% -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [*] pip not found, bootstrapping...
    %PYTHON% -m ensurepip --upgrade >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo  [ERROR] Could not bootstrap pip. Please install pip manually.
        pause
        exit /b 1
    )
)

:: --- Install core dependencies ──────────────────────────────────────────────
echo.
echo  [*] Installing core dependencies...
%PYTHON% -m pip install -r requirements.txt --no-warn-script-location -q
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Failed to install core dependencies.
    echo  Try running manually: pip install -r requirements.txt
    pause
    exit /b 1
)
echo  [OK] Core dependencies ready

:: --- Install impacket (required for SMB share enumeration on Windows) ────────
echo.
echo  [*] Installing impacket for SMB share enumeration...
%PYTHON% -m pip install impacket --prefer-binary --no-warn-script-location -q
if %ERRORLEVEL% NEQ 0 (
    echo  [WARN] impacket could not be installed automatically.
    echo.
    echo  SMB share enumeration (Discover Shares button) will be unavailable.
    echo  Scanning a known UNC path (e.g. \\server\share) still works without it.
    echo.
    echo  To enable share enumeration later, run:
    echo    pip install impacket --prefer-binary
    echo.
    echo  Common cause on newer Python versions: no pre-built wheel available yet.
    echo  Check https://github.com/fortra/impacket for compatibility updates.
    echo.
    timeout /t 5 /nobreak >nul
) else (
    echo  [OK] impacket ready
)

:: --- Create reports directory ────────────────────────────────────────────────
if not exist "reports" mkdir reports

:: --- Open browser after short delay ─────────────────────────────────────────
start /b cmd /c "timeout /t 2 /nobreak >nul && start "" http://localhost:3000"

:: --- Start server (blocking) ─────────────────────────────────────────────────
echo.
echo  [*] Starting LeakLens at http://localhost:3000
echo      Press Ctrl+C to stop.
echo.
%PYTHON% leaklens.py
