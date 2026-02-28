@echo off
title LeakLens
chcp 65001 >nul

echo.
echo  =========================================================
echo   LeakLens - Credential Exposure Scanner
echo  =========================================================
echo.

:: --- Check Python -------------------------------------------------------------
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Please install Python 3.11+ from https://www.python.org
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version') do set PY_VER=%%v
echo  [OK] %PY_VER% found

:: --- Install dependencies -----------------------------------------------------
echo.
echo  [*] Installing dependencies (flask, smbprotocol)...
python -m pip install -r requirements.txt -q
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] pip install failed.
    pause
    exit /b 1
)
echo  [OK] Dependencies ready

:: --- Create reports directory -------------------------------------------------
if not exist "reports" mkdir reports

:: --- Open browser after short delay -------------------------------------------
start /b cmd /c "timeout /t 2 /nobreak >nul && start "" http://localhost:3000"

:: --- Start server (blocking) --------------------------------------------------
echo.
echo  [*] Starting LeakLens at http://localhost:3000
echo      Press Ctrl+C to stop.
echo.
python leaklens.py
