@echo off
title LeakLens
chcp 65001 >nul

echo.
echo  =========================================================
echo   LeakLens - Credential Exposure Scanner
echo  =========================================================
echo.

:: --- Check Node.js -----------------------------------------------------------
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Node.js is not installed or not in PATH.
    echo.
    echo  Please install Node.js from https://nodejs.org
    echo  Download the LTS version, run the installer, then try again.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('node -v') do set NODE_VER=%%v
echo  [OK] Node.js %NODE_VER% found

:: --- Check PowerShell --------------------------------------------------------
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] PowerShell is not available in PATH.
    echo.
    pause
    exit /b 1
)
echo  [OK] PowerShell found

:: --- Install dependencies if needed ------------------------------------------
if not exist "backend\node_modules" (
    echo.
    echo  [*] Installing backend dependencies...
    cd backend
    call npm install --silent
    cd ..
    echo  [OK] Dependencies installed
) else (
    echo  [OK] Dependencies already installed
)

:: --- Create reports directory -------------------------------------------------
if not exist "reports" mkdir reports

:: --- Start backend ------------------------------------------------------------
echo.
echo  [*] Starting backend on http://localhost:3000
echo.
start "LeakLens Backend" /min cmd /c "cd backend && node server.js"

:: Wait for backend to be ready
timeout /t 2 /nobreak >nul

:: --- Open browser -------------------------------------------------------------
echo  [*] Opening browser...
start "" "http://localhost:3000"

echo.
echo  ---------------------------------------------------------
echo   LeakLens is running at http://localhost:3000
echo   Close this window to stop the server.
echo  ---------------------------------------------------------
echo.

:: Keep window open / show backend logs
cd backend
node server.js
