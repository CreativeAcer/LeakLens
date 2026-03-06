@echo off
setlocal enabledelayedexpansion

REM -----------------------------------------------------------------------
REM When double-clicked, Windows runs: cmd /c start.bat  (/c closes on exit)
REM Relaunch with cmd /k so the window stays open no matter what happens.
REM LEAKLENS_STARTED prevents infinite relaunching.
REM -----------------------------------------------------------------------
if not defined LEAKLENS_STARTED (
    set LEAKLENS_STARTED=1
    cmd /k ""%~f0""
    exit /b
)

REM Set UTF-8 console so pip progress bar characters do not corrupt cmd parsing
chcp 65001 >nul

title LeakLens
echo.
echo  =========================================================
echo   LeakLens - Credential Exposure Scanner
echo  =========================================================
echo.

REM -----------------------------------------------------------------------
REM Locate Python
REM -----------------------------------------------------------------------
set PYTHON=
where py >nul 2>&1
if !ERRORLEVEL! EQU 0 set PYTHON=py
if not defined PYTHON (
    where python >nul 2>&1
    if !ERRORLEVEL! EQU 0 set PYTHON=python
)
if not defined PYTHON (
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Please install Python 3.11+ from https://www.python.org
    echo  Make sure to check "Add Python to PATH" during installation.
    goto :fail
)

REM -----------------------------------------------------------------------
REM Check Python version (3.11+)
REM -----------------------------------------------------------------------
for /f "tokens=2" %%v in ('!PYTHON! --version 2^>^&1') do set PY_VER_STR=%%v
for /f "tokens=1,2 delims=." %%a in ("!PY_VER_STR!") do (
    set /a PY_MAJ=%%a
    set /a PY_MIN=%%b
)
if !PY_MAJ! LSS 3 goto :python_old
if !PY_MAJ! EQU 3 if !PY_MIN! LSS 11 goto :python_old
goto :python_ok
:python_old
echo  [ERROR] Python 3.11 or higher is required. Found: !PY_VER_STR!
echo.
goto :fail
:python_ok
echo  [OK] Python !PY_VER_STR! found

REM -----------------------------------------------------------------------
REM Ensure pip is available
REM -----------------------------------------------------------------------
!PYTHON! -m pip --version >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo  [*] pip not found, bootstrapping...
    !PYTHON! -m ensurepip --upgrade
    if !ERRORLEVEL! NEQ 0 (
        echo.
        echo  [ERROR] Could not bootstrap pip. Please install pip manually.
        goto :fail
    )
)

REM -----------------------------------------------------------------------
REM Install core dependencies
REM -----------------------------------------------------------------------
echo.
echo  [*] Installing core dependencies...
!PYTHON! -m pip install -r requirements.txt --no-warn-script-location
set DEPS_RC=!ERRORLEVEL!
if !DEPS_RC! NEQ 0 goto :deps_fail
echo  [OK] Core dependencies ready
goto :deps_done
:deps_fail
echo.
echo  [ERROR] Failed to install core dependencies.
echo  Try running manually: pip install -r requirements.txt
goto :fail
:deps_done

REM -----------------------------------------------------------------------
REM Check impacket (optional - enables credential-based share enumeration)
REM
REM NOTE: impacket has no binary wheels on PyPI. Installing from source fails
REM on Windows because the source tarball contains filenames that Windows
REM rejects during extraction. We therefore only check if it is already
REM present (e.g. installed by the user separately) and do not attempt
REM an automatic install.
REM
REM Without impacket, share enumeration falls back to the built-in
REM net view command, which works for the current Windows session.
REM -----------------------------------------------------------------------
echo.
echo  [*] Checking impacket for SMB share enumeration...
!PYTHON! -c "import impacket" >nul 2>&1
if !ERRORLEVEL! EQU 0 goto :impacket_found
echo  [INFO] impacket not found - share enumeration will use built-in net use/net view.
echo  This supports username and password on all Windows versions with no extra install.
goto :impacket_done
:impacket_found
echo  [OK] impacket found - using impacket for share enumeration
:impacket_done

REM -----------------------------------------------------------------------
REM Create reports directory
REM -----------------------------------------------------------------------
if not exist "reports" mkdir reports

REM -----------------------------------------------------------------------
REM Open browser then start server
REM -----------------------------------------------------------------------
start /b cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:3000"
echo.
echo  [*] Starting LeakLens at http://localhost:3000
echo      Press Ctrl+C to stop.
echo.
!PYTHON! leaklens.py
set SERVER_RC=!ERRORLEVEL!
if !SERVER_RC! NEQ 0 goto :server_fail
goto :done
:server_fail
echo.
echo  [ERROR] LeakLens stopped unexpectedly (exit code !SERVER_RC!).
echo  Check the output above for details.
goto :fail

:fail
echo.
echo  =========================================================
echo   Startup failed. Read the output above for details.
echo  =========================================================
goto :done

:done
echo.
echo  Press any key to close this window...
pause >nul
exit
