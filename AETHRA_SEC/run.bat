@echo off
REM ============================================================
REM  AETHRA-SEC one-click starter for Windows
REM  Double-click this file to set up (first time) and launch.
REM ============================================================
title AETHRA-SEC Launcher
cd /d "%~dp0"

echo.
echo ==========================================================
echo    AETHRA-SEC - Unified Cybersecurity Monitoring Platform
echo ==========================================================
echo.

REM --- 1. Check that Python is installed -----------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed, or it was not added to PATH.
    echo.
    echo   Please install Python 3.12+ from https://www.python.org/downloads/
    echo   and make sure you TICK "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)
echo [OK] Python found:
python --version
echo.

REM --- 2. Create the .env config file on first run -------------------------
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [SETUP] Created a new .env configuration file.
        echo.
        echo   IMPORTANT: Open the file ".env" in Notepad and set your MySQL
        echo   username and password ^(AETHRA_DB_USER / AETHRA_DB_PASSWORD^),
        echo   then run this launcher again.
        echo.
        pause
        exit /b 0
    ) else (
        echo [WARN] No .env or .env.example found. The app may not connect to MySQL.
        echo.
    )
)

REM --- 3. Install Python packages the first time ---------------------------
if not exist ".deps_installed" (
    echo [SETUP] Installing required Python packages ^(first run only^)...
    echo         This may take a minute or two.
    echo.
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Package installation failed. Check your internet connection
        echo         and try running this launcher again.
        echo.
        pause
        exit /b 1
    )
    echo installed > ".deps_installed"
    echo.
    echo [OK] Packages installed.
    echo.
)

REM --- 4. Launch the application -------------------------------------------
echo [LAUNCH] Starting AETHRA-SEC...
echo          ^(Log in with:  admin  /  Admin@123  - change it after first login^)
echo.
python main.py
set EXITCODE=%errorlevel%

if not "%EXITCODE%"=="0" (
    echo.
    echo [ERROR] AETHRA-SEC exited with an error ^(code %EXITCODE%^).
    echo         See the file  logs\files\errors.log  for details.
    echo.
    pause
)
exit /b %EXITCODE%
