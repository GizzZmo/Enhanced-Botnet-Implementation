@echo off
REM Setup script for Enhanced Botnet Implementation (Windows)

echo ==========================================
echo Enhanced Botnet Implementation - Setup
echo Educational/Research Use Only
echo ==========================================
echo.

REM Check Python version
echo Checking Python version...
python --version 2>NUL
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8 or higher.
    exit /b 1
)
echo.

REM Create virtual environment
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    echo Virtual environment created
) else (
    echo Virtual environment already exists
)
echo.

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo Error: Failed to activate virtual environment
    exit /b 1
)
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip --quiet
echo pip upgraded
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt --quiet
echo Dependencies installed
echo.

REM Generate encryption key if needed
echo Checking encryption key...
if "%BOTNET_ENCRYPTION_KEY%"=="" (
    for /f %%i in ('python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"') do set encryption_key=%%i
    echo Generated encryption key: %encryption_key%
    echo.
    echo Add this to your environment:
    echo   set BOTNET_ENCRYPTION_KEY=%encryption_key%
    echo.
    echo Or create a .env file with this key
) else (
    echo Encryption key already configured
)
echo.

REM Create example config if it doesn't exist
if not exist ".env" (
    if exist ".env.example" (
        echo Creating .env from example...
        copy .env.example .env
        echo .env file created (please customize it)
        echo.
    )
)

echo ==========================================
echo Setup Complete!
echo ==========================================
echo.
echo Quick Start:
echo   1. Activate virtual environment:
echo      venv\Scripts\activate.bat
echo.
echo   2. Run the launcher:
echo      python launch.py
echo.
echo   3. Or run directly:
echo      python botnet_controller.py --help
echo      python botnet_server_enhanced.py --help
echo.
echo For more information, see README.md
echo ==========================================
pause
