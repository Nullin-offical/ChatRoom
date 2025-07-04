@echo off
setlocal enabledelayedexpansion

REM ChatRoom DevOps Deployment Script for Windows
REM Automatically deploys and shares ChatRoom application

set "REPO_URL=https://github.com/H0lwin/ChatRoom"
set "PROJECT_NAME=ChatRoom"
set "PORT=5000"
set "ADMIN_EMAIL=admin@chatroom.local"

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    ChatRoom Deployment                       ║
echo ║                    Automated Setup                           ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Step 1: Check system requirements
echo [1/12] Checking system requirements...
python --version >nul 2>&1
if errorlevel 1 (
    echo ✗ Python is not installed. Please install Python 3.8+ first.
    pause
    exit /b 1
)

git --version >nul 2>&1
if errorlevel 1 (
    echo ✗ Git is not installed. Please install Git first.
    pause
    exit /b 1
)

echo ✓ System requirements check passed

REM Step 2: Create deployment directory
echo [2/12] Creating deployment directory...
set "DEPLOY_DIR=%USERPROFILE%\chatroom_deployment"
if not exist "%DEPLOY_DIR%" mkdir "%DEPLOY_DIR%"
cd /d "%DEPLOY_DIR%"
echo ✓ Deployment directory created: %DEPLOY_DIR%

REM Step 3: Clone repository
echo [3/12] Cloning ChatRoom repository...
if exist "%PROJECT_NAME%" rmdir /s /q "%PROJECT_NAME%"
git clone "%REPO_URL%" "%PROJECT_NAME%" >nul 2>&1
cd /d "%PROJECT_NAME%"
echo ✓ Repository cloned successfully

REM Step 4: Check Python version
echo [4/12] Verifying Python version...
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%i"
echo ✓ Python version verified: %PYTHON_VERSION%

REM Step 5: Create virtual environment
echo [5/12] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat
echo ✓ Virtual environment created and activated

REM Step 6: Upgrade pip
echo [6/12] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo ✓ Pip upgraded successfully

REM Step 7: Install dependencies
echo [7/12] Installing Python dependencies...
cd backend
pip install -r requirements.txt >nul 2>&1
echo ✓ Dependencies installed successfully

REM Step 8: Initialize database
echo [8/12] Initializing database...
if not exist "db\chatroom.db" (
    python init_db.py >nul 2>&1
)
python db\migrate_add_settings_table.py >nul 2>&1
echo ✓ Database initialized successfully

REM Step 9: Set environment variables
echo [9/12] Configuring environment...
set "FLASK_ENV=development"
set "FLASK_DEBUG=True"
set "SECRET_KEY=dev-secret-key-%RANDOM%"
echo ✓ Environment configured

REM Step 10: Check port availability
echo [10/12] Checking port availability...
netstat -an | find ":%PORT% " >nul 2>&1
if not errorlevel 1 (
    echo ⚠ Port %PORT% is already in use. Trying alternative ports...
    for %%p in (5001 5002 5003 5004 5005) do (
        netstat -an | find ":%%p " >nul 2>&1
        if errorlevel 1 (
            set "PORT=%%p"
            echo ℹ Using alternative port: !PORT!
            goto :port_found
        )
    )
)
:port_found
echo ✓ Port %PORT% is available

REM Step 11: Start the application
echo [11/12] Starting ChatRoom application...
start /b python run.py >nul 2>&1
timeout /t 3 /nobreak >nul
echo ✓ Application started

REM Step 12: Wait for service to be ready
echo [12/12] Waiting for service to be ready...
timeout /t 5 /nobreak >nul
echo ✓ Service is ready and responding

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    DEPLOYMENT COMPLETE!                      ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Get local IP
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /i "IPv4"') do (
    set "LOCAL_IP=%%i"
    set "LOCAL_IP=!LOCAL_IP: =!"
    goto :ip_found
)
:ip_found

echo 📊 Deployment Information:
echo   • Local URL:     http://localhost:%PORT%
echo   • Network URL:   http://%LOCAL_IP%:%PORT%
echo   • Deployment:    %DEPLOY_DIR%\%PROJECT_NAME%
echo.

echo 🔐 Default Admin Credentials:
echo   • Username: admin
echo   • Password: admin123
echo.

echo 🌐 To share with others:
echo   1. Make sure your firewall allows connections on port %PORT%
echo   2. Share this URL: http://%LOCAL_IP%:%PORT%
echo   3. Users can register new accounts or use admin credentials
echo.

echo 🛠️  Management Commands:
echo   • Stop server:    taskkill /f /im python.exe
echo   • View logs:      type logs\chatroom.log
echo   • Restart:        Run this script again
echo.

echo 🎉 ChatRoom is now running and ready for use!
echo 📧 Admin contact: %ADMIN_EMAIL%
echo.

REM Open browser
start http://localhost:%PORT%

echo 💡 Press any key to stop the server
pause >nul

REM Cleanup
taskkill /f /im python.exe >nul 2>&1
echo.
echo ✓ Server stopped.
pause 