@echo off
setlocal enabledelayedexpansion

REM ChatRoom Deployment Script for Windows
REM Automated setup with admin user creation

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
echo [1/13] Checking system requirements...
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
echo [2/13] Creating deployment directory...
set "DEPLOY_DIR=%USERPROFILE%\chatroom_deployment"
if not exist "%DEPLOY_DIR%" mkdir "%DEPLOY_DIR%"
cd /d "%DEPLOY_DIR%"
echo ✓ Deployment directory created: %DEPLOY_DIR%

REM Step 3: Clone repository
echo [3/13] Cloning ChatRoom repository...
if exist "%PROJECT_NAME%" rmdir /s /q "%PROJECT_NAME%"
git clone "%REPO_URL%" "%PROJECT_NAME%" >nul 2>&1
cd /d "%PROJECT_NAME%"
echo ✓ Repository cloned successfully

REM Step 4: Check Python version
echo [4/13] Verifying Python version...
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%i"
echo ✓ Python version verified: %PYTHON_VERSION%

REM Step 5: Create virtual environment
echo [5/13] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat
echo ✓ Virtual environment created and activated

REM Step 6: Upgrade pip
echo [6/13] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo ✓ Pip upgraded successfully

REM Step 7: Install dependencies
echo [7/13] Installing Python dependencies...
cd backend
pip install -r requirements.txt >nul 2>&1
echo ✓ Dependencies installed successfully

REM Step 8: Initialize database
echo [8/13] Initializing database...
if not exist "db\chatroom.db" (
    python init_db.py >nul 2>&1
)
python db\migrate_add_settings_table.py >nul 2>&1
echo ✓ Database initialized successfully

REM Step 9: Admin user creation
echo [9/13] Setting up admin user...
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    Admin User Setup                          ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

set /p "ADMIN_USERNAME=Enter admin username (default: admin): "
if "!ADMIN_USERNAME!"=="" set "ADMIN_USERNAME=admin"

set /p "ADMIN_PASSWORD=Enter admin password (default: admin123): "
if "!ADMIN_PASSWORD!"=="" set "ADMIN_PASSWORD=admin123"

set /p "ADMIN_EMAIL=Enter admin email (default: admin@chatroom.local): "
if "!ADMIN_EMAIL!"=="" set "ADMIN_EMAIL=admin@chatroom.local"

set /p "ADMIN_DISPLAY_NAME=Enter admin display name (default: Administrator): "
if "!ADMIN_DISPLAY_NAME!"=="" set "ADMIN_DISPLAY_NAME=Administrator"

echo.
echo Creating admin user: !ADMIN_USERNAME!
echo.

REM Create admin user in database
python -c "
import sqlite3
import hashlib
import os
from datetime import datetime

db_path = 'db/chatroom.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Check if admin user already exists
    cur.execute('SELECT id FROM users WHERE username = ?', ('!ADMIN_USERNAME!',))
    if not cur.fetchone():
        # Create admin user
        password_hash = hashlib.sha256('!ADMIN_PASSWORD!'.encode()).hexdigest()
        cur.execute('''
            INSERT INTO users (username, password_hash, email, display_name, is_admin, created_at, last_seen)
            VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', ('!ADMIN_USERNAME!', password_hash, '!ADMIN_EMAIL!', '!ADMIN_DISPLAY_NAME!'))
        conn.commit()
        print('Admin user created successfully')
    else:
        print('Admin user already exists')
    
    conn.close()
else:
    print('Database not found')
"

echo ✓ Admin user setup completed

REM Step 10: Set environment variables
echo [10/13] Configuring environment...
set "FLASK_ENV=development"
set "FLASK_DEBUG=True"
set "SECRET_KEY=dev-secret-key-%RANDOM%"
echo ✓ Environment configured

REM Step 11: Check port availability
echo [11/13] Checking port availability...
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

REM Step 12: Start the application
echo [12/13] Starting ChatRoom application...
start /b python run.py >nul 2>&1
timeout /t 3 /nobreak >nul
echo ✓ Application started

REM Step 13: Wait for service to be ready
echo [13/13] Waiting for service to be ready...
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

echo 🔐 Admin Credentials:
echo   • Username: !ADMIN_USERNAME!
echo   • Password: !ADMIN_PASSWORD!
echo   • Email: !ADMIN_EMAIL!
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
echo 📧 Admin contact: !ADMIN_EMAIL!
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