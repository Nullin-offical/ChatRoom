#!/bin/bash

# ChatRoom Secure Startup Script
# This script starts the ChatRoom application with security checks

set -e  # Exit on any error

echo "🚀 Starting ChatRoom Application with Security Features"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "backend/app.py" ]; then
    echo "❌ Error: Please run this script from the ChatRoom root directory"
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.8 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install/upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing dependencies..."
cd backend
pip install -r requirements.txt

# Check if database exists
if [ ! -f "db/chatroom.db" ]; then
    echo "🗄️  Initializing database..."
    python init_db.py
fi

# Run security tests
echo "🔒 Running security tests..."
if python security_test.py; then
    echo "✅ Security tests passed"
else
    echo "❌ Security tests failed! Please check the issues above."
    echo "Continuing anyway, but security features may not work properly."
fi

# Set environment variables for security
export FLASK_ENV=development
export FLASK_DEBUG=True

# Check for production environment
if [ "$1" = "production" ]; then
    echo "🏭 Starting in PRODUCTION mode"
    export FLASK_ENV=production
    export FLASK_DEBUG=False
    
    # Check for required production environment variables
    if [ -z "$SECRET_KEY" ]; then
        echo "❌ Error: SECRET_KEY environment variable is required for production!"
        echo "Please set it: export SECRET_KEY='your-secure-secret-key'"
        exit 1
    fi
    
    echo "✅ Production environment variables set"
else
    echo "🔧 Starting in DEVELOPMENT mode"
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Start the application
echo "🚀 Starting ChatRoom server..."
echo "📊 Security features enabled:"
echo "   - Rate limiting (60 messages/minute)"
echo "   - Spam protection (10-minute bans)"
echo "   - XSS prevention"
echo "   - Input sanitization"
echo "   - Security headers"
echo "   - Request filtering"
echo ""
echo "🌐 Server will be available at: http://localhost:5000"
echo "📝 Logs will be written to: logs/chatroom.log"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================================="

# Start the application with logging
python run.py 2>&1 | tee logs/chatroom.log 