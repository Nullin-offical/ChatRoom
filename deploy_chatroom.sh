#!/bin/bash

# ChatRoom Deployment Script
# Automated setup with admin user creation

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/H0lwin/ChatRoom"
PROJECT_NAME="ChatRoom"
PORT=5000
ADMIN_EMAIL="admin@chatroom.local"

# Progress tracking
TOTAL_STEPS=13
CURRENT_STEP=0

# Function to show progress
show_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local filled=$((percentage / 2))
    local empty=$((50 - filled))
    
    printf "\r${BLUE}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} "
    printf "${GREEN}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "]${NC} ${percentage}%% "
    printf "${CYAN}%s${NC}" "$1"
    printf "%${empty}s" ""
}

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Function to get local IP
get_local_ip() {
    if command -v ipconfig >/dev/null 2>&1; then
        # Windows
        ipconfig | grep -A 5 "Ethernet adapter" | grep "IPv4" | head -1 | awk '{print $NF}'
    else
        # Linux/Mac
        hostname -I | awk '{print $1}'
    fi
}

# Function to check if port is available
check_port() {
    if command -v netstat >/dev/null 2>&1; then
        netstat -tuln | grep ":$1 " >/dev/null 2>&1
    else
        lsof -i :$1 >/dev/null 2>&1
    fi
}

# Function to wait for service
wait_for_service() {
    local url=$1
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    return 1
}

# Function to create admin user
create_admin_user() {
    local username=$1
    local password=$2
    local email=$3
    local display_name=$4
    
    python3 -c "
import sqlite3
import hashlib
import os
from datetime import datetime

db_path = 'db/chatroom.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Check if admin user already exists
    cur.execute('SELECT id FROM users WHERE username = ?', ('$username',))
    if not cur.fetchone():
        # Create admin user
        password_hash = hashlib.sha256('$password'.encode()).hexdigest()
        cur.execute('''
            INSERT INTO users (username, password_hash, email, display_name, is_admin, created_at, last_seen)
            VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', ('$username', password_hash, '$email', '$display_name'))
        conn.commit()
        print('Admin user created successfully')
    else:
        print('Admin user already exists')
    
    conn.close()
else:
    print('Database not found')
"
}

# Main deployment function
main() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ChatRoom Deployment                       ║"
    echo "║                    Automated Setup                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Step 1: Check system requirements
    show_progress "Checking system requirements..."
    if ! command -v python3 >/dev/null 2>&1; then
        print_error "Python 3 is not installed. Please install Python 3.8+ first."
        exit 1
    fi
    
    if ! command -v git >/dev/null 2>&1; then
        print_error "Git is not installed. Please install Git first."
        exit 1
    fi
    
    if ! command -v curl >/dev/null 2>&1; then
        print_warning "curl not found. Some features may not work."
    fi
    
    print_status "System requirements check passed"
    
    # Step 2: Create deployment directory
    show_progress "Creating deployment directory..."
    DEPLOY_DIR="$HOME/chatroom_deployment"
    mkdir -p "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
    print_status "Deployment directory created: $DEPLOY_DIR"
    
    # Step 3: Clone repository
    show_progress "Cloning ChatRoom repository..."
    if [ -d "$PROJECT_NAME" ]; then
        rm -rf "$PROJECT_NAME"
    fi
    git clone "$REPO_URL" "$PROJECT_NAME" >/dev/null 2>&1
    cd "$PROJECT_NAME"
    print_status "Repository cloned successfully"
    
    # Step 4: Check Python version
    show_progress "Verifying Python version..."
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
    REQUIRED_VERSION="3.8"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        print_error "Python 3.8+ is required. Found: $PYTHON_VERSION"
        exit 1
    fi
    print_status "Python version verified: $PYTHON_VERSION"
    
    # Step 5: Create virtual environment
    show_progress "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    print_status "Virtual environment created and activated"
    
    # Step 6: Upgrade pip
    show_progress "Upgrading pip..."
    pip install --upgrade pip >/dev/null 2>&1
    print_status "Pip upgraded successfully"
    
    # Step 7: Install dependencies
    show_progress "Installing Python dependencies..."
    cd backend
    pip install -r requirements.txt >/dev/null 2>&1
    print_status "Dependencies installed successfully"
    
    # Step 8: Initialize database
    show_progress "Initializing database..."
    if [ ! -f "db/chatroom.db" ]; then
        python init_db.py >/dev/null 2>&1
    fi
    python db/migrate_add_settings_table.py >/dev/null 2>&1
    print_status "Database initialized successfully"
    
    # Step 9: Admin user creation
    show_progress "Setting up admin user..."
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                    Admin User Setup                          ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get admin credentials
    read -p "Enter admin username (default: admin): " ADMIN_USERNAME
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    
    read -s -p "Enter admin password (default: admin123): " ADMIN_PASSWORD
    echo ""
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123}
    
    read -p "Enter admin email (default: admin@chatroom.local): " ADMIN_EMAIL
    ADMIN_EMAIL=${ADMIN_EMAIL:-admin@chatroom.local}
    
    read -p "Enter admin display name (default: Administrator): " ADMIN_DISPLAY_NAME
    ADMIN_DISPLAY_NAME=${ADMIN_DISPLAY_NAME:-Administrator}
    
    echo ""
    echo -e "${CYAN}Creating admin user: $ADMIN_USERNAME${NC}"
    echo ""
    
    # Create admin user
    create_admin_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$ADMIN_EMAIL" "$ADMIN_DISPLAY_NAME"
    print_status "Admin user setup completed"
    
    # Step 10: Set environment variables
    show_progress "Configuring environment..."
    export FLASK_ENV=development
    export FLASK_DEBUG=True
    export SECRET_KEY="dev-secret-key-$(date +%s)"
    print_status "Environment configured"
    
    # Step 11: Check port availability
    show_progress "Checking port availability..."
    if check_port $PORT; then
        print_warning "Port $PORT is already in use. Trying to find alternative..."
        for alt_port in 5001 5002 5003 5004 5005; do
            if ! check_port $alt_port; then
                PORT=$alt_port
                print_info "Using alternative port: $PORT"
                break
            fi
        done
    fi
    print_status "Port $PORT is available"
    
    # Step 12: Start the application
    show_progress "Starting ChatRoom application..."
    nohup python run.py >/dev/null 2>&1 &
    APP_PID=$!
    sleep 3
    
    # Save PID for later cleanup
    echo $APP_PID > .chatroom.pid
    print_status "Application started with PID: $APP_PID"
    
    # Step 13: Wait for service to be ready
    show_progress "Waiting for service to be ready..."
    if wait_for_service "http://localhost:$PORT"; then
        print_status "Service is ready and responding"
    else
        print_warning "Service may not be fully ready yet"
    fi
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    DEPLOYMENT COMPLETE!                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get local IP
    LOCAL_IP=$(get_local_ip)
    
    # Display access information
    echo -e "${CYAN}📊 Deployment Information:${NC}"
    echo -e "  ${BLUE}•${NC} Local URL:     ${GREEN}http://localhost:$PORT${NC}"
    echo -e "  ${BLUE}•${NC} Network URL:   ${GREEN}http://$LOCAL_IP:$PORT${NC}"
    echo -e "  ${BLUE}•${NC} Process ID:    ${GREEN}$APP_PID${NC}"
    echo -e "  ${BLUE}•${NC} Deployment:    ${GREEN}$DEPLOY_DIR/$PROJECT_NAME${NC}"
    echo ""
    
    # Display admin credentials
    echo -e "${YELLOW}🔐 Admin Credentials:${NC}"
    echo -e "  ${BLUE}•${NC} Username: ${GREEN}$ADMIN_USERNAME${NC}"
    echo -e "  ${BLUE}•${NC} Password: ${GREEN}$ADMIN_PASSWORD${NC}"
    echo -e "  ${BLUE}•${NC} Email: ${GREEN}$ADMIN_EMAIL${NC}"
    echo ""
    
    # Instructions for sharing
    echo -e "${PURPLE}🌐 To share with others:${NC}"
    echo -e "  ${BLUE}1.${NC} Make sure your firewall allows connections on port $PORT"
    echo -e "  ${BLUE}2.${NC} Share this URL: ${GREEN}http://$LOCAL_IP:$PORT${NC}"
    echo -e "  ${BLUE}3.${NC} Users can register new accounts or use admin credentials"
    echo ""
    
    # Management commands
    echo -e "${CYAN}🛠️  Management Commands:${NC}"
    echo -e "  ${BLUE}•${NC} Stop server:    ${GREEN}kill $APP_PID${NC}"
    echo -e "  ${BLUE}•${NC} View logs:      ${GREEN}tail -f logs/chatroom.log${NC}"
    echo -e "  ${BLUE}•${NC} Restart:        ${GREEN}cd $DEPLOY_DIR/$PROJECT_NAME/backend && ./deploy_chatroom.sh${NC}"
    echo ""
    
    # Success message
    echo -e "${GREEN}🎉 ChatRoom is now running and ready for use!${NC}"
    echo -e "${BLUE}📧 Admin contact: $ADMIN_EMAIL${NC}"
    echo ""
    
    # Open browser (optional)
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://localhost:$PORT" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "http://localhost:$PORT" >/dev/null 2>&1 &
    elif command -v start >/dev/null 2>&1; then
        start "http://localhost:$PORT" >/dev/null 2>&1 &
    fi
    
    # Keep script running to maintain the process
    echo -e "${YELLOW}💡 Press Ctrl+C to stop the server${NC}"
    echo ""
    
    # Wait for user interrupt
    trap 'echo -e "\n${RED}Stopping ChatRoom server...${NC}"; kill $APP_PID 2>/dev/null; rm -f .chatroom.pid; echo -e "${GREEN}Server stopped.${NC}"; exit 0' INT
    wait $APP_PID
}

# Run main function
main "$@" 