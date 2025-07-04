# ChatRoom - Modern Real-Time Chat Application

<div align="center">

![ChatRoom Logo](https://img.shields.io/badge/ChatRoom-Modern%20Chat-blue?style=for-the-badge&logo=chat)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-red?style=for-the-badge&logo=flask)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-brightgreen?style=for-the-badge&logo=shield)

**A secure, modern, and feature-rich real-time chat application built with Flask, Socket.IO, and Bootstrap 5**

[Features](#-features) • [Installation](#-installation) • [Security](#-security) • [Usage](#-usage) • [Deployment](#-deployment)

</div>

---

## 👨‍💻 About the Author

**H0lwin** - Full-Stack Developer & Security Enthusiast

I've developed this ChatRoom application with a focus on **security**, **user experience**, and **modern web standards**. This project demonstrates best practices in web development, real-time communication, and cybersecurity.

**Contact:** [GitHub](https://github.com/H0lwin) • [Email](mailto:admin@chatroom.local)

---

## ✨ Features

### 🚀 Core Features
- **Real-time messaging** with WebSocket support
- **User authentication** with secure session management
- **Admin panel** with comprehensive management tools
- **Private messaging (PM)** between users
- **User profiles** with avatars and bio
- **Password-protected chat rooms**
- **Responsive design** for all devices

### 🔒 Security Features
- **Rate limiting** (60 messages/minute per user)
- **Spam protection** with automatic 10-minute bans
- **XSS prevention** through input sanitization
- **SQL injection protection** with parameterized queries
- **CSRF protection** with secure tokens
- **Security headers** (CSP, X-Frame-Options, etc.)
- **Session security** with HTTP-only cookies
- **Login attempt limiting** (5 attempts per 15 minutes)

### 🎨 User Experience
- **Modern UI/UX** with Bootstrap 5 and custom animations
- **Real-time notifications** for new messages
- **Online/offline status** tracking
- **Message timestamps** in user's timezone
- **RTL/LTR text support** for international users
- **Avatar selection** from predefined options
- **Responsive design** for mobile and desktop

### 🛠️ Admin Features
- **User management** (view, delete users)
- **Message moderation** (view, delete messages)
- **Room management** (create, delete, hide rooms)
- **Site settings** (change site name dynamically)
- **System monitoring** and statistics

---

## 🚀 Quick Installation

### Option 1: Automated Deployment (Recommended)

#### For Linux/Mac:
```bash
# Download and run the deployment script
curl -O https://raw.githubusercontent.com/H0lwin/ChatRoom/main/deploy_chatroom.sh
chmod +x deploy_chatroom.sh
./deploy_chatroom.sh
```

#### For Windows:
```cmd
# Download and run the deployment script
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/H0lwin/ChatRoom/main/deploy_chatroom.bat' -OutFile 'deploy_chatroom.bat'"
deploy_chatroom.bat
```

### Option 2: Manual Installation

#### Prerequisites
- Python 3.8 or higher
- Git
- pip (Python package manager)

#### Step-by-step Installation

1. **Clone the repository:**
```bash
git clone https://github.com/H0lwin/ChatRoom.git
cd ChatRoom
```

2. **Set up Python environment:**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate
```

3. **Install dependencies:**
```bash
cd backend
pip install -r requirements.txt
```

4. **Initialize database:**
```bash
python db/init_db.py
python db/migrate_add_settings_table.py
```

5. **Run the application:**
```bash
python run.py
```

6. **Access the application:**
   - Open your browser and go to: `http://localhost:5000`
   - Default admin credentials: `admin` / `admin123`

---

## 🔒 Security Overview

This application implements enterprise-grade security measures:

### 🛡️ Protection Against Common Attacks
- **XSS (Cross-Site Scripting)**: Input sanitization and Content Security Policy
- **SQL Injection**: Parameterized queries and input validation
- **CSRF (Cross-Site Request Forgery)**: Secure tokens and SameSite cookies
- **Brute Force**: Login attempt limiting and account lockout
- **Spam/DoS**: Rate limiting and automatic user banning

### 🔐 Authentication & Authorization
- Secure password hashing with Werkzeug
- Session management with configurable timeouts
- Admin-only access to sensitive endpoints
- Role-based access control

### 📊 Security Monitoring
- Real-time security event logging
- Failed login attempt tracking
- Suspicious activity detection
- Comprehensive audit trails

---

## 📖 Usage Guide

### For Users

#### Registration & Login
1. Visit the registration page and create an account
2. Use your credentials to log in
3. Complete your profile with avatar and bio

#### Chatting
1. **Public Rooms**: Join existing chat rooms from the dashboard
2. **Private Messages**: Click on any user's profile to start a private conversation
3. **Real-time**: Messages appear instantly for all participants

#### Profile Management
- Edit your profile information
- Change your avatar
- Update your bio and personal details
- View your chat statistics

### For Administrators

#### Accessing Admin Panel
1. Log in with admin credentials
2. Click the "Admin" link in the navigation
3. Access comprehensive management tools

#### Managing Users
- View all registered users
- Delete problematic users
- Monitor user activity

#### Managing Content
- View and moderate messages
- Delete inappropriate content
- Manage chat rooms

#### Site Settings
- Change the site name dynamically
- Monitor system statistics
- Configure security settings

---

## 🌐 Deployment

### Local Development
```bash
# Development mode
export FLASK_ENV=development
export FLASK_DEBUG=True
python run.py
```

### Production Deployment
```bash
# Production mode
export FLASK_ENV=production
export SECRET_KEY="your-secure-secret-key"
export FLASK_DEBUG=False
python run.py
```

### Cloud Deployment
The application is compatible with:
- **Heroku**
- **AWS EC2**
- **Google Cloud Platform**
- **DigitalOcean**

---

## 🛠️ Configuration

### Environment Variables
```bash
# Required for production
export SECRET_KEY="your-secure-secret-key"
export FLASK_ENV="production"

# Optional
export CORS_ORIGINS="https://yourdomain.com"
export MAX_MESSAGES_PER_MINUTE=60
export SPAM_BAN_DURATION_MINUTES=10
```

### Security Settings
```python
# Rate limiting
MAX_MESSAGES_PER_MINUTE = 60
SPAM_BAN_DURATION_MINUTES = 10
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT_MINUTES = 15

# Content limits
MAX_MESSAGE_LENGTH = 1000
MIN_MESSAGE_LENGTH = 1
MAX_USERNAME_LENGTH = 30
MIN_USERNAME_LENGTH = 3
```

---

## 📁 Project Structure

```
ChatRoom/
├── backend/                 # Flask backend application
│   ├── app.py              # Main application file
│   ├── auth.py             # Authentication module
│   ├── security.py         # Security features
│   ├── middleware.py       # Security middleware
│   ├── config.py           # Configuration settings
│   ├── run.py              # Application runner
│   ├── requirements.txt    # Python dependencies
│   ├── db/                 # Database files
│   └── models/             # Database models
├── frontend/               # Frontend templates and static files
│   ├── templates/          # HTML templates
│   └── static/             # CSS, JS, images, avatars
├── deploy_chatroom.sh      # Linux/Mac deployment script
├── deploy_chatroom.bat     # Windows deployment script
└── README.md               # This file
```

---

## 🔧 Development

### Adding New Features
1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new functionality
5. Submit a pull request

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Maintain security best practices

---

## 🤝 Contributing

I welcome contributions from the community! Here's how you can help:

### Ways to Contribute
- 🐛 **Report bugs** and issues
- 💡 **Suggest new features**
- 📝 **Improve documentation**
- 🔧 **Submit code improvements**
- 🧪 **Add tests**

### Development Setup
1. Fork the repository
2. Clone your fork locally
3. Create a virtual environment
4. Install dependencies
5. Make your changes
6. Run tests
7. Submit a pull request

---

## 📞 Support & Contact

### Getting Help
- 📖 **Documentation**: Check this README and inline code comments
- 🐛 **Issues**: Report bugs on [GitHub Issues](https://github.com/H0lwin/ChatRoom/issues)
- 💬 **Discussions**: Join discussions on [GitHub Discussions](https://github.com/H0lwin/ChatRoom/discussions)

### Contact Information
- **Author**: H0lwin
- **GitHub**: [@H0lwin](https://github.com/H0lwin)
- **Email**: admin@chatroom.local
- **Project**: [ChatRoom Repository](https://github.com/H0lwin/ChatRoom)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Flask** team for the excellent web framework
- **Bootstrap** team for the responsive UI components
- **Socket.IO** team for real-time communication
- **Open source community** for inspiration and tools

---

<div align="center">

**Made with ❤️ and lots of ☕ by H0lwin**

[![GitHub stars](https://img.shields.io/github/stars/H0lwin/ChatRoom?style=social)](https://github.com/H0lwin/ChatRoom/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/H0lwin/ChatRoom?style=social)](https://github.com/H0lwin/ChatRoom/network)
[![GitHub issues](https://img.shields.io/github/issues/H0lwin/ChatRoom)](https://github.com/H0lwin/ChatRoom/issues)

</div>
