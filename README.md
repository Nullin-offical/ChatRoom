# ChatRoom

A secure, real-time web-based chatroom application built with Flask (Python), Bootstrap 5, and SQLite.

## 🔒 Security Features

This application includes comprehensive security measures:

- **Rate Limiting**: 60 messages per minute per user
- **Spam Protection**: Automatic 10-minute bans for violations
- **XSS Prevention**: Input sanitization and Content Security Policy
- **SQL Injection Protection**: Parameterized queries
- **CSRF Protection**: Token validation and secure cookies
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, etc.
- **Input Validation**: Comprehensive validation for all user inputs
- **Session Security**: Secure, HTTP-only cookies with proper timeouts

## Features

- User authentication (register/login) with security measures
- Real-time chat (WebSocket) with rate limiting
- Admin panel with access control
- Private messaging with security validation
- User profiles with avatar support
- Password-protected chat rooms
- Modular, extensible, and secure codebase

## Getting Started

### Quick Start (Recommended)

Use the secure startup script:

```bash
chmod +x start_secure.sh
./start_secure.sh
```

### Manual Setup

#### Backend

1. `cd backend`
2. `pip install -r requirements.txt`
3. `python run.py`

#### Frontend

- HTML templates are in `frontend/templates/`
- Static files (CSS/JS) are in `frontend/static/`

## Security Configuration

### Development Mode
```bash
export FLASK_ENV=development
export FLASK_DEBUG=True
```

### Production Mode
```bash
export FLASK_ENV=production
export SECRET_KEY="your-secure-secret-key"
export FLASK_DEBUG=False
```

## Security Testing

Run the security test suite:

```bash
cd backend
python security_test.py
```

## Documentation

- [Security Documentation](SECURITY.md) - Comprehensive security guide
- [API Documentation](docs/API.md) - API endpoints and usage

---

**⚠️ Security Note**: Always use a strong SECRET_KEY in production and keep dependencies updated.
