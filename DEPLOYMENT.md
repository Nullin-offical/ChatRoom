# ChatRoom Automated Deployment

This guide explains how to use the automated deployment scripts to quickly set up and share ChatRoom.

## 🚀 Quick Start

### For Linux/Mac Users:
```bash
chmod +x deploy_chatroom.sh
./deploy_chatroom.sh
```

### For Windows Users:
```cmd
deploy_chatroom.bat
```

## 📋 What the Scripts Do

The deployment scripts automatically perform the following steps:

1. **System Requirements Check** - Verifies Python 3.8+ and Git are installed
2. **Repository Clone** - Downloads the latest ChatRoom code from GitHub
3. **Environment Setup** - Creates Python virtual environment
4. **Dependencies Installation** - Installs all required Python packages
5. **Database Initialization** - Sets up SQLite database with default data
6. **Configuration** - Sets up environment variables and security settings
7. **Port Management** - Finds available port (5000, 5001, etc.)
8. **Application Launch** - Starts the ChatRoom server
9. **Service Verification** - Ensures the application is responding
10. **Network Sharing** - Provides local and network URLs for sharing

## 🎯 Features

- **Progress Bar** - Visual progress indicator with percentage
- **Error Handling** - Graceful error handling and user feedback
- **Port Detection** - Automatically finds available ports
- **Network Sharing** - Provides both local and network URLs
- **Admin Credentials** - Shows default admin login information
- **Browser Launch** - Automatically opens the application in browser
- **Clean Shutdown** - Proper cleanup when stopping the server

## 📊 Output Information

After successful deployment, you'll see:

```
📊 Deployment Information:
  • Local URL:     http://localhost:5000
  • Network URL:   http://192.168.1.100:5000
  • Process ID:    12345
  • Deployment:    /home/user/chatroom_deployment/ChatRoom

🔐 Default Admin Credentials:
  • Username: admin
  • Password: admin123

🌐 To share with others:
  1. Make sure your firewall allows connections on port 5000
  2. Share this URL: http://192.168.1.100:5000
  3. Users can register new accounts or use admin credentials
```

## 🔧 Management Commands

### Stop the Server:
- **Linux/Mac**: `Ctrl+C` or `kill <PID>`
- **Windows**: Press any key or `taskkill /f /im python.exe`

### View Logs:
- **Linux/Mac**: `tail -f logs/chatroom.log`
- **Windows**: `type logs\chatroom.log`

### Restart:
- Run the deployment script again

## 🌐 Sharing with Others

1. **Local Network**: Share the Network URL with users on the same network
2. **Internet Access**: Configure port forwarding on your router
3. **Firewall**: Ensure port 5000 (or alternative) is allowed
4. **SSL/HTTPS**: For production, consider using a reverse proxy with SSL

## 🔒 Security Notes

- Default admin credentials are for development only
- Change admin password after first login
- Use strong SECRET_KEY in production
- Configure firewall rules appropriately
- Consider using HTTPS for production deployments

## 🛠️ Troubleshooting

### Port Already in Use:
The script automatically finds alternative ports (5001, 5002, etc.)

### Python Not Found:
Install Python 3.8+ from [python.org](https://python.org)

### Git Not Found:
Install Git from [git-scm.com](https://git-scm.com)

### Permission Denied:
- **Linux/Mac**: `chmod +x deploy_chatroom.sh`
- **Windows**: Run as Administrator if needed

### Network Issues:
- Check firewall settings
- Ensure port forwarding is configured
- Verify network connectivity

## 📞 Support

For issues or questions:
- Check the logs in `logs/chatroom.log`
- Review the [main README](README.md)
- Open an issue on GitHub

---

**Happy Chatting! 🎉** 