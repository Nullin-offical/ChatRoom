// Chat Application
const socket = io();

// DOM Elements
const chatBox = document.getElementById('chat-box');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const roomList = document.getElementById('room-list');
const roomCount = document.getElementById('room-count');
const onlineCount = document.getElementById('online-count');
const typingIndicator = document.getElementById('typing-indicator');

// Templates
const messageTemplate = document.getElementById('message-template');
const roomTemplate = document.getElementById('room-template');

// State
let currentRoom = null;
let typingTimeout = null;
let onlineUsers = new Set();

// Language detection function
function detectTextDirection(text) {
    if (!text || typeof text !== 'string') return 'ltr';
    
    // Persian/Arabic character ranges
    const persianArabicRegex = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF\u0590-\u05FF]/;
    
    // Check if text contains Persian/Arabic characters
    const hasPersianArabic = persianArabicRegex.test(text);
    
    // Check if text contains English/Latin characters
    const hasEnglish = /[a-zA-Z]/.test(text);
    
    // If only Persian/Arabic characters, use RTL
    if (hasPersianArabic && !hasEnglish) {
        return 'rtl';
    }
    // If only English/Latin characters, use LTR
    else if (hasEnglish && !hasPersianArabic) {
        return 'ltr';
    }
    // If mixed content, use mixed class for better handling
    else if (hasPersianArabic && hasEnglish) {
        return 'mixed';
    }
    // Default to LTR
    else {
        return 'ltr';
    }
}

// Function to clean and format text for better display
function formatMessageText(text) {
    if (!text) return '';
    
    // Replace multiple spaces with single space
    text = text.replace(/\s+/g, ' ');
    
    // Trim whitespace
    text = text.trim();
    
    return text;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Request room list
    socket.emit('get_rooms');
    
    // If we're in a specific room, load it
    if (window.currentRoom) {
        currentRoom = window.currentRoom;
        joinRoom(currentRoom.slug);
        loadChatHistory(currentRoom.slug);
    }
    
    // Setup event listeners
    setupEventListeners();
    
    // Start periodic online status updates
    setInterval(updateOnlineStatus, 30000); // Every 30 seconds
});

// Event Listeners
function setupEventListeners() {
    // Message form
    if (chatForm) {
        chatForm.addEventListener('submit', handleMessageSubmit);
    }
    
    // Message input typing
    if (messageInput) {
        messageInput.addEventListener('input', handleTyping);
    }
}

// Handle message submission
function handleMessageSubmit(e) {
    e.preventDefault();
    const content = messageInput.value.trim();
    
    if (content && currentRoom && currentRoom.slug) {
        socket.emit('send_message', {
            content: content,
            room_slug: currentRoom.slug
        });
        messageInput.value = '';
        messageInput.focus();
    }
}

// Handle typing indicator
function handleTyping() {
    if (currentRoom && currentRoom.slug) {
        socket.emit('typing', { room_slug: currentRoom.slug });
        
        // Clear existing timeout
        if (typingTimeout) {
            clearTimeout(typingTimeout);
        }
        
        // Set new timeout
        typingTimeout = setTimeout(() => {
            socket.emit('stop_typing', { room_slug: currentRoom.slug });
        }, 1000);
    }
}

// Join room
function joinRoom(roomSlug) {
    socket.emit('join_room', { room_slug: roomSlug });
    console.log(`Joined room: ${roomSlug}`);
}

// Leave room
function leaveRoom(roomSlug) {
    socket.emit('leave_room', { room_slug: roomSlug });
    console.log(`Left room: ${roomSlug}`);
}

// Load chat history
function loadChatHistory(roomSlug) {
    socket.emit('get_chat_history', { room_slug: roomSlug });
}

// Render message with improved timestamp, profile image, and direction support
function renderMessage(message) {
    if (!chatBox) return;
    
    const clone = messageTemplate.content.cloneNode(true);
    const messageItem = clone.querySelector('.message-item');
    const messageRow = clone.querySelector('.message-row');
    const username = clone.querySelector('.message-username');
    const time = clone.querySelector('.message-time');
    const content = clone.querySelector('.message-content');
    const profileImage = clone.querySelector('.profile-image');
    const avatarFallback = clone.querySelector('.avatar-fallback');
    
    // Format and clean message text
    const formattedText = formatMessageText(message.content);
    
    // Detect text direction and apply appropriate class
    const textDirection = detectTextDirection(formattedText);
    content.classList.add(textDirection);
    
    // Set message data
    username.textContent = message.username;
    username.href = `/user/${message.username}`;
    username.setAttribute('data-username', message.username);
    
    // Handle profile image
    if (message.profile_image) {
        profileImage.src = message.profile_image;
        profileImage.style.display = 'block';
        avatarFallback.style.display = 'none';
    } else {
        profileImage.style.display = 'none';
        avatarFallback.style.display = 'block';
        avatarFallback.textContent = message.username[0].toUpperCase();
    }
    
    // Format timestamp for user's local timezone
    const messageDate = new Date(message.timestamp);
    const now = new Date();
    const isToday = messageDate.toDateString() === now.toDateString();
    const isYesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000).toDateString() === messageDate.toDateString();
    const timeDiff = now.getTime() - messageDate.getTime();
    
    let timeString;
    if (timeDiff < 60000) {
        timeString = 'Just now';
    } else if (timeDiff < 3600000) {
        const minutes = Math.floor(timeDiff / 60000);
        timeString = `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (isToday) {
        timeString = messageDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
    } else if (isYesterday) {
        timeString = `Yesterday at ${messageDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true })}`;
    } else {
        timeString = messageDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' at ' + messageDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
    }
    
    time.textContent = timeString;
    content.textContent = formattedText;
    
    // Check if it's own message
    if (message.username === window.currentUser) {
        messageItem.classList.add('own-message');
    }
    
    // Add to chat box
    chatBox.appendChild(clone);
    
    // Scroll to bottom
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Render room list with online status
function renderRoomList(rooms) {
    if (!roomList) return;
    
    roomList.innerHTML = '';
    roomCount.textContent = rooms.length;
    
    rooms.forEach(room => {
        const clone = roomTemplate.content.cloneNode(true);
        const roomItem = clone.querySelector('.room-item');
        const roomName = clone.querySelector('.room-name');
        const roomInfo = clone.querySelector('.room-info');
        const roomBadge = clone.querySelector('.room-badge');
        
        // Set room data
        roomName.textContent = room.name;
        roomInfo.textContent = `Created ${new Date(room.created_at).toLocaleDateString()}`;
        roomBadge.textContent = room.has_password ? '🔒' : '🌐';
        
        // Set link
        roomItem.href = `/chat/room/${room.slug}`;
        
        // Highlight current room
        if (currentRoom && currentRoom.slug === room.slug) {
            roomItem.classList.add('active');
        }
        
        roomList.appendChild(clone);
    });
}

// Update online status periodically
function updateOnlineStatus() {
    socket.emit('ping');
}

// Socket Events
socket.on('room_list', (rooms) => {
    renderRoomList(rooms);
});

socket.on('chat_history', (messages) => {
    if (chatBox) {
        chatBox.innerHTML = '';
        messages.forEach(renderMessage);
    }
});

socket.on('new_message', (message) => {
    // Only show if it's for current room
    if (currentRoom && message.room_slug === currentRoom.slug) {
        renderMessage(message);
    }
});

socket.on('user_typing', (data) => {
    if (typingIndicator && currentRoom && data.room_slug === currentRoom.slug) {
        typingIndicator.style.display = 'block';
        typingIndicator.innerHTML = `<i class="bi bi-three-dots"></i> ${data.username} is typing...`;
    }
});

socket.on('user_stop_typing', (data) => {
    if (typingIndicator && currentRoom && data.room_slug === currentRoom.slug) {
        typingIndicator.style.display = 'none';
    }
});

socket.on('user_joined', (data) => {
    if (currentRoom && data.room_slug === currentRoom.slug) {
        showSystemMessage(`${data.username} joined the room`);
    }
});

socket.on('user_left', (data) => {
    if (currentRoom && data.room_slug === currentRoom.slug) {
        showSystemMessage(`${data.username} left the room`);
    }
});

// Real-time user status updates
socket.on('user_status_change', (data) => {
    console.log(`User ${data.username} is now ${data.status}`);
    // Update UI based on status change
    updateUserStatusInUI(data.username, data.status);
});

// Show system message
function showSystemMessage(text) {
    if (!chatBox) return;
    
    const div = document.createElement('div');
    div.className = 'text-center my-2';
    div.innerHTML = `<small class="text-muted">${text}</small>`;
    
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Update user status in UI
function updateUserStatusInUI(username, status) {
    // Update any user status indicators in the UI
    const statusElements = document.querySelectorAll(`[data-username="${username}"]`);
    statusElements.forEach(element => {
        if (status === 'online') {
            element.classList.remove('text-muted');
            element.classList.add('text-success');
            element.innerHTML = '<i class="bi bi-circle-fill me-1"></i>Online';
        } else {
            element.classList.remove('text-success');
            element.classList.add('text-muted');
            element.innerHTML = '<i class="bi bi-circle me-1"></i>Offline';
        }
    });
}

// Update online count
function updateOnlineCount(count) {
    if (onlineCount) {
        onlineCount.textContent = `${count} online`;
    }
}

// Handle room switching
function switchRoom(roomSlug) {
    if (currentRoom && currentRoom.slug !== roomSlug) {
        leaveRoom(currentRoom.slug);
    }
    
    currentRoom = { slug: roomSlug };
    joinRoom(roomSlug);
    loadChatHistory(roomSlug);
}

// Auto-scroll to bottom when new messages arrive
function autoScroll() {
    if (chatBox) {
        const isScrolledToBottom = chatBox.scrollTop + chatBox.clientHeight >= chatBox.scrollHeight - 10;
        if (isScrolledToBottom) {
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    }
}

// Handle window focus/blur for typing indicator
window.addEventListener('focus', () => {
    if (currentRoom && currentRoom.slug) {
        socket.emit('user_active', { room_slug: currentRoom.slug });
    }
});

window.addEventListener('blur', () => {
    if (currentRoom && currentRoom.slug) {
        socket.emit('user_inactive', { room_slug: currentRoom.slug });
    }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (currentRoom && currentRoom.slug) {
        leaveRoom(currentRoom.slug);
    }
}); 