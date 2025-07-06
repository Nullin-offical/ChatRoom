// Chat Application
// Socket is defined in base.html

// State variables
let currentRoom = null;
let typingTimeout = null;
let onlineUsers = new Set();
let isInitialized = false;

// DOM Elements - will be initialized when needed
let chatBox = null;
let chatForm = null;
let messageInput = null;
let roomList = null;
let roomListMobile = null;
let roomCount = null;
let onlineCount = null;
let typingIndicator = null;
let messageTemplate = null;
let roomTemplate = null;

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

// Format timestamp for display
function formatTime(timestamp) {
    const messageDate = new Date(timestamp);
    const now = new Date();
    const isToday = messageDate.toDateString() === now.toDateString();
    const isYesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000).toDateString() === messageDate.toDateString();
    const timeDiff = now.getTime() - messageDate.getTime();
    
    if (timeDiff < 60000) { // Less than 1 minute
        return 'Just now';
    } else if (timeDiff < 3600000) { // Less than 1 hour
        const minutes = Math.floor(timeDiff / 60000);
        return `${minutes}m ago`;
    } else if (isToday) {
        return messageDate.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    } else if (isYesterday) {
        return 'Yesterday';
    } else {
        return messageDate.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
    }
}

// Initialize DOM elements
function initializeDOMElements() {
    chatBox = document.getElementById('chat-box');
    chatForm = document.getElementById('chat-form');
    messageInput = document.getElementById('message-input');
    roomList = document.getElementById('room-list');
    roomListMobile = document.getElementById('room-list-mobile');
    roomCount = document.getElementById('room-count');
    onlineCount = document.getElementById('online-count');
    typingIndicator = document.getElementById('typing-indicator');
    messageTemplate = document.getElementById('message-template');
    roomTemplate = document.getElementById('room-template');
    
    // Debug DOM elements
    console.log('DOM Elements found:');
    console.log('- chatBox:', chatBox);
    console.log('- chatForm:', chatForm);
    console.log('- messageInput:', messageInput);
    console.log('- roomList:', roomList);
    console.log('- roomListMobile:', roomListMobile);
    console.log('- roomCount:', roomCount);
    console.log('- onlineCount:', onlineCount);
    console.log('- typingIndicator:', typingIndicator);
    console.log('- messageTemplate:', messageTemplate);
    console.log('- roomTemplate:', roomTemplate);
}

// Initialize chat functionality
function initializeChat() {
    if (isInitialized) {
        console.log('Chat already initialized');
        return;
    }
    
    console.log('Initializing chat with socket:', socket);
    
    // Test socket connection
    console.log('Socket connected:', socket.connected);
    console.log('Socket ID:', socket.id);
    
    // Setup socket event listeners
    setupSocketEvents();
    
    // Request room list
    console.log('Requesting room list...');
    socket.emit('get_rooms');
    
    // Fallback: Load rooms via API if socket doesn't work
    setTimeout(() => {
        if (!roomList || roomList.children.length === 0) {
            console.log('Socket may not have worked, trying API fallback...');
            loadRoomsViaAPI();
        }
    }, 3000);
    
    // If we're in a specific room, load it
    if (window.currentRoom) {
        currentRoom = window.currentRoom;
        console.log('Current room from window:', currentRoom);
        joinRoom(currentRoom.slug);
        loadChatHistory(currentRoom.slug);
    } else {
        console.log('No current room found in window object');
    }
    
    // Setup event listeners
    setupEventListeners();
    
    // Start periodic online status updates
    setInterval(updateOnlineStatus, 30000); // Every 30 seconds
    
    isInitialized = true;
}

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
    
    // Room click handlers
    document.addEventListener('click', (e) => {
        const roomItem = e.target.closest('.room-item');
        if (roomItem) {
            e.preventDefault();
            const roomSlug = roomItem.getAttribute('data-slug');
            const hasPassword = roomItem.getAttribute('data-has-password') === '1';
            if (hasPassword) {
                // Show password modal
                const modal = new bootstrap.Modal(document.getElementById('roomPasswordModal'));
                document.getElementById('room-password-slug').value = roomSlug;
                document.getElementById('room-password-input').value = '';
                document.getElementById('room-password-error').textContent = '';
                document.getElementById('room-password-input').classList.remove('is-invalid');
                modal.show();
            } else {
                // Redirect to the room page
                window.location.href = `/chat/room/${roomSlug}`;
            }
        }
    });

    // Password modal form submit
    const passwordForm = document.getElementById('room-password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const slug = document.getElementById('room-password-slug').value;
            const password = document.getElementById('room-password-input').value;
            const errorDiv = document.getElementById('room-password-error');
            const input = document.getElementById('room-password-input');
            errorDiv.textContent = '';
            input.classList.remove('is-invalid');
            
            try {
                const response = await fetch(`/chat/room/${slug}/join`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `password=${encodeURIComponent(password)}`
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Password correct - redirect to room
                    window.location.href = data.redirect;
                } else {
                    // Password incorrect - show error
                    errorDiv.textContent = data.error || 'Incorrect password.';
                    input.classList.add('is-invalid');
                }
            } catch (err) {
                console.error('Password submission error:', err);
                errorDiv.textContent = 'Network error. Please try again.';
                input.classList.add('is-invalid');
            }
        });
    }
}

// Message submission handler
function handleMessageSubmit(e) {
    e.preventDefault();
    
    if (!messageInput || !currentRoom) return;
    
    const content = messageInput.value.trim();
    if (!content) return;
    
    // Send message via socket
    socket.emit('send_message', {
        room: currentRoom.slug,
        content: content
    });
    
    // Clear input
    messageInput.value = '';
    
    // Stop typing indicator
    if (typingTimeout) {
        clearTimeout(typingTimeout);
        typingTimeout = null;
    }
    socket.emit('stop_typing', { room: currentRoom.slug });
}

// Typing handler
function handleTyping() {
    if (!currentRoom) return;
    
    // Clear existing timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }
    
    // Emit typing event
    socket.emit('typing', { room: currentRoom.slug });
    
    // Set timeout to stop typing
    typingTimeout = setTimeout(() => {
        socket.emit('stop_typing', { room: currentRoom.slug });
        typingTimeout = null;
    }, 1000);
}

// Join room
function joinRoom(roomSlug) {
    if (!roomSlug) return;
    
    console.log('Joining room:', roomSlug);
    socket.emit('join_room', { room: roomSlug });
}

// Leave room
function leaveRoom(roomSlug) {
    if (!roomSlug) return;
    
    console.log('Leaving room:', roomSlug);
    socket.emit('leave_room', { room: roomSlug });
}

// Load chat history
function loadChatHistory(roomSlug) {
    if (!roomSlug) return;
    
    console.log('Loading chat history for room:', roomSlug);
    socket.emit('get_chat_history', { room: roomSlug });
}

// Render message
function renderMessage(message) {
    if (!messageTemplate || !chatBox) {
        console.log('Chat box not found');
        return;
    }
    
    const isOwnMessage = message.username === window.currentUser;
    const messageDirection = detectTextDirection(message.content);
    
    // Clone template
    const messageElement = messageTemplate.content.cloneNode(true);
    const messageItem = messageElement.querySelector('.message-item');
    const messageRow = messageElement.querySelector('.message-row');
    const messageContent = messageElement.querySelector('.message-content');
    const messageText = messageElement.querySelector('.message-text');
    const messageUsername = messageElement.querySelector('.message-username');
    const messageTime = messageElement.querySelector('.message-time');
    const messageStatus = messageElement.querySelector('.message-status');
    
    // Set message content
    messageText.textContent = formatMessageText(message.content);
    messageText.className = `message-text ${messageDirection}`;
    
    // Set username and link
    messageUsername.textContent = message.username;
    messageUsername.href = `/user/${message.username}`;
    
    // Set timestamp
    messageTime.textContent = formatTime(message.timestamp);
    
    // Set avatar
    const avatarOwn = messageElement.querySelector('.message-avatar-own img');
    const avatarOther = messageElement.querySelector('.message-avatar-other img');
    const fallbackOwn = messageElement.querySelector('.message-avatar-own .avatar-fallback');
    const fallbackOther = messageElement.querySelector('.message-avatar-other .avatar-fallback');
    
    if (message.profile_image) {
        if (avatarOwn) avatarOwn.src = message.profile_image;
        if (avatarOther) avatarOther.src = message.profile_image;
    }
    
    if (fallbackOwn) fallbackOwn.textContent = message.username.charAt(0).toUpperCase();
    if (fallbackOther) fallbackOther.textContent = message.username.charAt(0).toUpperCase();
    
    // Set message status
    if (isOwnMessage) {
        messageStatus.innerHTML = '<i class="bi bi-check2-all"></i><span>Sent</span>';
    } else {
        messageStatus.innerHTML = '';
    }
    
    // Apply styling based on message ownership
    if (isOwnMessage) {
        messageItem.classList.add('own-message');
        messageRow.style.flexDirection = 'row-reverse';
        messageContent.classList.add('own-content');
        
        // Ensure avatar positioning for own messages - avatar BEFORE message on right
        const avatarOwn = messageElement.querySelector('.message-avatar-own');
        const avatarOther = messageElement.querySelector('.message-avatar-other');
        
        avatarOwn.style.display = 'flex';
        avatarOwn.style.order = '1'; // Avatar before message on right
        avatarOther.style.display = 'none';
        messageContent.style.order = '2'; // Message after avatar on right
    } else {
        messageItem.classList.add('other-message');
        messageRow.style.flexDirection = 'row';
        messageContent.classList.add('other-content');
        
        // Ensure avatar positioning for other messages - avatar BEFORE message on left
        const avatarOwn = messageElement.querySelector('.message-avatar-own');
        const avatarOther = messageElement.querySelector('.message-avatar-other');
        
        avatarOther.style.display = 'flex';
        avatarOther.style.order = '0'; // Avatar before message on left
        avatarOwn.style.display = 'none';
        messageContent.style.order = '1'; // Message after avatar on left
    }
    
    // Add to chat box
    chatBox.appendChild(messageElement);
    
    // Auto scroll to bottom
    autoScroll();
}

// Render room list
function renderRoomList(rooms) {
    console.log('Rendering room list:', rooms);
    
    if (!roomTemplate) {
        console.error('Room template not found');
        return;
    }
    
    // Clear existing rooms
    if (roomList) roomList.innerHTML = '';
    if (roomListMobile) roomListMobile.innerHTML = '';
    
    // Update room count
    if (roomCount) roomCount.textContent = rooms.length;
    
    console.log('Found room list elements:', [roomList, roomListMobile].filter(Boolean).length);
    
    rooms.forEach(room => {
        // Clone template
        const roomElement = roomTemplate.content.cloneNode(true);
        const roomItem = roomElement.querySelector('.room-item');
        const roomName = roomElement.querySelector('.room-name');
        const roomInfo = roomElement.querySelector('.room-info');
        
        // Set room data
        roomItem.href = `/chat/room/${room.slug}`;
        roomItem.setAttribute('data-slug', room.slug);
        roomItem.setAttribute('data-has-password', room.has_password ? '1' : '0');
        roomName.textContent = room.name;
        
        // Set room info
        if (room.has_password) {
            roomInfo.innerHTML = '<i class="bi bi-lock me-1"></i>Protected';
        } else {
            roomInfo.innerHTML = '<i class="bi bi-unlock me-1"></i>Public';
        }
        
        // Add to both desktop and mobile lists
        if (roomList) roomList.appendChild(roomElement.cloneNode(true));
        if (roomListMobile) roomListMobile.appendChild(roomElement.cloneNode(true));
    });
}

// Update online status
function updateOnlineStatus() {
    if (socket && socket.connected) {
        socket.emit('ping');
    }
}

// Setup socket events
function setupSocketEvents() {
    console.log('Setting up socket event listeners');
    
    socket.on('connect', () => {
        console.log('Socket connected successfully');
        console.log('Socket ID:', socket.id);
        
        // Update UI to show connected status
        const roomStatus = document.getElementById('room-status');
        if (roomStatus) {
            roomStatus.innerHTML = '<i class="bi bi-wifi"></i>';
            roomStatus.className = 'badge bg-success';
        }
    });
    
    socket.on('disconnect', () => {
        console.log('Socket disconnected');
        
        // Update UI to show disconnected status
        const roomStatus = document.getElementById('room-status');
        if (roomStatus) {
            roomStatus.innerHTML = '<i class="bi bi-wifi-off"></i>';
            roomStatus.className = 'badge bg-danger';
        }
    });
    
    socket.on('room_list', (rooms) => {
        console.log('Received room list from server:', rooms);
        renderRoomList(rooms);
    });
    
    socket.on('chat_history', (messages) => {
        console.log('Received chat history:', messages);
        console.log('Chat box element:', chatBox);
        
        if (!chatBox) {
            console.log('Chat box not found');
            return;
        }
        
        // Clear existing messages
        chatBox.innerHTML = '';
        
        // Render messages
        messages.forEach(message => {
            renderMessage(message);
        });
        
        // Scroll to bottom
        forceScrollToBottom();
    });
    
    socket.on('new_message', (message) => {
        console.log('Received new message:', message);
        renderMessage(message);
    });
    
    socket.on('user_joined', (data) => {
        console.log('User joined:', data.username);
        showSystemMessage(`${data.username} joined the room`);
    });
    
    socket.on('user_left', (data) => {
        console.log('User left:', data.username);
        showSystemMessage(`${data.username} left the room`);
    });
    
    socket.on('typing', (data) => {
        console.log('User typing:', data.username);
        showTypingIndicator(data.username);
    });
    
    socket.on('stop_typing', (data) => {
        console.log('User stopped typing:', data.username);
        hideTypingIndicator();
    });
    
    socket.on('user_status_change', (data) => {
        console.log('User status change:', data);
        updateUserStatusInUI(data.username, data.status);
    });
    
    socket.on('online_users', (users) => {
        console.log('Online users:', users);
        onlineUsers = new Set(users);
        updateOnlineCount(users.length);
    });
    
    socket.on('user_online', (data) => {
        console.log('User online:', data.username);
        onlineUsers.add(data.username);
        updateOnlineCount(onlineUsers.size);
    });
    
    socket.on('user_offline', (data) => {
        console.log('User offline:', data.username);
        onlineUsers.delete(data.username);
        updateOnlineCount(onlineUsers.size);
    });
}

// Show system message
function showSystemMessage(text) {
    if (!chatBox) return;
    
    const systemMessage = document.createElement('div');
    systemMessage.className = 'system-message text-center text-muted my-2';
    systemMessage.textContent = text;
    chatBox.appendChild(systemMessage);
    autoScroll();
}

// Update user status in UI
function updateUserStatusInUI(username, status) {
    // This could be used to update user status indicators
    console.log(`User ${username} is now ${status}`);
}

// Update online count
function updateOnlineCount(count) {
    if (onlineCount) {
        onlineCount.textContent = `${count} online`;
    }
}

// Switch room (redirect to room page)
function switchRoom(roomSlug) {
    if (!roomSlug) return;
    
    // Leave current room if any
    if (currentRoom) {
        leaveRoom(currentRoom.slug);
    }
    
    // Redirect to new room
    window.location.href = `/chat/room/${roomSlug}`;
}

// Auto scroll to bottom
function autoScroll() {
    if (!chatBox) return;
    
    // Always scroll to bottom for new messages
    forceScrollToBottom();
}

// Force scroll to bottom
function forceScrollToBottom() {
    if (!chatBox) return;
    
    // Use setTimeout to ensure DOM is updated
    setTimeout(() => {
        chatBox.scrollTop = chatBox.scrollHeight;
    }, 10);
}

// Show typing indicator
function showTypingIndicator(username) {
    if (!typingIndicator) return;
    
    typingIndicator.style.display = 'block';
    const typingText = typingIndicator.querySelector('small');
    if (typingText) {
        typingText.textContent = `${username} is typing...`;
    }
}

// Hide typing indicator
function hideTypingIndicator() {
    if (!typingIndicator) return;
    
    typingIndicator.style.display = 'none';
}

// Load rooms via API fallback
async function loadRoomsViaAPI() {
    try {
        const response = await fetch('/api/rooms');
        const rooms = await response.json();
        console.log('Loaded rooms via API:', rooms);
        renderRoomList(rooms);
    } catch (error) {
        console.error('Failed to load rooms via API:', error);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('Chat.js initialized');
    
    // Initialize DOM elements
    initializeDOMElements();
    
    // Wait for socket to be available
    if (typeof socket === 'undefined') {
        console.error('Socket not available, waiting...');
        setTimeout(() => {
            if (typeof socket !== 'undefined') {
                initializeChat();
            } else {
                console.error('Socket still not available after timeout');
            }
        }, 1000);
    } else {
        initializeChat();
    }
    
    // Ensure chat scrolls to bottom after page load
    setTimeout(() => {
        if (chatBox && chatBox.children.length > 0) {
            console.log('Ensuring chat scrolls to bottom after page load');
            forceScrollToBottom();
        }
    }, 500);
});