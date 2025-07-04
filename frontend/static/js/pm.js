// Private Messaging Application
const socket = io();

// DOM Elements
const chatBox = document.getElementById('chat-box');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const chatList = document.getElementById('chat-list');
const chatCount = document.getElementById('chat-count');
const userSearchForm = document.getElementById('user-search-form');
const userSearchInput = document.getElementById('user-search-input');
const typingIndicator = document.getElementById('typing-indicator');

// Templates
const messageTemplate = document.getElementById('message-template');
const chatTemplate = document.getElementById('chat-template');

// State
let currentChat = null;
let typingTimeout = null;
let searchTimeout = null;

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
    // Request chat list
    socket.emit('get_pm_chats');
    
    // If we have a target user, load the chat
    if (window.targetUser) {
        currentChat = window.targetUser;
        loadChatHistory(currentChat);
        // Join PM room for real-time updates
        socket.emit('join_pm', { username: currentChat });
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
    
    // User search form
    if (userSearchForm) {
        userSearchForm.addEventListener('submit', handleUserSearch);
    }
    
    // User search input
    if (userSearchInput) {
        userSearchInput.addEventListener('input', handleSearch);
        userSearchInput.addEventListener('focus', () => {
            const searchResults = document.getElementById('search-results');
            if (searchResults) {
                searchResults.style.display = 'block';
            }
        });
    }
    
    // Close search results when clicking outside
    document.addEventListener('click', (e) => {
        const searchResults = document.getElementById('search-results');
        if (searchResults && !userSearchInput.contains(e.target) && !searchResults.contains(e.target)) {
            searchResults.style.display = 'none';
        }
    });
}

// Handle message submission
function handleMessageSubmit(e) {
    e.preventDefault();
    const content = messageInput.value.trim();
    
    if (content && currentChat) {
        socket.emit('send_pm', {
            content: content,
            recipient: currentChat
        });
    messageInput.value = '';
        messageInput.focus();
    }
}

// Handle user search
function handleUserSearch(e) {
    e.preventDefault();
    const query = userSearchInput.value.trim();
    
    if (query) {
        socket.emit('search_users', { query: query });
    }
}

// Handle typing indicator
function handleTyping() {
    if (currentChat) {
        socket.emit('pm_typing', { recipient: currentChat });
        
        // Clear existing timeout
        if (typingTimeout) {
            clearTimeout(typingTimeout);
        }
        
        // Set new timeout
        typingTimeout = setTimeout(() => {
            socket.emit('pm_stop_typing', { recipient: currentChat });
        }, 1000);
    }
}

// Handle search
function handleSearch() {
    const query = userSearchInput.value.trim();
    
    // Clear existing timeout
    if (searchTimeout) {
        clearTimeout(searchTimeout);
    }
    
    // Set new timeout for debouncing
    searchTimeout = setTimeout(() => {
        if (query.length >= 2) {
            socket.emit('search_users', { query: query });
        } else {
            const searchResults = document.getElementById('search-results');
            if (searchResults) {
                searchResults.innerHTML = '';
                searchResults.style.display = 'none';
            }
        }
    }, 300);
}

// Load chat history
function loadChatHistory(targetUser) {
    socket.emit('get_pm_history', { target_user: targetUser });
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

// Load chat list
async function loadChatList() {
    try {
        const response = await fetch('/api/pm_chats');
        const chats = await response.json();
        renderChatList(chats);
    } catch (error) {
        console.error('Error loading chat list:', error);
    }
}

// Render chat list with improved timestamp
function renderChatList(chats) {
    if (!chatList) return;
    
    chatList.innerHTML = '';
    if (chatCount) {
        chatCount.textContent = chats.length;
    }
    
    chats.forEach(chat => {
        const clone = chatTemplate.content.cloneNode(true);
        const chatItem = clone.querySelector('.chat-item');
        const username = clone.querySelector('.chat-username');
        const time = clone.querySelector('.chat-time');
        const preview = clone.querySelector('.chat-preview');
        const count = clone.querySelector('.chat-count');
        
        // Set chat data
        username.textContent = chat.username;
        
        // Format timestamp for user's local timezone with high precision
        const messageDate = new Date(chat.last_message_time);
        const now = new Date();
        const isToday = messageDate.toDateString() === now.toDateString();
        const isYesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000).toDateString() === messageDate.toDateString();
        const timeDiff = now.getTime() - messageDate.getTime();
        
        let timeString;
        if (timeDiff < 60000) { // Less than 1 minute
            timeString = 'Just now';
        } else if (timeDiff < 3600000) { // Less than 1 hour
            const minutes = Math.floor(timeDiff / 60000);
            timeString = `${minutes}m ago`;
        } else if (isToday) {
            timeString = messageDate.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
            });
        } else if (isYesterday) {
            timeString = 'Yesterday';
        } else {
            timeString = messageDate.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric'
            });
        }
        
        time.textContent = timeString;
        preview.textContent = chat.last_message || 'No messages yet';
        
        // Set unread count
        if (chat.message_count > 0) {
            count.textContent = `${chat.message_count} msgs`;
      } else {
            count.textContent = '';
        }
        
        // Set link
        chatItem.href = `/pm/${chat.username}`;
        
        // Highlight current chat
        if (currentChat === chat.username) {
            chatItem.classList.add('active');
        }
        
        chatList.appendChild(clone);
    });
}

// Update online status periodically
function updateOnlineStatus() {
    socket.emit('ping');
}

// Socket Events
socket.on('pm_chats', (chats) => {
    renderChatList(chats);
});

socket.on('pm_history', (messages) => {
    if (chatBox) {
        chatBox.innerHTML = '';
        messages.forEach(renderMessage);
    }
});

socket.on('new_pm', (message) => {
    // Only show if it's for current chat
    if (currentChat && (message.sender === currentChat || message.recipient === currentChat)) {
        renderMessage(message);
    }
    
    // Update chat list to show new message
    socket.emit('get_pm_chats');
});

socket.on('pm_typing', (data) => {
    if (typingIndicator && currentChat === data.sender) {
        typingIndicator.style.display = 'block';
        typingIndicator.innerHTML = `<i class="bi bi-three-dots"></i> ${data.sender} is typing...`;
    }
});

socket.on('pm_stop_typing', (data) => {
    if (typingIndicator && currentChat === data.sender) {
        typingIndicator.style.display = 'none';
    }
});

socket.on('search_results', (users) => {
    const searchResults = document.getElementById('search-results');
    if (searchResults) {
        searchResults.innerHTML = '';
        
        users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'search-result-item p-2 border-bottom';
            div.innerHTML = `
                <a href="/pm/${user.username}" class="text-decoration-none">
                    <div class="d-flex align-items-center">
                        <div class="avatar-sm bg-primary rounded-circle d-flex align-items-center justify-content-center me-2">
                            <i class="bi bi-person text-white"></i>
                        </div>
                        <div>
                            <div class="fw-bold">${user.username}</div>
                            <small class="text-muted">${user.display_name || ''}</small>
                        </div>
                    </div>
                </a>
            `;
            searchResults.appendChild(div);
        });
        
        if (users.length === 0) {
            searchResults.innerHTML = '<div class="p-2 text-muted">No users found</div>';
        }
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

// Handle chat switching
function switchChat(username) {
    if (currentChat !== username) {
        currentChat = username;
        loadChatHistory(username);
    }
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
    if (currentChat) {
        socket.emit('user_active', { recipient: currentChat });
    }
});

window.addEventListener('blur', () => {
    if (currentChat) {
        socket.emit('user_inactive', { recipient: currentChat });
    }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (currentChat) {
        socket.emit('leave_pm', { recipient: currentChat });
    }
});