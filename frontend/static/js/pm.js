// Private Messaging Application
const socket = io();

// DOM Elements
const chatBox = document.getElementById('chat-box');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const chatList = document.getElementById('chat-list');
const chatListMobile = document.getElementById('chat-list-mobile');
const chatCount = document.getElementById('chat-count');
const userSearchForm = document.getElementById('user-search-form');
const userSearchFormMobile = document.getElementById('user-search-form-mobile');
const userSearchInput = document.getElementById('user-search-input');
const userSearchInputMobile = document.getElementById('user-search-input-mobile');
const searchResults = document.getElementById('search-results');
const searchResultsMobile = document.getElementById('search-results-mobile');
const typingIndicator = document.getElementById('typing-indicator');

// Templates
const messageTemplate = document.getElementById('message-template');
const chatTemplate = document.getElementById('chat-template');

// State
let currentChat = null;
let typingTimeout = null;
let searchTimeout = null;
let currentUserId = null;

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
    if (!timestamp) {
        console.warn('No timestamp provided to formatTime');
        return 'Unknown time';
    }
    
    try {
        const messageDate = new Date(timestamp);
        
        // Check if date is valid
        if (isNaN(messageDate.getTime())) {
            console.warn('Invalid timestamp:', timestamp);
            return 'Invalid time';
        }
        
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
    } catch (error) {
        console.error('Error formatting time:', error, 'timestamp:', timestamp);
        return 'Error';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('PM.js initialized');
    
    // Set current user ID
    currentUserId = window.currentUserId;
    console.log('Current user ID:', currentUserId);
    
    // Set target user if available
    if (window.targetUser) {
        currentChat = window.targetUser;
        console.log('Target user:', currentChat);
        
        // Check blocking state and update UI
        checkBlockingState();
        
        // Load chat history
        loadChatHistory(currentChat);
    }
    
    // Load chat list
    loadChatList();
    
    // Setup event listeners
    setupEventListeners();
    
    // Start periodic online status updates
    setInterval(updateOnlineStatus, 30000); // Every 30 seconds
    
    // Ensure chat scrolls to bottom after page load
    setTimeout(() => {
        if (chatBox && chatBox.children.length > 0) {
            console.log('Ensuring PM chat scrolls to bottom after page load');
            forceScrollToBottom();
        }
    }, 500);
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
    
    // Header action buttons
    const deleteChatBtn = document.getElementById('delete-chat-btn');
    const blockUserBtn = document.getElementById('block-user-btn');
    const unblockUserBtn = document.getElementById('unblock-user-btn');
    
    if (deleteChatBtn && window.targetUser) {
        deleteChatBtn.addEventListener('click', async () => {
            console.log('Delete chat button clicked for user:', window.targetUser);
            if (confirm(`Are you sure you want to delete the chat with ${window.targetUser}?`)) {
                try {
                    // First try to get user ID from current chat list
                    const response = await fetch('/api/pm_chats');
                    const chats = await response.json();
                    console.log('Available chats:', chats);
                    
                    let currentChat = chats.find(chat => chat.username === window.targetUser);
                    let userId = null;
                    
                    if (currentChat) {
                        userId = currentChat.user_id;
                        console.log('Found user ID from chat list:', userId);
                    } else {
                        // If not in chat list, search for user directly
                        console.log('User not in chat list, searching directly...');
                        const searchResponse = await fetch(`/api/search_users?q=${encodeURIComponent(window.targetUser)}`);
                        const users = await searchResponse.json();
                        console.log('Search results:', users);
                        
                        const user = users.find(u => u.username === window.targetUser);
                        if (user) {
                            userId = user.id;
                            console.log('Found user ID from search:', userId);
                        }
                    }
                    
                    if (userId) {
                        console.log('Calling deleteChat with ID:', userId);
                        deleteChat(userId);
                    } else {
                        console.error('Could not find user ID for:', window.targetUser);
                        showNotification('Could not find user information', 'error');
                    }
                } catch (error) {
                    console.error('Error in delete chat button handler:', error);
                    showNotification('Error processing delete request', 'error');
                }
            }
        });
    }
    
    if (blockUserBtn && window.targetUser) {
        blockUserBtn.addEventListener('click', async () => {
            console.log('Block button clicked for user:', window.targetUser);
            if (confirm(`Are you sure you want to block ${window.targetUser}?`)) {
                try {
                    // First try to get user ID from current chat list
                    const response = await fetch('/api/pm_chats');
                    const chats = await response.json();
                    console.log('Available chats:', chats);
                    
                    let currentChat = chats.find(chat => chat.username === window.targetUser);
                    let userId = null;
                    
                    if (currentChat) {
                        userId = currentChat.user_id;
                        console.log('Found user ID from chat list:', userId);
                    } else {
                        // If not in chat list, search for user directly
                        console.log('User not in chat list, searching directly...');
                        const searchResponse = await fetch(`/api/search_users?q=${encodeURIComponent(window.targetUser)}`);
                        const users = await searchResponse.json();
                        console.log('Search results:', users);
                        
                        const user = users.find(u => u.username === window.targetUser);
                        if (user) {
                            userId = user.id;
                            console.log('Found user ID from search:', userId);
                        }
                    }
                    
                    if (userId) {
                        console.log('Calling blockUser with ID:', userId, 'username:', window.targetUser);
                        await blockUser(userId, window.targetUser);
                        // Update button state after blocking
                        updateBlockButtonState(true);
                    } else {
                        console.error('Could not find user ID for:', window.targetUser);
                        showNotification('Could not find user information', 'error');
                    }
                } catch (error) {
                    console.error('Error in block button handler:', error);
                    showNotification('Error processing block request', 'error');
                }
            }
        });
    }
    
    if (unblockUserBtn && window.targetUser) {
        unblockUserBtn.addEventListener('click', async () => {
            console.log('Unblock button clicked for user:', window.targetUser);
            if (confirm(`Are you sure you want to unblock ${window.targetUser}?`)) {
                try {
                    // First try to get user ID from current chat list
                    const response = await fetch('/api/pm_chats');
                    const chats = await response.json();
                    console.log('Available chats:', chats);
                    
                    let currentChat = chats.find(chat => chat.username === window.targetUser);
                    let userId = null;
                    
                    if (currentChat) {
                        userId = currentChat.user_id;
                        console.log('Found user ID from chat list:', userId);
                    } else {
                        // If not in chat list (because blocked), search for user directly
                        console.log('User not in chat list, searching directly...');
                        const searchResponse = await fetch(`/api/search_users?q=${encodeURIComponent(window.targetUser)}`);
                        const users = await searchResponse.json();
                        console.log('Search results:', users);
                        
                        const user = users.find(u => u.username === window.targetUser);
                        if (user) {
                            userId = user.id;
                            console.log('Found user ID from search:', userId);
                        }
                    }
                    
                    if (userId) {
                        console.log('Calling unblockUser with ID:', userId, 'username:', window.targetUser);
                        await unblockUser(userId, window.targetUser);
                        // Update button state after unblocking
                        updateBlockButtonState(false);
                    } else {
                        console.error('Could not find user ID for:', window.targetUser);
                        showNotification('Could not find user information', 'error');
                    }
                } catch (error) {
                    console.error('Error in unblock button handler:', error);
                    showNotification('Error processing unblock request', 'error');
                }
            }
        });
    }
    
    // User search forms
    if (userSearchForm) {
        userSearchForm.addEventListener('submit', handleUserSearch);
    }
    
    if (userSearchFormMobile) {
        userSearchFormMobile.addEventListener('submit', handleUserSearch);
    }
    
    // User search inputs
    if (userSearchInput) {
        userSearchInput.addEventListener('input', handleSearch);
        userSearchInput.addEventListener('focus', () => {
            if (searchResults) {
                searchResults.style.display = 'block';
            }
        });
    }
    
    if (userSearchInputMobile) {
        userSearchInputMobile.addEventListener('input', handleSearch);
        userSearchInputMobile.addEventListener('focus', () => {
            if (searchResultsMobile) {
                searchResultsMobile.style.display = 'block';
            }
        });
    }
    
    // Close search results when clicking outside
    document.addEventListener('click', (e) => {
        const searchInputs = [userSearchInput, userSearchInputMobile];
        const searchResultsList = [searchResults, searchResultsMobile];
        
        const isClickInsideSearch = searchInputs.some(input => input && input.contains(e.target));
        const isClickInsideResults = searchResultsList.some(results => results && results.contains(e.target));
        
        if (!isClickInsideSearch && !isClickInsideResults) {
            searchResultsList.forEach(results => {
                if (results) {
                    results.style.display = 'none';
                }
            });
        }
    });
}

// Handle message submission
function handleMessageSubmit(e) {
    e.preventDefault();
    const content = messageInput.value.trim();
    
    // Debug logging
    console.log('Sending PM:', { content, currentChat, targetUser: window.targetUser });
    
    if (!content) {
        console.error('No content to send');
        return;
    }
    
    // Use currentChat or fallback to window.targetUser
    const recipient = currentChat || window.targetUser;
    
    if (!recipient) {
        console.error('No recipient specified');
        alert('Please select a user to send message to');
        return;
    }
    
    console.log('Sending to recipient:', recipient);
    
    socket.emit('send_pm', {
        content: content,
        recipient: recipient
    });
    
    messageInput.value = '';
    messageInput.focus();
}

// Handle user search
function handleUserSearch(e) {
    e.preventDefault();
    const form = e.target;
    const input = form.querySelector('input[type="text"]');
    const query = input.value.trim();
    
    if (query) {
        // Navigate to PM with the searched user
        window.location.href = `/pm/${query}`;
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

// Handle search with live results
function handleSearch() {
    const inputs = [userSearchInput, userSearchInputMobile];
    const results = [searchResults, searchResultsMobile];
    
    inputs.forEach((input, index) => {
        if (!input) return;
        
        const query = input.value.trim();
        const resultContainer = results[index];
        
        // Clear existing timeout
        if (searchTimeout) {
            clearTimeout(searchTimeout);
        }
        
        // Set new timeout for debouncing
        searchTimeout = setTimeout(async () => {
            if (query.length >= 2) {
                try {
                    const response = await fetch(`/api/search_users?q=${encodeURIComponent(query)}`);
                    const users = await response.json();
                    renderSearchResults(users, resultContainer);
                } catch (error) {
                    console.error('Error searching users:', error);
                }
            } else {
                if (resultContainer) {
                    resultContainer.innerHTML = '';
                    resultContainer.style.display = 'none';
                }
            }
        }, 300);
    });
}

// Render search results
function renderSearchResults(users, container) {
    console.log('Rendering search results:', users);
    
    if (!container) {
        console.error('Search results container not found');
        return;
    }
    
    container.innerHTML = '';
    
    if (!users || users.length === 0) {
        container.innerHTML = '<div class="search-result-item text-muted">No users found</div>';
        container.style.display = 'block';
        return;
    }
    
    users.forEach(user => {
        // Handle both string usernames and user objects
        const username = typeof user === 'string' ? user : (user.username || 'Unknown');
        const displayName = user.display_name || username;
        
        const resultItem = document.createElement('div');
        resultItem.className = 'search-result-item';
        
        // Safe fallback for first character
        const firstChar = username && username.length > 0 ? username[0].toUpperCase() : 'U';
        
        resultItem.innerHTML = `
            <div class="avatar-sm bg-primary rounded-circle d-flex align-items-center justify-content-center">
                <span class="text-white fw-bold">${firstChar}</span>
            </div>
            <div class="flex-grow-1">
                <div class="fw-bold">${displayName}</div>
                <small class="text-muted">Click to start chat</small>
            </div>
        `;
        
        resultItem.addEventListener('click', () => {
            console.log('Navigating to PM with user:', username);
            window.location.href = `/pm/${username}`;
        });
        
        container.appendChild(resultItem);
    });
    
    container.style.display = 'block';
}

// Load chat history
function loadChatHistory(targetUser) {
    console.log('Loading chat history for user:', targetUser);
    if (!targetUser) {
        console.error('No target user specified for chat history');
        return;
    }
    
    // Clear existing messages
    if (chatBox) {
        chatBox.innerHTML = '';
    }
    
    socket.emit('get_pm_history', { target_user: targetUser });
}

// Render a single message
function renderMessage(message) {
    console.log('Rendering message:', message);
    
    if (!messageTemplate || !chatBox) {
        console.log('Message template or chat box not found');
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

// Load chat list
async function loadChatList() {
    try {
        const response = await fetch('/api/pm_chats');
        const chats = await response.json();
        
        // Get blocked users to check state
        const blockedResponse = await fetch('/api/blocked_users');
        const blockedUsers = await blockedResponse.json();
        const blockedUsernames = blockedUsers.map(user => user.username);
        
        renderChatList(chats, blockedUsernames);
    } catch (error) {
        console.error('Error loading chat list:', error);
    }
}

// Render chat list with improved timestamp
function renderChatList(chats, blockedUsernames = []) {
    const lists = [chatList, chatListMobile].filter(Boolean);
    
    lists.forEach(list => {
        if (!list) return;
        
        list.innerHTML = '';
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
            const chatLink = clone.querySelector('.chat-link');
            const deleteBtn = clone.querySelector('.delete-chat-btn');
            const blockBtn = clone.querySelector('.block-user-btn');
            const unblockBtn = clone.querySelector('.unblock-user-btn');
            
            // Set chat data
            username.textContent = chat.username;
            chatItem.setAttribute('data-user-id', chat.user_id);
            
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
            chatLink.href = `/pm/${chat.username}`;
            
            // Check if user is blocked and update button accordingly
            const isBlocked = blockedUsernames.includes(chat.username);
            if (blockBtn && unblockBtn) {
                if (isBlocked) {
                    blockBtn.style.display = 'none';
                    unblockBtn.style.display = 'inline-block';
                } else {
                    blockBtn.style.display = 'inline-block';
                    unblockBtn.style.display = 'none';
                }
            }
            
            // Add event listeners for action buttons
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (confirm(`Are you sure you want to delete the chat with ${chat.username}?`)) {
                        deleteChat(chat.user_id);
                    }
                });
            }
            
            // Block button event listener
            if (blockBtn) {
                blockBtn.addEventListener('click', async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    if (confirm(`Are you sure you want to block ${chat.username}?`)) {
                        await blockUser(chat.user_id, chat.username);
                        // Reload chat list to update button states
                        loadChatList();
                    }
                });
            }
            
            // Unblock button event listener
            if (unblockBtn) {
                unblockBtn.addEventListener('click', async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    if (confirm(`Are you sure you want to unblock ${chat.username}?`)) {
                        await unblockUser(chat.user_id, chat.username);
                        // Reload chat list to update button states
                        loadChatList();
                    }
                });
            }
            
            // Highlight current chat
            if (currentChat === chat.username) {
                chatItem.classList.add('active');
            }
            
            list.appendChild(clone);
        });
    });
}

// Auto scroll to bottom
function autoScroll() {
    if (chatBox) {
        console.log('Auto scrolling chat box');
        // Always scroll to bottom with smooth animation
        chatBox.scrollTo({
            top: chatBox.scrollHeight,
            behavior: 'smooth'
        });
        
        // Fallback for older browsers
        setTimeout(() => {
            chatBox.scrollTop = chatBox.scrollHeight;
        }, 100);
    } else {
        console.warn('Chat box not found for auto scroll');
    }
}

// Force scroll to bottom (for page load/refresh)
function forceScrollToBottom() {
    if (chatBox) {
        // Use setTimeout to ensure DOM is updated
        setTimeout(() => {
            chatBox.scrollTop = chatBox.scrollHeight;
        }, 10);
    }
}

// Update online status
function updateOnlineStatus() {
    socket.emit('ping');
}

// Socket Events
socket.on('pm_chats', (chats) => {
    console.log('Received PM chats:', chats);
    renderChatList(chats);
});

socket.on('pm_history', (messages) => {
    console.log('Received PM history:', messages);
    if (chatBox) {
        chatBox.innerHTML = '';
        messages.forEach(message => {
            const messageElement = renderMessage(message);
            if (messageElement) {
                chatBox.appendChild(messageElement);
            }
        });
        forceScrollToBottom();
    }
});

socket.on('new_pm', (message) => {
    console.log('Received new PM:', message);
    
    // Only show if it's for current chat
    if (currentChat && (message.sender === currentChat || message.recipient === currentChat)) {
        const messageElement = renderMessage(message);
        if (messageElement && chatBox) {
            chatBox.appendChild(messageElement);
            autoScroll();
        }
    }
    
    // Always update chat list to show new message
    console.log('Updating chat list after new PM');
    socket.emit('get_pm_chats');
});

socket.on('pm_typing', (data) => {
    if (currentChat && data.sender === currentChat) {
        if (typingIndicator) {
            typingIndicator.style.display = 'block';
        }
    }
});

socket.on('pm_stop_typing', (data) => {
    if (currentChat && data.sender === currentChat) {
        if (typingIndicator) {
            typingIndicator.style.display = 'none';
        }
    }
});

socket.on('user_search_results', (data) => {
    // This is handled by the fetch API now
});

socket.on('error', (data) => {
    console.error('Socket error:', data.message);
    alert('Error: ' + data.message);
});

// Update chat count
function updateChatCount() {
    const lists = [chatList, chatListMobile].filter(Boolean);
    const totalChats = lists.reduce((total, list) => {
        return total + (list ? list.children.length : 0);
    }, 0);
    
    if (chatCount) {
        chatCount.textContent = totalChats;
    }
}

// Delete chat conversation (one-sided deletion)
async function deleteChat(userId) {
    try {
        const response = await fetch(`/api/delete_chat/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Remove chat from UI
            const chatElement = document.querySelector(`[data-user-id="${userId}"]`);
            if (chatElement) {
                chatElement.remove();
            }
            
            // Update chat count
            updateChatCount();
            
            // Show success message
            showNotification('Chat deleted successfully', 'success');
            
            // If this was the current chat, redirect to PM index
            // Find the username from the chat element
            const usernameElement = chatElement?.querySelector('.chat-username');
            if (currentChat && usernameElement && currentChat === usernameElement.textContent) {
                window.location.href = '/pm';
            }
        } else {
            showNotification(data.error || 'Failed to delete chat', 'error');
        }
    } catch (error) {
        console.error('Error deleting chat:', error);
        showNotification('Failed to delete chat', 'error');
    }
}

// Block user
async function blockUser(userId, username) {
    try {
        const response = await fetch(`/api/block_user/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`User ${username} blocked successfully`, 'success');
            
            // Update header buttons if this is the current chat
            if (currentChat === username) {
                await checkBlockingState();
            }
            
            // Remove from chat list if present
            const chatElement = document.querySelector(`[data-user-id="${userId}"]`);
            if (chatElement) {
                chatElement.remove();
                updateChatCount();
            }
            
            // If this was the current chat, redirect to PM index
            if (currentChat === username) {
                window.location.href = '/pm';
            }
            
            // Reload chat list to update button states
            loadChatList();
        } else {
            showNotification(data.error || 'Failed to block user', 'error');
        }
    } catch (error) {
        console.error('Error blocking user:', error);
        showNotification('Failed to block user', 'error');
    }
}

// Unblock user
async function unblockUser(userId, username) {
    console.log(`Attempting to unblock user: ${username} (ID: ${userId})`);
    try {
        const response = await fetch(`/api/unblock_user/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        console.log(`Unblock response:`, data);
        
        if (response.ok) {
            showNotification(`User ${username} unblocked successfully`, 'success');
            
            // Update header buttons if this is the current chat
            if (currentChat === username) {
                console.log(`Updating header buttons for current chat: ${username}`);
                await checkBlockingState();
            }
            
            // Reload chat list to update button states
            console.log('Reloading chat list after unblock');
            loadChatList();
        } else {
            console.error(`Unblock failed: ${data.error}`);
            showNotification(data.error || 'Failed to unblock user', 'error');
        }
    } catch (error) {
        console.error('Error unblocking user:', error);
        showNotification('Failed to unblock user', 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'info'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Check if current user has blocked the target user
async function checkBlockingState() {
    console.log('Checking blocking state for target user:', window.targetUser);
    if (!window.targetUser) {
        console.log('No target user specified');
        return;
    }
    
    try {
        const response = await fetch('/api/blocked_users');
        const blockedUsers = await response.json();
        console.log('Blocked users:', blockedUsers);
        
        const isBlocked = blockedUsers.some(user => user.username === window.targetUser);
        console.log('Is user blocked:', isBlocked);
        
        updateBlockButtonState(isBlocked);
    } catch (error) {
        console.error('Error checking blocking state:', error);
    }
}

// Update block/unblock button state
function updateBlockButtonState(isBlocked) {
    console.log('Updating block button state, isBlocked:', isBlocked);
    const blockBtn = document.getElementById('block-user-btn');
    const unblockBtn = document.getElementById('unblock-user-btn');
    
    console.log('Found buttons - blockBtn:', blockBtn, 'unblockBtn:', unblockBtn);
    
    if (blockBtn && unblockBtn) {
        if (isBlocked) {
            console.log('User is blocked, showing unblock button');
            blockBtn.style.display = 'none';
            unblockBtn.style.display = 'inline-block';
        } else {
            console.log('User is not blocked, showing block button');
            blockBtn.style.display = 'inline-block';
            unblockBtn.style.display = 'none';
        }
    } else {
        console.error('Block or unblock button not found in DOM');
    }
}