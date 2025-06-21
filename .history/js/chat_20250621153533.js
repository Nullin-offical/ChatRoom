// Chat Module
// Handles real-time messaging functionality

class ChatManager {
    constructor() {
        this.supabase = window.supabaseClient;
        this.authManager = window.authManager;
        this.currentUser = null;
        this.userProfile = null;
        this.subscription = null;
        this.isConnected = false;
        this.init();
    }

    async init() {
        // Wait for auth manager to be ready
        setTimeout(async () => {
            if (this.authManager.requireAuth()) {
                this.currentUser = this.authManager.getCurrentUser();
                await this.loadUserProfile();
                await this.loadChatHistory();
                this.setupEventListeners();
                this.setupRealtimeSubscription();
                this.updateConnectionStatus();
            }
        }, 200);
    }

    async loadUserProfile() {
        try {
            const { data: profile, error } = await this.supabase
                .from('profiles')
                .select('username')
                .eq('user_id', this.currentUser.id)
                .single();

            if (error) throw error;
            this.userProfile = profile;
        } catch (error) {
            console.error('Error loading user profile:', error);
            this.userProfile = { username: 'User' };
        }
    }

    async loadChatHistory() {
        try {
            const { data: messages, error } = await this.supabase
                .from('messages')
                .select(`
                    id,
                    content,
                    created_at,
                    user_id,
                    profiles!inner(username)
                `)
                .order('created_at', { ascending: true })
                .limit(50);

            if (error) throw error;

            this.displayMessages(messages || []);
            this.scrollToBottom();

        } catch (error) {
            console.error('Error loading chat history:', error);
            this.showError('Failed to load chat history');
        }
    }

    setupEventListeners() {
        const messageForm = document.getElementById('messageForm');
        const messageInput = document.getElementById('messageInput');
        const clearChatBtn = document.getElementById('clearChatBtn');
        const charCount = document.getElementById('charCount');

        // Message form submission
        messageForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.sendMessage();
        });

        // Character count
        messageInput.addEventListener('input', () => {
            const count = messageInput.value.length;
            charCount.textContent = count;
            
            if (count > 450) {
                charCount.classList.add('text-warning');
            } else {
                charCount.classList.remove('text-warning');
            }
        });

        // Clear chat button
        clearChatBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to clear the chat? This action cannot be undone.')) {
                this.clearChat();
            }
        });

        // Enter key to send
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
    }

    setupRealtimeSubscription() {
        // Subscribe to new messages
        this.subscription = this.supabase
            .channel('messages')
            .on('postgres_changes', 
                { 
                    event: 'INSERT', 
                    schema: 'public', 
                    table: 'messages' 
                }, 
                (payload) => {
                    this.handleNewMessage(payload.new);
                }
            )
            .on('postgres_changes',
                {
                    event: 'DELETE',
                    schema: 'public',
                    table: 'messages'
                },
                (payload) => {
                    this.handleMessageDeleted(payload.old.id);
                }
            )
            .subscribe((status) => {
                this.isConnected = status === 'SUBSCRIBED';
                this.updateConnectionStatus();
            });
    }

    async sendMessage() {
        const messageInput = document.getElementById('messageInput');
        const content = messageInput.value.trim();

        if (!content) return;

        try {
            const { error } = await this.supabase
                .from('messages')
                .insert([
                    {
                        user_id: this.currentUser.id,
                        content: content
                    }
                ]);

            if (error) throw error;

            // Clear input
            messageInput.value = '';
            document.getElementById('charCount').textContent = '0';

        } catch (error) {
            console.error('Error sending message:', error);
            this.showError('Failed to send message');
        }
    }

    handleNewMessage(message) {
        // Get username for the message
        this.getUsernameForMessage(message.user_id).then(username => {
            message.username = username;
            this.addMessageToUI(message);
            this.scrollToBottom();
        });
    }

    handleMessageDeleted(messageId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (messageElement) {
            messageElement.remove();
        }
    }

    async getUsernameForMessage(userId) {
        try {
            const { data: profile, error } = await this.supabase
                .from('profiles')
                .select('username')
                .eq('user_id', userId)
                .single();

            if (error) throw error;
            return profile?.username || 'Unknown User';
        } catch (error) {
            console.error('Error getting username:', error);
            return 'Unknown User';
        }
    }

    displayMessages(messages) {
        const chatMessages = document.getElementById('chatMessages');
        
        if (messages.length === 0) {
            chatMessages.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-comment-slash fa-2x mb-2"></i>
                    <p>No messages yet</p>
                    <small>Be the first to start the conversation!</small>
                </div>
            `;
            return;
        }

        const messagesHTML = messages.map(message => this.createMessageHTML(message)).join('');
        chatMessages.innerHTML = messagesHTML;
    }

    addMessageToUI(message) {
        const chatMessages = document.getElementById('chatMessages');
        
        // Remove "no messages" placeholder if it exists
        const noMessagesDiv = chatMessages.querySelector('.text-center.text-muted');
        if (noMessagesDiv) {
            noMessagesDiv.remove();
        }

        const messageHTML = this.createMessageHTML(message);
        chatMessages.insertAdjacentHTML('beforeend', messageHTML);
    }

    createMessageHTML(message) {
        const isOwnMessage = message.user_id === this.currentUser.id;
        const messageClass = isOwnMessage ? 'own' : 'other';
        const messageDate = new Date(message.created_at);
        const timeString = messageDate.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });

        return `
            <div class="message ${messageClass} fade-in" data-message-id="${message.id}">
                <div class="message-header">
                    <strong>${message.username || 'Unknown User'}</strong>
                    <small class="text-muted ms-2">${timeString}</small>
                </div>
                <div class="message-content">
                    ${this.escapeHtml(message.content)}
                </div>
            </div>
        `;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    scrollToBottom() {
        const chatMessages = document.getElementById('chatMessages');
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        if (this.isConnected) {
            statusElement.className = 'badge bg-success me-2';
            statusElement.innerHTML = '<i class="fas fa-circle me-1"></i>Connected';
        } else {
            statusElement.className = 'badge bg-danger me-2';
            statusElement.innerHTML = '<i class="fas fa-circle me-1"></i>Disconnected';
        }
    }

    async clearChat() {
        try {
            const { error } = await this.supabase
                .from('messages')
                .delete()
                .neq('id', 0); // Delete all messages

            if (error) throw error;

            document.getElementById('chatMessages').innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="fas fa-comment-slash fa-2x mb-2"></i>
                    <p>Chat cleared</p>
                    <small>Start a new conversation!</small>
                </div>
            `;

            this.showSuccess('Chat cleared successfully');

        } catch (error) {
            console.error('Error clearing chat:', error);
            this.showError('Failed to clear chat');
        }
    }

    showError(message) {
        if (window.authManager) {
            window.authManager.showToast(message, 'danger');
        }
    }

    showSuccess(message) {
        if (window.authManager) {
            window.authManager.showToast(message, 'success');
        }
    }

    disconnect() {
        if (this.subscription) {
            this.supabase.removeChannel(this.subscription);
        }
    }
}

// Initialize chat manager
window.chatManager = new ChatManager(); 