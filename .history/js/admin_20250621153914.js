// Admin Module
// Handles admin panel functionality

class AdminManager {
    constructor() {
        this.supabase = window.supabaseClient;
        this.authManager = window.authManager;
        this.init();
    }

    async init() {
        // Wait for auth manager to be ready
        setTimeout(async () => {
            if (this.authManager.requireAdmin()) {
                await this.loadAdminStats();
                await this.loadUsers();
                await this.loadMessages();
                this.setupEventListeners();
            }
        }, 200);
    }

    async loadAdminStats() {
        try {
            // Get total users count
            const { count: totalUsers, error: usersError } = await this.supabase
                .from('profiles')
                .select('*', { count: 'exact', head: true });

            if (usersError) throw usersError;

            // Get total messages count
            const { count: totalMessages, error: messagesError } = await this.supabase
                .from('messages')
                .select('*', { count: 'exact', head: true });

            if (messagesError) throw messagesError;

            // Get admin users count
            const { count: adminUsers, error: adminError } = await this.supabase
                .from('profiles')
                .select('*', { count: 'exact', head: true })
                .eq('is_admin', true);

            if (adminError) throw adminError;

            // Update UI
            document.getElementById('totalUsers').textContent = totalUsers || 0;
            document.getElementById('totalMessages').textContent = totalMessages || 0;
            document.getElementById('adminUsers').textContent = adminUsers || 0;

        } catch (error) {
            console.error('Error loading admin stats:', error);
        }
    }

    async loadUsers() {
        try {
            const { data: users, error } = await this.supabase
                .from('profiles')
                .select(`
                    user_id,
                    username,
                    is_admin,
                    created_at,
                    auth.users!inner(email)
                `)
                .order('created_at', { ascending: false });

            if (error) throw error;

            this.displayUsers(users || []);

        } catch (error) {
            console.error('Error loading users:', error);
            this.showError('Failed to load users');
        }
    }

    async loadMessages() {
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
                .order('created_at', { ascending: false })
                .limit(100);

            if (error) throw error;

            this.displayMessages(messages || []);

        } catch (error) {
            console.error('Error loading messages:', error);
            this.showError('Failed to load messages');
        }
    }

    displayUsers(users) {
        const tbody = document.getElementById('usersTableBody');
        
        if (users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        <i class="fas fa-users fa-2x mb-2"></i>
                        <p>No users found</p>
                    </td>
                </tr>
            `;
            return;
        }

        const usersHTML = users.map(user => {
            const joinDate = new Date(user.created_at);
            const formattedDate = joinDate.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });

            return `
                <tr>
                    <td>
                        <strong>${user.username || 'Unknown'}</strong>
                        ${user.is_admin ? '<span class="badge bg-warning ms-1">Admin</span>' : ''}
                    </td>
                    <td>${user.auth?.users?.email || 'N/A'}</td>
                    <td>
                        ${user.is_admin ? 
                            '<span class="badge bg-warning">Admin</span>' : 
                            '<span class="badge bg-secondary">User</span>'
                        }
                    </td>
                    <td>${formattedDate}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-info" onclick="window.adminManager.getUserMessageCount('${user.user_id}')">
                            Count
                        </button>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            ${!user.is_admin ? 
                                `<button class="btn btn-outline-warning" onclick="window.adminManager.makeAdmin('${user.user_id}')">
                                    <i class="fas fa-crown"></i>
                                </button>` : ''
                            }
                            <button class="btn btn-outline-danger" onclick="window.adminManager.deleteUser('${user.user_id}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = usersHTML;
    }

    displayMessages(messages) {
        const tbody = document.getElementById('messagesTableBody');
        
        if (messages.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted">
                        <i class="fas fa-comment-slash fa-2x mb-2"></i>
                        <p>No messages found</p>
                    </td>
                </tr>
            `;
            return;
        }

        const messagesHTML = messages.map(message => {
            const messageDate = new Date(message.created_at);
            const timeString = messageDate.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });

            const truncatedContent = message.content.length > 50 
                ? message.content.substring(0, 50) + '...' 
                : message.content;

            return `
                <tr>
                    <td>
                        <strong>${message.profiles?.username || 'Unknown User'}</strong>
                    </td>
                    <td>${this.escapeHtml(truncatedContent)}</td>
                    <td>${timeString}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="window.adminManager.deleteMessage('${message.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = messagesHTML;
    }

    setupEventListeners() {
        const refreshUsersBtn = document.getElementById('refreshUsers');
        const clearAllMessagesBtn = document.getElementById('clearAllMessages');
        const createAdminForm = document.getElementById('createAdminForm');
        const userSearch = document.getElementById('userSearch');
        const messageSearch = document.getElementById('messageSearch');

        // Refresh users
        refreshUsersBtn.addEventListener('click', async () => {
            await this.loadUsers();
            await this.loadAdminStats();
        });

        // Clear all messages
        clearAllMessagesBtn.addEventListener('click', async () => {
            if (confirm('Are you sure you want to delete ALL messages? This action cannot be undone.')) {
                await this.clearAllMessages();
            }
        });

        // Create admin form
        createAdminForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('adminEmail').value.trim();
            await this.makeAdminByEmail(email);
            createAdminForm.reset();
        });

        // Search functionality
        userSearch.addEventListener('input', (e) => {
            this.filterUsers(e.target.value);
        });

        messageSearch.addEventListener('input', (e) => {
            this.filterMessages(e.target.value);
        });
    }

    async makeAdmin(userId) {
        try {
            const { error } = await this.supabase
                .from('profiles')
                .update({ is_admin: true })
                .eq('user_id', userId);

            if (error) throw error;

            this.showSuccess('User promoted to admin successfully');
            await this.loadUsers();
            await this.loadAdminStats();

        } catch (error) {
            console.error('Error making user admin:', error);
            this.showError('Failed to promote user to admin');
        }
    }

    async makeAdminByEmail(email) {
        try {
            // First find the user by email
            const { data: user, error: userError } = await this.supabase
                .from('profiles')
                .select('user_id')
                .eq('auth.users.email', email)
                .single();

            if (userError) throw userError;

            // Then make them admin
            await this.makeAdmin(user.user_id);

        } catch (error) {
            console.error('Error making user admin by email:', error);
            this.showError('User not found or failed to promote to admin');
        }
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user? This will also delete all their messages.')) {
            return;
        }

        try {
            // Delete user's messages first
            const { error: messagesError } = await this.supabase
                .from('messages')
                .delete()
                .eq('user_id', userId);

            if (messagesError) throw messagesError;

            // Delete user profile
            const { error: profileError } = await this.supabase
                .from('profiles')
                .delete()
                .eq('user_id', userId);

            if (profileError) throw profileError;

            this.showSuccess('User deleted successfully');
            await this.loadUsers();
            await this.loadAdminStats();

        } catch (error) {
            console.error('Error deleting user:', error);
            this.showError('Failed to delete user');
        }
    }

    async deleteMessage(messageId) {
        if (!confirm('Are you sure you want to delete this message?')) {
            return;
        }

        try {
            const { error } = await this.supabase
                .from('messages')
                .delete()
                .eq('id', messageId);

            if (error) throw error;

            this.showSuccess('Message deleted successfully');
            await this.loadMessages();
            await this.loadAdminStats();

        } catch (error) {
            console.error('Error deleting message:', error);
            this.showError('Failed to delete message');
        }
    }

    async clearAllMessages() {
        try {
            const { error } = await this.supabase
                .from('messages')
                .delete()
                .neq('id', 0);

            if (error) throw error;

            this.showSuccess('All messages cleared successfully');
            await this.loadMessages();
            await this.loadAdminStats();

        } catch (error) {
            console.error('Error clearing messages:', error);
            this.showError('Failed to clear messages');
        }
    }

    async getUserMessageCount(userId) {
        try {
            const { count, error } = await this.supabase
                .from('messages')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', userId);

            if (error) throw error;

            this.showInfo(`User has sent ${count || 0} messages`);

        } catch (error) {
            console.error('Error getting message count:', error);
            this.showError('Failed to get message count');
        }
    }

    filterUsers(searchTerm) {
        const rows = document.querySelectorAll('#usersTableBody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm.toLowerCase()) ? '' : 'none';
        });
    }

    filterMessages(searchTerm) {
        const rows = document.querySelectorAll('#messagesTableBody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm.toLowerCase()) ? '' : 'none';
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showSuccess(message) {
        if (window.authManager) {
            window.authManager.showToast(message, 'success');
        }
    }

    showError(message) {
        if (window.authManager) {
            window.authManager.showToast(message, 'danger');
        }
    }

    showInfo(message) {
        if (window.authManager) {
            window.authManager.showToast(message, 'info');
        }
    }
}

// Initialize admin manager
window.adminManager = new AdminManager(); 