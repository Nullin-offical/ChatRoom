// Dashboard Module
// Handles dashboard functionality and user data display

class DashboardManager {
    constructor() {
        this.supabase = window.supabaseClient;
        this.authManager = window.authManager;
        this.init();
    }

    async init() {
        // Wait for auth manager to be ready
        setTimeout(async () => {
            if (this.authManager.requireAuth()) {
                await this.loadUserData();
                await this.loadUserStats();
                await this.loadRecentActivity();
                this.updateAdminUI();
            }
        }, 200);
    }

    async loadUserData() {
        try {
            const currentUser = this.authManager.getCurrentUser();
            if (!currentUser) return;

            // Get user profile data
            const { data: profile, error } = await this.supabase
                .from('profiles')
                .select('username, is_admin')
                .eq('user_id', currentUser.id)
                .single();

            if (error) throw error;

            // Update UI with user data
            document.getElementById('userName').textContent = profile?.username || 'User';
            document.getElementById('userEmail').textContent = currentUser.email;

            // Update admin badge
            const adminBadge = document.querySelector('.admin-badge');
            if (profile?.is_admin) {
                adminBadge.classList.remove('d-none');
            } else {
                adminBadge.classList.add('d-none');
            }

        } catch (error) {
            console.error('Error loading user data:', error);
            document.getElementById('userName').textContent = 'User';
            document.getElementById('userEmail').textContent = 'Error loading data';
        }
    }

    async loadUserStats() {
        try {
            const currentUser = this.authManager.getCurrentUser();
            if (!currentUser) return;

            // Get message count
            const { count: messageCount, error: messageError } = await this.supabase
                .from('messages')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', currentUser.id);

            if (messageError) throw messageError;

            // Update message count
            document.getElementById('messageCount').textContent = messageCount || 0;

            // Format join date
            const joinDate = new Date(currentUser.created_at);
            const formattedDate = joinDate.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
            document.getElementById('joinDate').textContent = formattedDate;

        } catch (error) {
            console.error('Error loading user stats:', error);
            document.getElementById('messageCount').textContent = '0';
            document.getElementById('joinDate').textContent = '-';
        }
    }

    async loadRecentActivity() {
        try {
            const currentUser = this.authManager.getCurrentUser();
            if (!currentUser) return;

            // Get recent messages by the user
            const { data: recentMessages, error } = await this.supabase
                .from('messages')
                .select(`
                    id,
                    content,
                    created_at,
                    profiles!inner(username)
                `)
                .eq('user_id', currentUser.id)
                .order('created_at', { ascending: false })
                .limit(5);

            if (error) throw error;

            this.displayRecentActivity(recentMessages || []);

        } catch (error) {
            console.error('Error loading recent activity:', error);
            this.displayRecentActivity([]);
        }
    }

    displayRecentActivity(messages) {
        const activityContainer = document.getElementById('recentActivity');

        if (messages.length === 0) {
            activityContainer.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-comment-slash fa-2x mb-2"></i>
                    <p>No recent activity</p>
                    <small>Start chatting to see your recent messages here!</small>
                </div>
            `;
            return;
        }

        const activityHTML = messages.map(message => {
            const messageDate = new Date(message.created_at);
            const timeAgo = this.getTimeAgo(messageDate);
            const truncatedContent = message.content.length > 50 
                ? message.content.substring(0, 50) + '...' 
                : message.content;

            return `
                <div class="activity-item d-flex align-items-center p-3 border-bottom">
                    <div class="activity-icon me-3">
                        <i class="fas fa-comment text-primary"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <strong>You</strong> sent a message
                                <p class="mb-0 text-muted small">${truncatedContent}</p>
                            </div>
                            <small class="text-muted">${timeAgo}</small>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        activityContainer.innerHTML = activityHTML;
    }

    getTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);

        if (diffInSeconds < 60) {
            return 'Just now';
        } else if (diffInSeconds < 3600) {
            const minutes = Math.floor(diffInSeconds / 60);
            return `${minutes}m ago`;
        } else if (diffInSeconds < 86400) {
            const hours = Math.floor(diffInSeconds / 3600);
            return `${hours}h ago`;
        } else {
            const days = Math.floor(diffInSeconds / 86400);
            return `${days}d ago`;
        }
    }

    updateAdminUI() {
        const isAdmin = this.authManager.isUserAdmin();
        const adminElements = document.querySelectorAll('.admin-only');

        adminElements.forEach(element => {
            if (isAdmin) {
                element.classList.remove('d-none');
            } else {
                element.classList.add('d-none');
            }
        });
    }
}

// Initialize dashboard manager
window.dashboardManager = new DashboardManager(); 