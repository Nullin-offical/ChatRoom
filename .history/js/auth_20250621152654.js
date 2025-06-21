// Authentication Module
// Handles user authentication, registration, and session management

class AuthManager {
    constructor() {
        this.supabase = window.supabaseClient;
        this.currentUser = null;
        this.isAdmin = false;
        this.init();
    }

    async init() {
        // Check for existing session
        const { data: { session } } = await this.supabase.auth.getSession();
        if (session) {
            this.currentUser = session.user;
            await this.checkAdminStatus();
            this.updateUI();
        }

        // Listen for auth state changes
        this.supabase.auth.onAuthStateChange(async (event, session) => {
            if (event === 'SIGNED_IN' && session) {
                this.currentUser = session.user;
                await this.checkAdminStatus();
                this.updateUI();
                this.showToast('Successfully logged in!', 'success');
            } else if (event === 'SIGNED_OUT') {
                this.currentUser = null;
                this.isAdmin = false;
                this.updateUI();
                this.showToast('Successfully logged out!', 'info');
            }
        });
    }

    async register(email, password, username) {
        try {
            const { data, error } = await this.supabase.auth.signUp({
                email,
                password,
                options: {
                    data: {
                        username: username
                    }
                }
            });

            if (error) throw error;

            // Create profile record
            if (data.user) {
                const { error: profileError } = await this.supabase
                    .from('profiles')
                    .insert([
                        {
                            user_id: data.user.id,
                            username: username,
                            is_admin: false
                        }
                    ]);

                if (profileError) {
                    console.error('Error creating profile:', profileError);
                }
            }

            return { success: true, data };
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: error.message };
        }
    }

    async login(email, password) {
        try {
            const { data, error } = await this.supabase.auth.signInWithPassword({
                email,
                password
            });

            if (error) throw error;

            return { success: true, data };
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: error.message };
        }
    }

    async logout() {
        try {
            const { error } = await this.supabase.auth.signOut();
            if (error) throw error;
            return { success: true };
        } catch (error) {
            console.error('Logout error:', error);
            return { success: false, error: error.message };
        }
    }

    async checkAdminStatus() {
        if (!this.currentUser) return;

        try {
            const { data, error } = await this.supabase
                .from('profiles')
                .select('is_admin')
                .eq('user_id', this.currentUser.id)
                .single();

            if (error) throw error;
            this.isAdmin = data?.is_admin || false;
        } catch (error) {
            console.error('Error checking admin status:', error);
            this.isAdmin = false;
        }
    }

    updateUI() {
        const authLinks = document.querySelectorAll('#auth-links');
        const userLinks = document.querySelectorAll('#user-links');
        const adminLinks = document.querySelectorAll('#admin-links');

        if (this.currentUser) {
            // User is logged in
            authLinks.forEach(link => link.classList.add('d-none'));
            userLinks.forEach(link => link.classList.remove('d-none'));
            
            if (this.isAdmin) {
                adminLinks.forEach(link => link.classList.remove('d-none'));
            } else {
                adminLinks.forEach(link => link.classList.add('d-none'));
            }
        } else {
            // User is not logged in
            authLinks.forEach(link => link.classList.remove('d-none'));
            userLinks.forEach(link => link.classList.add('d-none'));
            adminLinks.forEach(link => link.classList.add('d-none'));
        }
    }

    showToast(message, type = 'info') {
        // Create toast notification
        const toastContainer = document.querySelector('.toast-container') || 
            (() => {
                const container = document.createElement('div');
                container.className = 'toast-container';
                document.body.appendChild(container);
                return container;
            })();

        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Remove toast after it's hidden
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    getCurrentUser() {
        return this.currentUser;
    }

    isUserAdmin() {
        return this.isAdmin;
    }

    requireAuth() {
        if (!this.currentUser) {
            window.location.href = 'login.html';
            return false;
        }
        return true;
    }

    requireAdmin() {
        if (!this.requireAuth()) return false;
        if (!this.isAdmin) {
            window.location.href = 'dashboard.html';
            return false;
        }
        return true;
    }
}

// Initialize auth manager
window.authManager = new AuthManager();

// Handle logout button
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            const result = await window.authManager.logout();
            if (result.success) {
                window.location.href = 'index.html';
            }
        });
    }
}); 