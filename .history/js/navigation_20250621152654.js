// Navigation Module
// Handles navigation updates and route protection

class NavigationManager {
    constructor() {
        this.authManager = window.authManager;
        this.init();
    }

    init() {
        // Wait for auth manager to be ready
        setTimeout(() => {
            this.updateNavigation();
            this.protectRoutes();
        }, 100);
    }

    updateNavigation() {
        const currentUser = this.authManager.getCurrentUser();
        const isAdmin = this.authManager.isUserAdmin();

        // Update user info in navigation if available
        const userInfoElements = document.querySelectorAll('.user-info');
        userInfoElements.forEach(element => {
            if (currentUser) {
                element.textContent = currentUser.email;
            } else {
                element.textContent = 'Guest';
            }
        });

        // Update admin badge
        const adminBadges = document.querySelectorAll('.admin-badge');
        adminBadges.forEach(badge => {
            if (isAdmin) {
                badge.classList.remove('d-none');
            } else {
                badge.classList.add('d-none');
            }
        });
    }

    protectRoutes() {
        const currentPath = window.location.pathname;
        const currentUser = this.authManager.getCurrentUser();
        const isAdmin = this.authManager.isUserAdmin();

        // Protected routes that require authentication
        const protectedRoutes = ['/dashboard.html', '/chat.html'];
        
        // Admin-only routes
        const adminRoutes = ['/admin.html'];

        // Check if current page requires authentication
        if (protectedRoutes.some(route => currentPath.includes(route))) {
            if (!currentUser) {
                window.location.href = 'login.html';
                return;
            }
        }

        // Check if current page requires admin access
        if (adminRoutes.some(route => currentPath.includes(route))) {
            if (!currentUser) {
                window.location.href = 'login.html';
                return;
            }
            if (!isAdmin) {
                window.location.href = 'dashboard.html';
                return;
            }
        }

        // Redirect authenticated users away from auth pages
        if (currentUser && (currentPath.includes('login.html') || currentPath.includes('register.html'))) {
            window.location.href = 'dashboard.html';
        }
    }

    showLoading() {
        const loadingElement = document.createElement('div');
        loadingElement.className = 'loading-overlay';
        loadingElement.innerHTML = `
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        `;
        document.body.appendChild(loadingElement);
    }

    hideLoading() {
        const loadingElement = document.querySelector('.loading-overlay');
        if (loadingElement) {
            loadingElement.remove();
        }
    }
}

// Initialize navigation manager
window.navigationManager = new NavigationManager();

// Add loading overlay styles
const style = document.createElement('style');
style.textContent = `
    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(255, 255, 255, 0.8);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 9999;
    }
`;
document.head.appendChild(style); 