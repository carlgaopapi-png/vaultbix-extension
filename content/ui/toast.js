/**
 * VaultBix Toast Notifications
 * Non-blocking notification system
 */

let toastContainer = null;

/**
 * Gets or creates the toast container
 */
function getContainer() {
    if (toastContainer && document.body.contains(toastContainer)) {
        return toastContainer;
    }
    
    toastContainer = document.createElement('div');
    toastContainer.className = 'vb-root vb-toast-container';
    toastContainer.setAttribute('role', 'alert');
    toastContainer.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastContainer);
    
    return toastContainer;
}

/**
 * Gets SVG icon for toast type
 */
function getIcon(type) {
    const icons = {
        danger: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #f04438;">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>`,
        warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #f79009;">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>`,
        success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #12b76a;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>`,
        info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #00e5bf;">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>`
    };
    return icons[type] || icons.info;
}

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Shows a toast notification
 * @param {Object} options - Toast options
 * @param {string} options.title - Toast title
 * @param {string} options.message - Toast message
 * @param {string} options.type - Toast type (danger, warning, success, info)
 * @param {number} options.duration - Duration in ms (default 4000)
 * @param {Function} options.onClick - Click handler
 */
export function showToast({ 
    title = '', 
    message = '', 
    type = 'info', 
    duration = 4000,
    onClick = null 
}) {
    const container = getContainer();
    
    const toast = document.createElement('div');
    toast.className = `vb-toast vb-toast--${type}`;
    toast.innerHTML = `
        <div class="vb-toast__icon">${getIcon(type)}</div>
        <div class="vb-toast__content">
            ${title ? `<div class="vb-toast__title">${escapeHtml(title)}</div>` : ''}
            <div class="vb-toast__message">${escapeHtml(message)}</div>
        </div>
        <button class="vb-toast__close" aria-label="Dismiss">×</button>
    `;
    
    container.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('vb-toast--visible');
    });
    
    // Dismiss function
    const dismiss = () => {
        toast.classList.remove('vb-toast--visible');
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 250);
    };
    
    // Event listeners
    toast.querySelector('.vb-toast__close').addEventListener('click', (e) => {
        e.stopPropagation();
        dismiss();
    });
    
    if (onClick) {
        toast.style.cursor = 'pointer';
        toast.addEventListener('click', () => {
            onClick();
            dismiss();
        });
    }
    
    // Auto dismiss
    if (duration > 0) {
        setTimeout(dismiss, duration);
    }
    
    return { dismiss };
}

/**
 * Shows a danger toast
 */
export function showDangerToast(title, message, duration = 5000) {
    return showToast({ title, message, type: 'danger', duration });
}

/**
 * Shows a warning toast
 */
export function showWarningToast(title, message, duration = 4000) {
    return showToast({ title, message, type: 'warning', duration });
}

/**
 * Shows a success toast
 */
export function showSuccessToast(title, message, duration = 3000) {
    return showToast({ title, message, type: 'success', duration });
}

/**
 * Shows an info toast
 */
export function showInfoToast(title, message, duration = 3000) {
    return showToast({ title, message, type: 'info', duration });
}

