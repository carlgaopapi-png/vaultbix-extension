/**
 * VaultBix Modal
 * Slide-up modal for blocking sensitive data
 */

let currentModal = null;

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Gets risk badge HTML
 */
function getRiskBadge(risk) {
    return `<span class="vb-badge vb-badge--${risk.toLowerCase()}">${risk} Risk</span>`;
}

/**
 * Gets finding icon based on risk
 */
function getFindingIcon(risk) {
    const color = risk === 'HIGH' ? '#f04438' : risk === 'MEDIUM' ? '#f79009' : '#12b76a';
    return `<svg class="vb-modal__finding-icon" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;
}

/**
 * Shows the blocking modal
 * @param {Object} options - Modal options
 * @param {string} options.title - Modal title
 * @param {Array} options.findings - Array of detected findings
 * @param {string} options.overallRisk - Overall risk level
 * @param {Function} options.onRedact - Callback for redact action
 * @param {Function} options.onOverride - Callback for override action
 * @param {Function} options.onCancel - Callback for cancel action
 */
export function showBlockModal({ 
    title = 'Sensitive Data Detected',
    findings = [],
    overallRisk = 'HIGH',
    onRedact,
    onOverride,
    onCancel
}) {
    // Remove existing modal if any
    if (currentModal) {
        currentModal.remove();
    }
    
    const overlay = document.createElement('div');
    overlay.className = 'vb-root vb-modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'vb-modal-title');
    
    const findingsHtml = findings.map(f => `
        <div class="vb-modal__finding">
            ${getFindingIcon(f.risk)}
            <div class="vb-modal__finding-content">
                <div class="vb-modal__finding-type">${escapeHtml(f.label)}</div>
                <code class="vb-modal__finding-value">${escapeHtml(f.redacted)}</code>
            </div>
        </div>
    `).join('');
    
    overlay.innerHTML = `
        <div class="vb-modal">
            <div class="vb-modal__header">
                <div class="vb-modal__title">
                    <svg class="vb-modal__title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M12 8v4"/>
                        <path d="M12 16h.01"/>
                    </svg>
                    <span id="vb-modal-title">${escapeHtml(title)}</span>
                </div>
                ${getRiskBadge(overallRisk)}
            </div>
            
            <div class="vb-modal__body">
                <div class="vb-modal__section">
                    <p class="vb-modal__desc">
                        VaultBix detected sensitive information that could compromise security if shared with AI tools.
                    </p>
                </div>
                
                <div class="vb-modal__section">
                    <div class="vb-modal__label">Detected Items (${findings.length})</div>
                    <div class="vb-modal__detected">
                        ${findingsHtml}
                    </div>
                </div>
                
                <div class="vb-modal__section">
                    <div class="vb-modal__privacy">
                        <svg class="vb-modal__privacy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <div class="vb-modal__privacy-text">
                            <div class="vb-modal__privacy-title">100% Local Analysis</div>
                            <div class="vb-modal__privacy-desc">
                                All detection runs in your browser. Nothing is sent to any server.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="vb-modal__actions">
                <button class="vb-btn vb-btn--primary" data-action="redact">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Redact & Continue Safely
                </button>
                <button class="vb-btn vb-btn--ghost" data-action="override">
                    Send Anyway (action will be logged)
                </button>
                <button class="vb-btn vb-btn--secondary" data-action="cancel">
                    Cancel
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    currentModal = overlay;
    
    // Animate in
    requestAnimationFrame(() => {
        overlay.classList.add('vb-modal-overlay--visible');
    });
    
    // Close function
    const close = () => {
        overlay.classList.remove('vb-modal-overlay--visible');
        setTimeout(() => {
            if (overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
            currentModal = null;
        }, 300);
    };
    
    // Event listeners
    overlay.querySelector('[data-action="redact"]').addEventListener('click', () => {
        if (onRedact) onRedact();
        close();
    });
    
    overlay.querySelector('[data-action="override"]').addEventListener('click', () => {
        if (onOverride) onOverride();
        close();
    });
    
    overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => {
        if (onCancel) onCancel();
        close();
    });
    
    // Click outside to cancel
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            if (onCancel) onCancel();
            close();
        }
    });
    
    // Escape key to cancel
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            if (onCancel) onCancel();
            close();
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
    
    // Focus first button
    overlay.querySelector('[data-action="redact"]').focus();
    
    return { close };
}

/**
 * Hides any open modal
 */
export function hideModal() {
    if (currentModal) {
        currentModal.classList.remove('vb-modal-overlay--visible');
        setTimeout(() => {
            if (currentModal && currentModal.parentNode) {
                currentModal.parentNode.removeChild(currentModal);
            }
            currentModal = null;
        }, 300);
    }
}

/**
 * Checks if modal is currently open
 */
export function isModalOpen() {
    return currentModal !== null;
}

