/**
 * VaultBix Inline Banner
 * Shows warnings above input elements
 */

const activeBanners = new WeakMap();

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Gets warning icon based on risk level
 */
function getWarningIcon(risk) {
    const color = risk === 'HIGH' ? '#f04438' : risk === 'MEDIUM' ? '#f79009' : '#12b76a';
    return `<svg class="vb-inline-banner__icon" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>`;
}

/**
 * Shows an inline banner above an input element
 * @param {HTMLElement} inputElement - The input element
 * @param {Object} options - Banner options
 * @param {string} options.message - Warning message
 * @param {string} options.riskLevel - Risk level (HIGH, MEDIUM, LOW)
 * @param {Function} options.onDismiss - Callback when dismissed
 * @returns {Object} Banner control object
 */
export function showInlineBanner(inputElement, { 
    message, 
    riskLevel = 'HIGH',
    onDismiss = null 
}) {
    // Remove existing banner for this element
    if (activeBanners.has(inputElement)) {
        activeBanners.get(inputElement).remove();
    }
    
    const banner = document.createElement('div');
    banner.className = `vb-root vb-inline-banner vb-inline-banner--${riskLevel.toLowerCase()}`;
    banner.innerHTML = `
        ${getWarningIcon(riskLevel)}
        <div class="vb-inline-banner__content">${escapeHtml(message)}</div>
        <button class="vb-inline-banner__dismiss" aria-label="Dismiss">×</button>
    `;
    
    // Insert before the input
    const parent = inputElement.parentNode;
    if (parent) {
        parent.insertBefore(banner, inputElement);
    }
    
    // Track the banner
    activeBanners.set(inputElement, banner);
    
    // Dismiss handler
    const dismiss = () => {
        banner.remove();
        activeBanners.delete(inputElement);
        if (onDismiss) onDismiss();
    };
    
    banner.querySelector('.vb-inline-banner__dismiss').addEventListener('click', dismiss);
    
    return { dismiss, element: banner };
}

/**
 * Removes banner for an element
 */
export function removeBanner(inputElement) {
    if (activeBanners.has(inputElement)) {
        activeBanners.get(inputElement).remove();
        activeBanners.delete(inputElement);
    }
}

/**
 * Removes all banners
 */
export function removeAllBanners() {
    document.querySelectorAll('.vb-inline-banner').forEach(banner => banner.remove());
    // Note: WeakMap entries will be garbage collected when elements are removed
}

