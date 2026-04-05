/**
 * VaultBix Text Highlighting
 * Highlights sensitive data in input elements
 */

/**
 * Creates a highlight overlay for text within an element
 * Note: This is complex because inputs don't support rich text.
 * We create an overlay that visually highlights the sensitive parts.
 * 
 * @param {HTMLElement} element - The input/textarea element
 * @param {Array} findings - Array of findings to highlight
 * @returns {Object} Controller for the highlights
 */
export function highlightFindings(element, findings) {
    // For contenteditable, we can do inline highlighting
    if (element.isContentEditable) {
        return highlightContentEditable(element, findings);
    }
    
    // For input/textarea, we show a tooltip or badge instead
    return showHighlightBadge(element, findings);
}

/**
 * Highlights text in contenteditable elements
 */
function highlightContentEditable(element, findings) {
    const originalContent = element.innerHTML;
    let html = element.textContent;
    
    // Sort findings by position (descending) to replace from end
    const sorted = [...findings].sort((a, b) => b.position - a.position);
    
    for (const finding of sorted) {
        const risk = finding.risk.toLowerCase();
        html = html.replace(
            finding.value,
            `<span class="vb-highlight vb-highlight--${risk}" data-vb-finding="${finding.id}" title="${finding.label}">${finding.value}</span>`
        );
    }
    
    element.innerHTML = html;
    
    // Return controller to restore original
    return {
        restore: () => {
            element.innerHTML = originalContent;
        },
        findings
    };
}

/**
 * Shows a highlight badge for inputs that can't have inline highlights
 */
function showHighlightBadge(element, findings) {
    // Create a badge that shows the count
    const badge = document.createElement('div');
    badge.className = 'vb-root';
    badge.innerHTML = `
        <div style="
            position: absolute;
            top: -8px;
            right: -8px;
            background: #f04438;
            color: white;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 6px;
            border-radius: 10px;
            z-index: 9999;
            pointer-events: none;
            font-family: -apple-system, sans-serif;
        ">${findings.length}</div>
    `;
    
    // Position relative to the element
    const parent = element.parentElement;
    if (parent) {
        parent.style.position = 'relative';
        parent.appendChild(badge.firstElementChild);
    }
    
    return {
        restore: () => {
            badge.firstElementChild?.remove();
        },
        findings
    };
}

/**
 * Removes all VaultBix highlights from an element
 */
export function removeHighlights(element) {
    if (element.isContentEditable) {
        // Remove highlight spans
        element.querySelectorAll('.vb-highlight').forEach(span => {
            const text = document.createTextNode(span.textContent);
            span.parentNode.replaceChild(text, span);
        });
    }
    
    // Remove any badges
    const parent = element.parentElement;
    if (parent) {
        parent.querySelectorAll('[style*="background: #f04438"]').forEach(el => el.remove());
    }
}

/**
 * Creates a visual indicator showing where sensitive data was found
 * @param {string} text - Original text
 * @param {Array} findings - Findings with positions
 * @returns {string} HTML string with highlights
 */
export function createHighlightedPreview(text, findings) {
    if (!findings.length) return escapeHtml(text);
    
    let result = '';
    let lastIndex = 0;
    
    // Sort by position
    const sorted = [...findings].sort((a, b) => a.position - b.position);
    
    for (const finding of sorted) {
        // Add text before this finding
        result += escapeHtml(text.slice(lastIndex, finding.position));
        
        // Add highlighted finding
        const risk = finding.risk.toLowerCase();
        result += `<span class="vb-highlight vb-highlight--${risk}">${escapeHtml(finding.value)}</span>`;
        
        lastIndex = finding.position + finding.length;
    }
    
    // Add remaining text
    result += escapeHtml(text.slice(lastIndex));
    
    return result;
}

/**
 * Escapes HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

