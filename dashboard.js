/**
 * VaultBix Dashboard Script
 * Activity log, statistics, and management interface.
 * No authentication required.
 *
 * @file dashboard.js
 * @version 3.0.0
 */

const MAX_LOG_DISPLAY = 500;

let currentLogs = [];
let isInitialized = false;
let refreshTimer = null;

function getUIElements() {
    return {
        tableBody: document.getElementById('logTableBody'),
        exportButton: document.getElementById('exportJson'),
        totalBlocks: document.getElementById('totalBlocks'),
        todayBlocks: document.getElementById('todayBlocks'),
        typeBreakdown: document.getElementById('typeBreakdown'),
        riskyDomains: document.getElementById('riskyDomains'),
        clearAllBtn: document.getElementById('clearAllBtn'),
        logCountBadge: document.getElementById('logCountBadge'),
        modalBackdrop: document.getElementById('modalBackdrop'),
        modalTitle: document.getElementById('modalTitle'),
        modalBody: document.getElementById('modalBody'),
        modalClose: document.getElementById('modalClose')
    };
}

// ============================================================================
// UTILITIES
// ============================================================================

function formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Unknown';
        const now = new Date();
        const diff = now - date;
        if (diff < 3600000) { const mins = Math.floor(diff / 60000); return mins <= 1 ? 'Just now' : `${mins}m ago`; }
        if (date.toDateString() === now.toDateString()) return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (date.getFullYear() === now.getFullYear()) return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return 'Unknown'; }
}

function escapeHtml(text) {
    if (text == null) return 'N/A';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function truncateUrl(url, maxLength = 50) {
    if (!url) return 'N/A';
    try {
        const parsed = new URL(url);
        const display = parsed.hostname + parsed.pathname;
        return display.length <= maxLength ? display : display.substring(0, maxLength - 3) + '...';
    } catch {
        return url.length <= maxLength ? url : url.substring(0, maxLength - 3) + '...';
    }
}

function isToday(timestamp) {
    try { return new Date(timestamp).toDateString() === new Date().toDateString(); } catch { return false; }
}

const TYPE_LABELS = {
    'PROMPT_DETECTED': 'Detected', 'PROMPT_BLOCKED': 'Blocked', 'PROMPT_REDACTED': 'Redacted',
    'PROMPT_OVERRIDDEN': 'Override', 'PASTE_WARNING': 'Paste Warning',
    'DETECTED': 'Detected', 'BLOCKED': 'Blocked', 'REDACTED': 'Redacted', 'OVERRIDDEN': 'Override'
};

function getTypeLabel(type) { return TYPE_LABELS[type] || (type || 'Unknown').replace(/_/g, ' ').replace(/PROMPT /g, ''); }

function getTypeClass(type) {
    const highRisk = ['PROMPT_BLOCKED', 'PROMPT_REDACTED', 'BLOCKED', 'REDACTED'];
    const mediumRisk = ['PROMPT_DETECTED', 'PROMPT_OVERRIDDEN', 'DETECTED', 'OVERRIDDEN', 'PASTE_WARNING'];
    if (highRisk.includes(type)) return 'type-high';
    if (mediumRisk.includes(type)) return 'type-medium';
    return 'type-low';
}

function getRiskLevelClass(level) {
    return { critical: 'risk-critical', high: 'risk-high', medium: 'risk-medium', low: 'risk-low' }[level] || 'risk-low';
}

function getRiskLevelLabel(level) {
    return { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }[level] || 'Low';
}

// ============================================================================
// MESSAGING
// ============================================================================

async function sendMessage(message) {
    try {
        return await chrome.runtime.sendMessage(message);
    } catch (error) {
        if (error?.message?.includes('Extension context invalidated')) {
            showModal('Connection Lost', '<p>Extension was reloaded. Please refresh this page.</p>');
        }
        return null;
    }
}

// ============================================================================
// LOG TABLE
// ============================================================================

function createLogRow(log) {
    const row = document.createElement('tr');
    row.className = 'log-row';
    const timeStr = formatTimestamp(log?.timestamp);
    const typeLabel = getTypeLabel(log?.type);
    const typeClass = getTypeClass(log?.type);
    const urlDisplay = truncateUrl(log?.url);
    const details = log?.details || 'No details';

    row.innerHTML = `
        <td class="timestamp-cell">${escapeHtml(timeStr)}</td>
        <td class="type-cell"><span class="type-badge ${typeClass}">${escapeHtml(typeLabel)}</span></td>
        <td class="url-cell" title="${escapeHtml(log?.url || '')}">${escapeHtml(urlDisplay)}</td>
        <td class="details-cell" title="${escapeHtml(details)}">${escapeHtml(details.substring(0, 60))}${details.length > 60 ? '...' : ''}</td>
    `;
    return row;
}

function showTableLoading() {
    const elements = getUIElements();
    if (elements.tableBody) {
        elements.tableBody.innerHTML = `<tr><td colspan="4" class="loading-row"><div class="loading-spinner"></div>Loading activity...</td></tr>`;
    }
}

function showTableEmpty() {
    const elements = getUIElements();
    if (elements.tableBody) {
        elements.tableBody.innerHTML = `
            <tr><td colspan="4" class="empty-row">
                <div class="empty-state">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <p>No activity recorded yet</p>
                    <span>VaultBix is actively monitoring for sensitive data</span>
                </div>
            </td></tr>
        `;
    }
}

function showTableError(message) {
    const elements = getUIElements();
    if (elements.tableBody) {
        elements.tableBody.innerHTML = `
            <tr><td colspan="4" class="error-row">
                <div class="error-state">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <p>${escapeHtml(message)}</p>
                    <button class="btn btn-secondary btn-small" onclick="location.reload()">Retry</button>
                </div>
            </td></tr>
        `;
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

async function updateStatistics(logs) {
    const elements = getUIElements();
    try {
        let totalCount = logs.length;
        try {
            const resp = await sendMessage({ action: 'get_total_count' });
            if (resp?.success && typeof resp.total === 'number') totalCount = resp.total;
        } catch {}
        if (elements.totalBlocks) elements.totalBlocks.textContent = totalCount.toLocaleString();
        const todayCount = logs.filter(log => isToday(log?.timestamp)).length;
        if (elements.todayBlocks) elements.todayBlocks.textContent = todayCount.toLocaleString();
        if (elements.logCountBadge) elements.logCountBadge.textContent = `${logs.length} events`;
    } catch {}
}

// ============================================================================
// RISKY DOMAINS
// ============================================================================

async function renderRiskyDomains() {
    const elements = getUIElements();
    if (!elements.riskyDomains) return;
    try {
        const response = await sendMessage({ action: 'get_top_risky_domains', limit: 5 });
        if (!response?.success || !response.domains?.length) {
            elements.riskyDomains.innerHTML = `<div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><p>No events recorded yet</p></div>`;
            return;
        }
        let html = '<div class="risky-domains-grid">';
        response.domains.forEach((domain, index) => {
            const riskClass = getRiskLevelClass(domain.level);
            const riskLabel = getRiskLevelLabel(domain.level);
            html += `
                <div class="risky-domain-card">
                    <div class="risky-domain-header">
                        <span class="risky-domain-rank">#${index + 1}</span>
                        <div class="risky-domain-info">
                            <div class="risky-domain-name">${escapeHtml(domain.domain)}</div>
                            <div class="risky-domain-meta">${domain.count} events</div>
                        </div>
                        <div class="risky-domain-score">
                            <span class="risk-badge ${riskClass}">${riskLabel}</span>
                            <span class="risk-score-value">${domain.score}</span>
                        </div>
                    </div>
                    <div class="risk-score-bar"><div class="risk-score-bar-fill ${riskClass}" style="width: ${domain.score}%"></div></div>
                </div>
            `;
        });
        html += '</div>';
        elements.riskyDomains.innerHTML = html;
    } catch {
        elements.riskyDomains.innerHTML = '<p class="error-text">Error loading sites</p>';
    }
}

// ============================================================================
// TYPE BREAKDOWN
// ============================================================================

const TYPE_DETAILS = {
    'PROMPT_DETECTED': { icon: 'info', label: 'Sensitive Data Detected', riskLevel: 'Low-Medium', description: 'VaultBix detected sensitive information in text you were about to send.', howDetected: 'Real-time pattern matching scans for API keys, passwords, SSNs, credit cards, and other sensitive data.', howProtected: 'A warning appears so you can review before sending.' },
    'PROMPT_BLOCKED': { icon: 'shield', label: 'Submission Blocked', riskLevel: 'High', description: 'VaultBix prevented sensitive data from being sent to an AI tool.', howDetected: 'High-risk sensitive data was found in your message before submission.', howProtected: 'The submission was intercepted. You can redact, send anyway, or cancel.' },
    'PROMPT_REDACTED': { icon: 'check', label: 'Content Redacted', riskLevel: 'Resolved', description: 'Sensitive data was replaced with safe placeholder text.', howDetected: 'You chose to redact sensitive content that VaultBix detected.', howProtected: 'Sensitive values were replaced with [REDACTED] before sending.' },
    'PROMPT_OVERRIDDEN': { icon: 'alert', label: 'User Override', riskLevel: 'Logged', description: 'You chose to send the message despite VaultBix warnings.', howDetected: 'You clicked "Send Anyway" on the warning.', howProtected: 'The action was logged locally for your records.' },
    'PASTE_WARNING': { icon: 'clipboard', label: 'Paste Warning', riskLevel: 'Medium', description: 'Sensitive data was detected in pasted content.', howDetected: 'VaultBix scans clipboard content when you paste into AI chat inputs.', howProtected: 'A warning appears immediately after pasting.' },
    'DETECTED': { icon: 'info', label: 'Detected', riskLevel: 'Varies', description: 'Sensitive information was detected.', howDetected: 'Pattern matching.', howProtected: 'Warning shown.' },
    'BLOCKED': { icon: 'shield', label: 'Blocked', riskLevel: 'High', description: 'Submission blocked.', howDetected: 'High-risk data found.', howProtected: 'Submission intercepted.' },
    'REDACTED': { icon: 'check', label: 'Redacted', riskLevel: 'Resolved', description: 'Content redacted.', howDetected: 'User chose to redact.', howProtected: 'Values masked.' },
    'OVERRIDDEN': { icon: 'alert', label: 'Override', riskLevel: 'Logged', description: 'User chose to send.', howDetected: 'User override.', howProtected: 'Logged locally.' }
};

function getTypeDetails(type) {
    return TYPE_DETAILS[type] || { icon: 'info', label: getTypeLabel(type), riskLevel: 'Unknown', description: 'Event logged by VaultBix.', howDetected: 'Detected through monitoring.', howProtected: 'Logged for review.' };
}

function renderTypeBreakdown(logs) {
    const elements = getUIElements();
    if (!elements.typeBreakdown) return;
    try {
        const typeCounts = {};
        logs.forEach(log => { const type = log?.type || 'UNKNOWN'; typeCounts[type] = (typeCounts[type] || 0) + 1; });
        const sortedTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

        if (sortedTypes.length === 0) {
            elements.typeBreakdown.innerHTML = `<div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><p>No activity recorded yet</p></div>`;
            return;
        }

        const total = logs.length;
        let html = '<div class="breakdown-list-interactive">';
        sortedTypes.forEach(([type, count]) => {
            const percentage = ((count / total) * 100).toFixed(1);
            const typeClass = getTypeClass(type);
            const details = getTypeDetails(type);
            html += `
                <div class="breakdown-item-interactive" data-type="${escapeHtml(type)}">
                    <div class="breakdown-item-header-interactive">
                        <div class="breakdown-item-left">
                            <span class="breakdown-type">${escapeHtml(details.label)}</span>
                        </div>
                        <div class="breakdown-item-right">
                            <span class="breakdown-count">${count}</span>
                            <span class="breakdown-percentage">${percentage}%</span>
                            <svg class="breakdown-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="breakdown-bar-container"><div class="breakdown-bar ${typeClass}" style="width: ${percentage}%"></div></div>
                    <div class="breakdown-details" style="display: none;">
                        <div class="breakdown-details-inner">
                            <div class="breakdown-risk-badge ${typeClass}">${escapeHtml(details.riskLevel)} Risk</div>
                            <p class="breakdown-description">${escapeHtml(details.description)}</p>
                            <div class="breakdown-section"><h4>How It's Detected</h4><p>${escapeHtml(details.howDetected)}</p></div>
                            <div class="breakdown-section"><h4>How VaultBix Protects You</h4><p>${escapeHtml(details.howProtected)}</p></div>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        html += '<p class="breakdown-hint">Click on any type to learn more</p>';
        elements.typeBreakdown.innerHTML = html;
        setupBreakdownClickHandlers();
    } catch {
        elements.typeBreakdown.innerHTML = '<p class="error-text">Error loading statistics</p>';
    }
}

function setupBreakdownClickHandlers() {
    const items = document.querySelectorAll('.breakdown-item-interactive');
    items.forEach(item => {
        const header = item.querySelector('.breakdown-item-header-interactive');
        const details = item.querySelector('.breakdown-details');
        const chevron = item.querySelector('.breakdown-chevron');
        if (!header || !details) return;

        header.addEventListener('click', () => {
            const isOpen = details.style.display !== 'none';
            items.forEach(other => {
                const od = other.querySelector('.breakdown-details');
                const oc = other.querySelector('.breakdown-chevron');
                if (other !== item && od) { od.style.display = 'none'; other.classList.remove('expanded'); if (oc) oc.style.transform = 'rotate(0deg)'; }
            });
            if (isOpen) { details.style.display = 'none'; item.classList.remove('expanded'); if (chevron) chevron.style.transform = 'rotate(0deg)'; }
            else { details.style.display = 'block'; item.classList.add('expanded'); if (chevron) chevron.style.transform = 'rotate(180deg)'; setTimeout(() => { try { details.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch {} }, 100); }
        });
    });
}

// ============================================================================
// MODAL
// ============================================================================

function showModal(title, htmlBody) {
    const elements = getUIElements();
    if (!elements.modalBackdrop || !elements.modalTitle || !elements.modalBody) return;
    elements.modalTitle.textContent = title;
    elements.modalBody.innerHTML = htmlBody;
    elements.modalBackdrop.classList.add('modal-show');
    elements.modalBackdrop.setAttribute('aria-hidden', 'false');
}

function hideModal() {
    const elements = getUIElements();
    if (!elements.modalBackdrop) return;
    elements.modalBackdrop.classList.remove('modal-show');
    elements.modalBackdrop.setAttribute('aria-hidden', 'true');
}

// ============================================================================
// EXPORT
// ============================================================================

function exportLogs() {
    try {
        if (currentLogs.length === 0) { showModal('Export', '<p>No data to export yet.</p>'); return; }
        const safeLogs = currentLogs.map(log => ({
            id: log?.id,
            timestamp: log?.timestamp,
            type: log?.type,
            site: log?.url ? (() => { try { return new URL(log.url).hostname; } catch { return 'Unknown'; } })() : 'Unknown',
            summary: log?.details ? log.details.substring(0, 100) : 'No details'
        }));
        const exportData = {
            exportDate: new Date().toISOString(),
            version: '3.0.0',
            totalEvents: safeLogs.length,
            privacyNote: 'This export contains only event metadata. No raw secrets, API keys, or PII are included.',
            logs: safeLogs
        };
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vaultbix-export-${new Date().toISOString().substring(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { try { document.body.removeChild(a); URL.revokeObjectURL(url); } catch {} }, 100);
        showModal('Export Complete', `<p>Exported ${safeLogs.length} events.</p><p><strong>Privacy:</strong> Only event metadata exported.</p>`);
    } catch {
        showModal('Export Error', '<p>Failed to export. Please try again.</p>');
    }
}

// ============================================================================
// CLEAR LOGS
// ============================================================================

async function clearAllLogs() {
    if (!confirm('Clear all activity logs and reset statistics?\n\nThis action cannot be undone.')) return;
    try {
        const response = await sendMessage({ action: 'clear_logs' });
        if (!response?.success) throw new Error();
        await loadAndRenderLogs();
        showModal('Success', '<p>All logs and statistics have been cleared.</p>');
    } catch {
        showModal('Error', '<p>Failed to clear logs. Please try again.</p>');
    }
}

// ============================================================================
// MAIN RENDER
// ============================================================================

async function renderDashboard(logs) {
    const elements = getUIElements();
    if (!elements.tableBody) return;

    try {
        currentLogs = Array.isArray(logs) ? logs : [];
        await updateStatistics(currentLogs);
        await renderRiskyDomains();
        renderTypeBreakdown(currentLogs);

        elements.tableBody.innerHTML = '';
        if (currentLogs.length === 0) { showTableEmpty(); return; }

        const displayLogs = currentLogs.slice(0, MAX_LOG_DISPLAY);
        displayLogs.forEach((log, index) => {
            try {
                const row = createLogRow(log);
                row.style.animationDelay = `${Math.min(index * 0.02, 0.5)}s`;
                row.classList.add('fade-in-scale');
                elements.tableBody.appendChild(row);
            } catch {}
        });

        if (currentLogs.length > MAX_LOG_DISPLAY) {
            const noticeRow = document.createElement('tr');
            noticeRow.innerHTML = `<td colspan="4" style="text-align: center; padding: 16px; color: var(--text-tertiary); font-size: 13px;">Showing ${MAX_LOG_DISPLAY} of ${currentLogs.length} events. Export to see all.</td>`;
            elements.tableBody.appendChild(noticeRow);
        }
    } catch {
        showTableError('Error rendering dashboard');
    }
}

async function loadAndRenderLogs() {
    showTableLoading();
    try {
        const response = await sendMessage({ action: 'get_logs' });
        if (!response) { showTableError('Connection lost. Please refresh.'); return; }
        if (!response.success) throw new Error();
        await renderDashboard(response.logs || []);
    } catch {
        showTableError('Error loading activity log');
    }
}

// ============================================================================
// TIER STATUS
// ============================================================================

async function updateTierDisplay() {
    try {
        const response = await sendMessage({ action: 'get_trial_state' });
        const statusEl = document.getElementById('earlyAccessStatus');
        const textEl = document.getElementById('tierStatusText');
        if (!statusEl || !textEl) return;

        if (response?.success && response.isActive) {
            textEl.textContent = `Trial: ${response.daysRemaining}d remaining`;
            statusEl.style.background = 'var(--success-light, rgba(18,183,106,0.1))';
            statusEl.style.color = 'var(--success, #12b76a)';
        } else {
            textEl.textContent = 'Free Plan';
            statusEl.style.background = 'var(--warning-light, rgba(247,144,9,0.1))';
            statusEl.style.color = 'var(--warning, #f79009)';
        }
    } catch {}
}

// ============================================================================
// EVENT HANDLERS & INIT
// ============================================================================

function setupEventListeners() {
    const elements = getUIElements();
    if (elements.exportButton) elements.exportButton.addEventListener('click', exportLogs);
    if (elements.clearAllBtn) elements.clearAllBtn.addEventListener('click', clearAllLogs);
    if (elements.modalClose) elements.modalClose.addEventListener('click', hideModal);
    if (elements.modalBackdrop) elements.modalBackdrop.addEventListener('click', (e) => { if (e.target === elements.modalBackdrop) hideModal(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideModal(); });

    try {
        chrome.runtime.onMessage.addListener((message) => {
            if (message?.action === 'log_updated' && isInitialized) {
                clearTimeout(refreshTimer);
                refreshTimer = setTimeout(loadAndRenderLogs, 500);
            }
        });
    } catch {}
}

async function initializeDashboard() {
    if (isInitialized) return;
    try {
        setupEventListeners();
        await updateTierDisplay();
        await loadAndRenderLogs();
        isInitialized = true;
    } catch {
        showTableError('Failed to initialize dashboard');
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
    initializeDashboard();
}





