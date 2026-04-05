/**
 * VaultBix Popup Script
 * Handles main view, settings, license activation, custom rules, and privacy.
 *
 * @file popup.js
 * @version 4.0.0
 */

// ============================================================================
// THEME
// ============================================================================

function initTheme() {
    try {
        const savedTheme = localStorage.getItem('vaultbix-theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
    } catch {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}

function toggleTheme() {
    try {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('vaultbix-theme', newTheme);
    } catch {
        // fail silently
    }
}

initTheme();

// ============================================================================
// CONSTANTS
// ============================================================================

const CONFIG = window.VAULTBIX_CONFIG || {
    BASE_URL: 'https://vaultbix.com',
    SUPPORT_URL: 'https://vaultbix.com/contact',
    SUPPORT_EMAIL: 'info@vaultbix.com'
};

const MAX_RECENT_LOGS = 5;
const MAX_DETAIL_LENGTH = 40;

// ============================================================================
// STATE
// ============================================================================

let isInitialized = false;
let currentView = null;
let licenseState = null;
let currentTier = 'free';
let settingsState = null;
let customRules = [];

// ============================================================================
// VIEW MANAGEMENT
// ============================================================================

function showView(viewId) {
    const views = ['mainView', 'settingsView', 'customRulesView', 'privacyView'];
    views.forEach(id => {
        const view = document.getElementById(id);
        if (view) view.style.display = id === viewId ? 'flex' : 'none';
    });
    currentView = viewId;
    const activeView = document.getElementById(viewId);
    if (activeView) {
        activeView.classList.add('view-enter');
        setTimeout(() => activeView.classList.remove('view-enter'), 300);
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

function formatTime(timestamp) {
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Unknown';
        const now = new Date();
        const diff = now - date;
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (date.toDateString() === now.toDateString()) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        const daysDiff = Math.floor(diff / 86400000);
        if (daysDiff < 7) return date.toLocaleDateString([], { weekday: 'short' });
        return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
        return 'Unknown';
    }
}

function truncateText(text, maxLength = MAX_DETAIL_LENGTH) {
    if (!text) return 'N/A';
    const str = String(text);
    return str.length <= maxLength ? str : str.substring(0, maxLength - 3) + '...';
}

function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function isToday(timestamp) {
    try {
        return new Date(timestamp).toDateString() === new Date().toDateString();
    } catch {
        return false;
    }
}

async function sendMessage(message) {
    try {
        return await chrome.runtime.sendMessage(message);
    } catch {
        return null;
    }
}

// ============================================================================
// TYPE LABELS
// ============================================================================

const TYPE_LABELS = {
    'PROMPT_DETECTED': 'Detected',
    'PROMPT_BLOCKED': 'Blocked',
    'PROMPT_REDACTED': 'Redacted',
    'PROMPT_OVERRIDDEN': 'Override',
    'PASTE_WARNING': 'Paste Warning',
    'DETECTED': 'Detected',
    'BLOCKED': 'Blocked',
    'REDACTED': 'Redacted',
    'OVERRIDDEN': 'Override'
};

const HIGH_RISK_TYPES = ['PROMPT_BLOCKED', 'PROMPT_REDACTED', 'BLOCKED', 'REDACTED'];

function getTypeLabel(type) {
    return TYPE_LABELS[type] || type?.replace(/_/g, ' ').replace(/PROMPT /g, '') || 'Unknown';
}

function isHighRisk(type) {
    return HIGH_RISK_TYPES.includes(type);
}

function getRiskIcon(type) {
    const color = isHighRisk(type) ? '#f04438' : '#f79009';
    return `<svg width="12" height="12" viewBox="0 0 24 24" fill="${color}" stroke="none"><circle cx="12" cy="12" r="6"/></svg>`;
}

// ============================================================================
// RENDERING
// ============================================================================

function getDisplayDetails(log) {
    try {
        if (log?.details && log.details !== 'No additional details') return truncateText(log.details);
        if (log?.url) {
            try { return truncateText(new URL(log.url).hostname); } catch { return truncateText(log.url); }
        }
        return 'Activity detected';
    } catch {
        return 'Unknown';
    }
}

function createLogItem(log) {
    const listItem = document.createElement('li');
    listItem.className = 'popup-log-item';
    listItem.innerHTML = `
        <div class="popup-log-item-content">
            <div class="popup-log-item-header">
                <div class="popup-log-type-wrap">
                    ${getRiskIcon(log?.type)}
                    <span class="popup-log-type">${escapeHtml(getTypeLabel(log?.type))}</span>
                </div>
                <span class="popup-log-time">${escapeHtml(formatTime(log?.timestamp))}</span>
            </div>
            <div class="popup-log-details">${escapeHtml(getDisplayDetails(log))}</div>
        </div>
    `;
    return listItem;
}

function showEmptyState() {
    const logsList = document.getElementById('recentLogs');
    if (logsList) {
        logsList.innerHTML = `
            <li class="popup-empty">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 8px; opacity: 0.5;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span>No events recorded yet.</span>
                <span style="font-size: 11px; opacity: 0.7;">VaultBix is actively monitoring.</span>
            </li>
        `;
    }
}

// ============================================================================
// LICENSE & TIER
// ============================================================================

async function loadLicenseState() {
    try {
        const response = await sendMessage({ action: 'get_license_state' });
        if (response?.success) {
            licenseState = response.license;
            currentTier = response.tier;
        } else {
            licenseState = null;
            currentTier = 'free';
        }
    } catch {
        licenseState = null;
        currentTier = 'free';
    }
}

async function loadSettings() {
    try {
        const response = await sendMessage({ action: 'get_settings' });
        if (response?.success) {
            settingsState = response.settings;
        } else {
            settingsState = { warningsEnabled: true, blockingEnabled: true, redactionEnabled: true };
        }
    } catch {
        settingsState = { warningsEnabled: true, blockingEnabled: true, redactionEnabled: true };
    }
}

function renderStatusBadge() {
    const badge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const subtitle = document.getElementById('mainViewSubtitle');
    const statusTitle = document.getElementById('protectionStatusTitle');
    const statusSubtitle = document.getElementById('protectionStatusSubtitle');
    const statusCard = document.getElementById('protectionStatusCard');
    const upgradeBanner = document.getElementById('upgradeBanner');

    const isPro = currentTier === 'pro';

    if (statusText) statusText.textContent = isPro ? 'Pro' : 'Free';
    if (badge) badge.className = 'early-access-badge';

    if (isPro) {
        if (subtitle) subtitle.textContent = 'Full Protection Active';
        if (statusTitle) statusTitle.textContent = 'Full Protection Active';
        if (statusSubtitle) statusSubtitle.textContent = 'Blocking, redaction, and custom rules enabled';
        if (statusCard) statusCard.className = 'status-card status-card-active';
        if (upgradeBanner) upgradeBanner.style.display = 'none';
    } else {
        if (subtitle) subtitle.textContent = 'Warnings Mode';
        if (statusTitle) statusTitle.textContent = 'Warnings Mode';
        if (statusSubtitle) statusSubtitle.textContent = 'Upgrade to Pro for blocking & redaction';
        if (statusCard) statusCard.className = 'status-card status-card-active';
        if (upgradeBanner) upgradeBanner.style.display = 'flex';
    }
}

function renderSettingsView() {
    if (!settingsState) return;

    const isPro = currentTier === 'pro';

    const tierTitle = document.getElementById('tierStatusTitle');
    const tierSubtitle = document.getElementById('tierStatusSubtitle');
    const tierCard = document.getElementById('tierStatusCard');
    const licenseSection = document.getElementById('licenseSection');
    const proStatusSection = document.getElementById('proStatusSection');
    const proEmail = document.getElementById('proEmail');
    const warningsStatus = document.getElementById('warningsStatus');
    const blockingStatus = document.getElementById('blockingStatus');
    const redactionStatus = document.getElementById('redactionStatus');
    const settingsNote = document.getElementById('settingsNote');

    if (isPro) {
        if (tierTitle) tierTitle.textContent = 'Pro Plan';
        if (tierSubtitle) tierSubtitle.textContent = 'All features unlocked';
        if (tierCard) tierCard.className = 'status-card status-card-active';
        if (licenseSection) licenseSection.style.display = 'none';
        if (proStatusSection) proStatusSection.style.display = 'block';
        if (proEmail && licenseState?.email) proEmail.textContent = licenseState.email;
        if (settingsNote) settingsNote.textContent = '';
    } else {
        if (tierTitle) tierTitle.textContent = 'Free Plan';
        if (tierSubtitle) tierSubtitle.textContent = 'Warnings only';
        if (tierCard) {
            tierCard.className = 'status-card';
            tierCard.style.borderColor = 'var(--border)';
        }
        if (licenseSection) licenseSection.style.display = 'block';
        if (proStatusSection) proStatusSection.style.display = 'none';
        if (settingsNote) settingsNote.textContent = 'Blocking and redaction require a Pro license.';
    }

    if (warningsStatus) warningsStatus.textContent = settingsState.warningsEnabled ? 'On' : 'Off';
    if (blockingStatus) {
        blockingStatus.textContent = isPro ? (settingsState.blockingEnabled ? 'On' : 'Off') : 'Pro only';
        blockingStatus.style.opacity = isPro ? '1' : '0.5';
    }
    if (redactionStatus) {
        redactionStatus.textContent = isPro ? (settingsState.redactionEnabled ? 'On' : 'Off') : 'Pro only';
        redactionStatus.style.opacity = isPro ? '1' : '0.5';
    }
}

// ============================================================================
// CUSTOM RULES
// ============================================================================

async function loadCustomRules() {
    try {
        const response = await sendMessage({ action: 'get_custom_rules' });
        if (response?.success) {
            customRules = response.rules || [];
        }
    } catch {
        customRules = [];
    }
}

function renderCustomRulesView() {
    const list = document.getElementById('customRulesList');
    const countEl = document.getElementById('customRulesCount');
    const limitNotice = document.getElementById('rulesLimitNotice');
    const isPro = currentTier === 'pro';

    if (countEl) countEl.textContent = customRules.length;

    if (limitNotice) {
        if (!isPro) {
            limitNotice.style.display = 'block';
            limitNotice.textContent = `Free plan: ${customRules.length}/3 rules. Upgrade to Pro for unlimited.`;
            limitNotice.style.color = customRules.length >= 3 ? 'var(--warning)' : 'var(--text-tertiary)';
        } else {
            limitNotice.style.display = 'none';
        }
    }

    if (!list) return;

    if (customRules.length === 0) {
        list.innerHTML = `<div style="text-align: center; padding: 24px; color: var(--text-tertiary); font-size: 13px;">No custom rules yet. Add one above.</div>`;
        return;
    }

    list.innerHTML = '';
    customRules.forEach(rule => {
        const ruleEl = document.createElement('div');
        ruleEl.style.cssText = 'display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--bg-tertiary); border-radius: 6px; border: 1px solid var(--border-color);';
        const riskColor = rule.risk === 'HIGH' ? 'var(--danger)' : rule.risk === 'MEDIUM' ? 'var(--warning)' : 'var(--success)';
        ruleEl.innerHTML = `
            <div style="flex: 1; min-width: 0;">
                <div style="font-size: 13px; font-weight: 600; color: var(--text-color); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(rule.name)}</div>
                <div style="font-size: 11px; color: var(--text-tertiary); font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(rule.pattern)}</div>
            </div>
            <span style="flex-shrink: 0; font-size: 10px; font-weight: 600; color: ${riskColor}; text-transform: uppercase;">${rule.risk}</span>
            <button class="delete-rule-btn" data-rule-id="${rule.id}" style="flex-shrink: 0; background: none; border: none; color: var(--text-tertiary); cursor: pointer; padding: 4px; font-size: 16px; line-height: 1;" title="Delete rule">&times;</button>
        `;
        list.appendChild(ruleEl);
    });

    list.querySelectorAll('.delete-rule-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const ruleId = btn.getAttribute('data-rule-id');
            await sendMessage({ action: 'delete_custom_rule', ruleId });
            await loadCustomRules();
            renderCustomRulesView();
        });
    });
}

// ============================================================================
// RISK & STATS
// ============================================================================

const RISK_LEVELS = {
    critical: { label: 'Critical', class: 'risk-critical' },
    high: { label: 'High', class: 'risk-high' },
    medium: { label: 'Medium', class: 'risk-medium' },
    low: { label: 'Low', class: 'risk-low' }
};

async function updateSiteRisk() {
    const siteRiskLevel = document.getElementById('siteRiskLevel');
    const siteRiskScore = document.getElementById('siteRiskScore');
    const siteRiskPill = document.getElementById('siteRiskPill');
    if (!siteRiskLevel) return;
    try {
        const response = await sendMessage({ action: 'get_current_tab_risk' });
        if (!response?.success || !response?.risk) {
            siteRiskLevel.textContent = 'Safe';
            if (siteRiskScore) siteRiskScore.textContent = '';
            if (siteRiskPill) siteRiskPill.className = 'popup-risk-pill risk-low';
            return;
        }
        const { score, level } = response.risk;
        const riskInfo = RISK_LEVELS[level] || { label: 'Safe', class: 'risk-low' };
        siteRiskLevel.textContent = riskInfo.label;
        if (siteRiskScore) siteRiskScore.textContent = score > 0 ? `${score}/100` : '';
        if (siteRiskPill) siteRiskPill.className = `popup-risk-pill ${riskInfo.class}`;
    } catch {
        siteRiskLevel.textContent = 'Unknown';
    }
}

async function updateLastEvent() {
    const card = document.getElementById('lastBlockedCard');
    if (!card) return;
    try {
        const response = await sendMessage({ action: 'get_logs' });
        if (!response?.success || !response.logs?.length) {
            card.style.display = 'none';
            return;
        }
        const lastLog = response.logs[0];
        const timeEl = document.getElementById('lastBlockedTime');
        const typeEl = document.getElementById('lastBlockedType');
        const detailEl = document.getElementById('lastBlockedDetail');
        if (timeEl) timeEl.textContent = formatTime(lastLog.timestamp);
        if (typeEl) typeEl.textContent = getTypeLabel(lastLog.type);
        if (detailEl) detailEl.textContent = getDisplayDetails(lastLog);
        card.style.display = 'block';
        card.classList.add('fade-in-scale');
    } catch {
        card.style.display = 'none';
    }
}

async function renderPopup(logs) {
    const countElement = document.getElementById('detectionCount');
    const todayCountElement = document.getElementById('todayCount');
    const logCount = document.getElementById('logCount');
    const logsList = document.getElementById('recentLogs');
    if (!countElement || !logsList) return;

    try {
        const validLogs = Array.isArray(logs) ? logs : [];
        let totalCount = validLogs.length;
        try {
            const resp = await sendMessage({ action: 'get_total_count' });
            if (resp?.success && typeof resp.total === 'number') totalCount = resp.total;
        } catch {}

        animateCounter(countElement, totalCount);
        const todayCount = validLogs.filter(log => isToday(log?.timestamp)).length;
        if (todayCountElement) animateCounter(todayCountElement, todayCount);
        if (logCount) logCount.textContent = Math.min(validLogs.length, MAX_RECENT_LOGS);

        logsList.innerHTML = '';
        if (validLogs.length === 0) { showEmptyState(); return; }

        validLogs.slice(0, MAX_RECENT_LOGS).forEach((log, index) => {
            const listItem = createLogItem(log);
            listItem.style.animationDelay = `${index * 0.05}s`;
            listItem.classList.add('fade-in-scale');
            logsList.appendChild(listItem);
        });
    } catch {
        logsList.innerHTML = '<li class="popup-error"><span>Error loading data</span></li>';
    }
}

function animateCounter(element, targetValue) {
    if (!element) return;
    const currentValue = parseInt(element.textContent.replace(/,/g, ''), 10) || 0;
    if (currentValue === targetValue) { element.textContent = targetValue.toLocaleString(); return; }
    if (Math.abs(targetValue - currentValue) <= 1) { element.textContent = targetValue.toLocaleString(); return; }
    const duration = 300;
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = Math.round(currentValue + (targetValue - currentValue) * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// ============================================================================
// DATA LOADING
// ============================================================================

async function loadAndRenderLogs() {
    const logsList = document.getElementById('recentLogs');
    if (logsList) logsList.innerHTML = '<li class="popup-loading">Loading events...</li>';
    try {
        const response = await sendMessage({ action: 'get_logs' });
        if (!response) {
            if (logsList) logsList.innerHTML = '<li class="popup-error"><span>Connection lost</span></li>';
            return;
        }
        if (!response.success) throw new Error();
        await renderPopup(response.logs || []);
    } catch {
        if (logsList) logsList.innerHTML = '<li class="popup-error"><span>Unable to load data</span></li>';
    }
}

async function loadMainViewData() {
    await loadAndRenderLogs();
    await updateSiteRisk();
    await updateLastEvent();
}

// ============================================================================
// FIRST-RUN WELCOME
// ============================================================================

async function checkFirstRun() {
    try {
        const result = await chrome.storage.local.get('vaultbix_welcome_dismissed');
        if (!result.vaultbix_welcome_dismissed) {
            const welcomeBanner = document.getElementById('welcomeBanner');
            if (welcomeBanner) welcomeBanner.style.display = 'flex';
        }
    } catch {
        // fail silently
    }
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

function addRipple(event, button) {
    try {
        const circle = document.createElement('span');
        circle.classList.add('ripple-effect');
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        circle.style.width = circle.style.height = size + 'px';
        circle.style.left = (event.clientX - rect.left - size / 2) + 'px';
        circle.style.top = (event.clientY - rect.top - size / 2) + 'px';
        button.appendChild(circle);
        setTimeout(() => circle.remove(), 600);
    } catch {
        // fail silently
    }
}

function setupEventListeners() {
    // Dashboard
    document.getElementById('openDashboard')?.addEventListener('click', (e) => {
        addRipple(e, e.currentTarget);
        try {
            chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html'), active: true });
        } catch {
            window.open(chrome.runtime.getURL('dashboard.html'), '_blank');
        }
    });

    // Upgrade banner
    document.getElementById('upgradeBanner')?.addEventListener('click', async () => {
        const resp = await sendMessage({ action: 'get_checkout_url', plan: 'monthly' });
        if (resp?.success && resp.url) {
            chrome.tabs.create({ url: resp.url, active: true });
        }
    });

    // Settings view
    document.getElementById('viewSettingsBtn')?.addEventListener('click', async () => {
        await loadLicenseState();
        await loadSettings();
        await loadCustomRules();
        renderSettingsView();
        const countEl = document.getElementById('customRulesCount');
        if (countEl) countEl.textContent = customRules.length;
        showView('settingsView');
    });
    document.getElementById('backToMainFromSettings')?.addEventListener('click', () => showView('mainView'));

    // Privacy view
    document.getElementById('viewPrivacyBtn')?.addEventListener('click', () => showView('privacyView'));
    document.getElementById('backToMainViewFromPrivacy')?.addEventListener('click', () => showView('mainView'));

    // Custom rules view
    document.getElementById('viewCustomRulesBtn')?.addEventListener('click', async () => {
        await loadCustomRules();
        renderCustomRulesView();
        showView('customRulesView');
    });
    document.getElementById('backToSettingsFromRules')?.addEventListener('click', () => {
        showView('settingsView');
    });

    // Add custom rule
    document.getElementById('addRuleBtn')?.addEventListener('click', async () => {
        const nameInput = document.getElementById('newRuleName');
        const patternInput = document.getElementById('newRulePattern');
        const riskSelect = document.getElementById('newRuleRisk');
        const errorEl = document.getElementById('ruleError');

        const name = nameInput?.value?.trim();
        const pattern = patternInput?.value?.trim();
        const risk = riskSelect?.value || 'HIGH';

        if (!name || !pattern) {
            if (errorEl) { errorEl.textContent = 'Name and pattern are required.'; errorEl.style.display = 'block'; }
            return;
        }

        const result = await sendMessage({ action: 'add_custom_rule', rule: { name, pattern, risk } });
        if (result?.success) {
            if (nameInput) nameInput.value = '';
            if (patternInput) patternInput.value = '';
            if (errorEl) errorEl.style.display = 'none';
            await loadCustomRules();
            renderCustomRulesView();
        } else {
            if (errorEl) { errorEl.textContent = result?.error || 'Failed to add rule.'; errorEl.style.display = 'block'; }
        }
    });

    // License activation
    document.getElementById('activateLicenseBtn')?.addEventListener('click', async () => {
        const input = document.getElementById('licenseKeyInput');
        const errorEl = document.getElementById('licenseError');
        const successEl = document.getElementById('licenseSuccess');
        const key = input?.value?.trim();

        if (errorEl) errorEl.style.display = 'none';
        if (successEl) successEl.style.display = 'none';

        if (!key) {
            if (errorEl) { errorEl.textContent = 'Please enter a license key.'; errorEl.style.display = 'block'; }
            return;
        }

        const btn = document.getElementById('activateLicenseBtn');
        if (btn) { btn.textContent = 'Validating...'; btn.disabled = true; }

        const result = await sendMessage({ action: 'activate_license', licenseKey: key });

        if (btn) { btn.textContent = 'Activate'; btn.disabled = false; }

        if (result?.success) {
            if (successEl) { successEl.textContent = 'License activated! Pro features unlocked.'; successEl.style.display = 'block'; }
            await loadLicenseState();
            renderSettingsView();
            renderStatusBadge();
        } else {
            if (errorEl) { errorEl.textContent = result?.error || 'Invalid license key.'; errorEl.style.display = 'block'; }
        }
    });

    // Buy Pro
    document.getElementById('buyProBtn')?.addEventListener('click', async () => {
        const resp = await sendMessage({ action: 'get_checkout_url', plan: 'monthly' });
        if (resp?.success && resp.url) {
            chrome.tabs.create({ url: resp.url, active: true });
        }
    });

    // Deactivate license
    document.getElementById('deactivateLicenseBtn')?.addEventListener('click', async () => {
        if (!confirm('Deactivate your Pro license? You will revert to the Free plan.')) return;
        await sendMessage({ action: 'deactivate_license' });
        await loadLicenseState();
        renderSettingsView();
        renderStatusBadge();
    });

    // Settings toggles
    document.getElementById('toggleWarnings')?.addEventListener('click', async () => {
        if (!settingsState) return;
        settingsState.warningsEnabled = !settingsState.warningsEnabled;
        await sendMessage({ action: 'update_settings', settings: { warningsEnabled: settingsState.warningsEnabled } });
        renderSettingsView();
    });
    document.getElementById('toggleBlocking')?.addEventListener('click', async () => {
        if (!settingsState || currentTier !== 'pro') return;
        settingsState.blockingEnabled = !settingsState.blockingEnabled;
        await sendMessage({ action: 'update_settings', settings: { blockingEnabled: settingsState.blockingEnabled } });
        renderSettingsView();
    });
    document.getElementById('toggleRedaction')?.addEventListener('click', async () => {
        if (!settingsState || currentTier !== 'pro') return;
        settingsState.redactionEnabled = !settingsState.redactionEnabled;
        await sendMessage({ action: 'update_settings', settings: { redactionEnabled: settingsState.redactionEnabled } });
        renderSettingsView();
    });

    // Clear data
    document.getElementById('clearDataBtn')?.addEventListener('click', async () => {
        if (!confirm('Clear all local activity logs? This cannot be undone.')) return;
        await sendMessage({ action: 'clear_logs' });
    });

    // Welcome dismiss
    document.getElementById('dismissWelcome')?.addEventListener('click', async () => {
        const banner = document.getElementById('welcomeBanner');
        if (banner) banner.style.display = 'none';
        try { await chrome.storage.local.set({ vaultbix_welcome_dismissed: true }); } catch {}
    });

    // Support link
    document.getElementById('supportLink')?.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: CONFIG.SUPPORT_URL || ('mailto:' + (CONFIG.SUPPORT_EMAIL || 'info@vaultbix.com')), active: true });
    });

    // Theme toggle
    document.getElementById('themeToggleBtn')?.addEventListener('click', toggleTheme);

    // Log updates
    try {
        chrome.runtime.onMessage.addListener((message) => {
            if (message?.action === 'log_updated' && currentView === 'mainView') {
                loadMainViewData();
            }
        });
    } catch {
        // fail silently
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

async function initializePopup() {
    if (isInitialized) return;

    try {
        setupEventListeners();
        await loadLicenseState();
        await loadSettings();
        renderStatusBadge();
        showView('mainView');
        await loadMainViewData();
        await checkFirstRun();
        isInitialized = true;
    } catch {
        showView('mainView');
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializePopup);
} else {
    initializePopup();
}
