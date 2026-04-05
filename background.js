/**
 * VaultBix Background Service Worker
 * Manages license state, custom rules, storage, messaging, and content script coordination.
 *
 * PRIVACY:
 * - All scanning happens locally in the browser.
 * - Logs are stored locally and never uploaded.
 * - Only network request: license key validation against our server (no prompt data sent).
 *
 * TIER MODEL:
 * - Free: Warnings/toasts only. 3 custom rules max.
 * - Pro (license key): Blocking, redaction, unlimited custom rules.
 *
 * @file background.js
 * @version 4.0.0
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const API_BASE_URL = 'https://server-vaultbix.vercel.app';
const CHECKOUT_URL = `${API_BASE_URL}/api/checkout/create`;
const LICENSE_VALIDATE_URL = `${API_BASE_URL}/api/license/validate`;

const LICENSE_REVALIDATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
const FREE_CUSTOM_RULES_LIMIT = 3;

// ============================================================================
// STORAGE KEYS
// ============================================================================

const STORAGE_KEYS = {
    LICENSE: 'vaultbix_license',
    SETTINGS: 'vaultbix_settings',
    CUSTOM_RULES: 'vaultbix_custom_rules',
    LOGS: 'vaultbix_logs',
    TOTAL_COUNT: 'vaultbix_total_count',
    DOMAIN_STATS: 'vaultbix_domain_stats',
    TYPE_COUNTS: 'vaultbix_type_counts',
    FIRST_RUN: 'vaultbix_first_run'
};

// Legacy key names for one-time migration
const LEGACY_KEYS = {
    'ai_firewall_logs': 'vaultbix_logs',
    'ai_firewall_total_count': 'vaultbix_total_count',
    'ai_firewall_domain_stats': 'vaultbix_domain_stats',
    'ai_firewall_type_counts': 'vaultbix_type_counts'
};

const MAX_LOGS = 1000;
const MAX_DOMAIN_STATS = 100;

// ============================================================================
// TIER SYSTEM
// ============================================================================

const TIERS = {
    FREE: 'free',
    PRO: 'pro'
};

const DEFAULT_SETTINGS = {
    warningsEnabled: true,
    blockingEnabled: true,
    redactionEnabled: true
};

// ============================================================================
// LICENSE MANAGEMENT
// ============================================================================

async function getLicenseState() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.LICENSE);
        return result[STORAGE_KEYS.LICENSE] || null;
    } catch {
        return null;
    }
}

async function saveLicenseState(license) {
    try {
        await chrome.storage.local.set({ [STORAGE_KEYS.LICENSE]: license });
    } catch {
        // fail silently
    }
}

async function activateLicense(licenseKey) {
    try {
        const response = await fetch(LICENSE_VALIDATE_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ licenseKey: licenseKey.trim() })
        });

        const data = await response.json();

        if (!response.ok || !data.valid) {
            return { success: false, error: data.error || 'Invalid license key' };
        }

        const license = {
            key: licenseKey.trim().toUpperCase(),
            tier: data.tier || TIERS.PRO,
            email: data.email,
            expiresAt: data.expiresAt || null,
            purchaseType: data.purchaseType,
            activatedAt: Date.now(),
            lastValidated: Date.now(),
            status: 'active'
        };

        await saveLicenseState(license);
        return { success: true, license };
    } catch (error) {
        return { success: false, error: 'Network error. Please check your connection.' };
    }
}

async function deactivateLicense() {
    try {
        await chrome.storage.local.remove(STORAGE_KEYS.LICENSE);
        return { success: true };
    } catch {
        return { success: false, error: 'Failed to deactivate' };
    }
}

async function revalidateLicense() {
    const license = await getLicenseState();
    if (!license || !license.key) return;

    if (license.expiresAt && Date.now() > license.expiresAt) {
        license.status = 'expired';
        await saveLicenseState(license);
        return;
    }

    if (Date.now() - license.lastValidated < LICENSE_REVALIDATION_INTERVAL) {
        return;
    }

    try {
        const response = await fetch(LICENSE_VALIDATE_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ licenseKey: license.key })
        });

        const data = await response.json();

        if (data.valid) {
            license.lastValidated = Date.now();
            license.status = 'active';
            if (data.expiresAt) license.expiresAt = data.expiresAt;
        } else {
            license.status = 'invalid';
        }

        await saveLicenseState(license);
    } catch {
        // Network error during revalidation — keep current state, try again later
    }
}

async function getCurrentTier() {
    const license = await getLicenseState();
    if (license && license.status === 'active') {
        if (license.expiresAt && Date.now() > license.expiresAt) {
            return TIERS.FREE;
        }
        return TIERS.PRO;
    }
    return TIERS.FREE;
}

async function hasFullFeatures() {
    return (await getCurrentTier()) === TIERS.PRO;
}

// ============================================================================
// SETTINGS
// ============================================================================

async function getSettings() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
        return { ...DEFAULT_SETTINGS, ...(result[STORAGE_KEYS.SETTINGS] || {}) };
    } catch {
        return { ...DEFAULT_SETTINGS };
    }
}

async function updateSettings(updates) {
    try {
        const current = await getSettings();
        const updated = { ...current, ...updates };
        await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated });
        return updated;
    } catch {
        return null;
    }
}

// ============================================================================
// CUSTOM RULES
// ============================================================================

async function getCustomRules() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES);
        return Array.isArray(result[STORAGE_KEYS.CUSTOM_RULES])
            ? result[STORAGE_KEYS.CUSTOM_RULES]
            : [];
    } catch {
        return [];
    }
}

async function saveCustomRules(rules) {
    try {
        await chrome.storage.local.set({ [STORAGE_KEYS.CUSTOM_RULES]: rules });
    } catch {
        // fail silently
    }
}

async function addCustomRule(rule) {
    const tier = await getCurrentTier();
    const rules = await getCustomRules();

    if (tier !== TIERS.PRO && rules.length >= FREE_CUSTOM_RULES_LIMIT) {
        return {
            success: false,
            error: `Free plan limited to ${FREE_CUSTOM_RULES_LIMIT} custom rules. Upgrade to Pro for unlimited.`
        };
    }

    try {
        new RegExp(rule.pattern);
    } catch {
        return { success: false, error: 'Invalid regex pattern' };
    }

    const newRule = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        name: rule.name || 'Custom Rule',
        pattern: rule.pattern,
        risk: rule.risk || 'HIGH',
        enabled: true,
        createdAt: Date.now()
    };

    rules.push(newRule);
    await saveCustomRules(rules);
    return { success: true, rule: newRule };
}

async function updateCustomRule(ruleId, updates) {
    const rules = await getCustomRules();
    const index = rules.findIndex(r => r.id === ruleId);
    if (index === -1) return { success: false, error: 'Rule not found' };

    if (updates.pattern) {
        try {
            new RegExp(updates.pattern);
        } catch {
            return { success: false, error: 'Invalid regex pattern' };
        }
    }

    rules[index] = { ...rules[index], ...updates };
    await saveCustomRules(rules);
    return { success: true, rule: rules[index] };
}

async function deleteCustomRule(ruleId) {
    const rules = await getCustomRules();
    const filtered = rules.filter(r => r.id !== ruleId);
    await saveCustomRules(filtered);
    return { success: true };
}

// ============================================================================
// CONSTANTS
// ============================================================================

const EVENT_TYPES = {
    PROMPT_DETECTED: 'PROMPT_DETECTED',
    PROMPT_BLOCKED: 'PROMPT_BLOCKED',
    PROMPT_REDACTED: 'PROMPT_REDACTED',
    PROMPT_OVERRIDDEN: 'PROMPT_OVERRIDDEN',
    PASTE_WARNING: 'PASTE_WARNING'
};

const RISK_WEIGHTS = {
    'PROMPT_BLOCKED': 8,
    'PROMPT_REDACTED': 8,
    'PROMPT_DETECTED': 5,
    'PROMPT_OVERRIDDEN': 6,
    'PASTE_WARNING': 4,
    'DETECTED': 5,
    'BLOCKED': 8,
    'REDACTED': 8,
    'OVERRIDDEN': 6
};

const RISK_THRESHOLDS = {
    critical: 85,
    high: 60,
    medium: 30,
    low: 0
};

// ============================================================================
// STORAGE FUNCTIONS
// ============================================================================

async function getLogs() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.LOGS);
        return Array.isArray(result[STORAGE_KEYS.LOGS]) ? result[STORAGE_KEYS.LOGS] : [];
    } catch {
        return [];
    }
}

function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return 'Unknown';
    try {
        const parsed = new URL(url);
        const sensitiveParams = ['token', 'key', 'secret', 'password', 'auth', 'api_key', 'apikey', 'access_token'];
        sensitiveParams.forEach(param => parsed.searchParams.delete(param));
        return parsed.origin + parsed.pathname;
    } catch {
        const match = url.match(/^https?:\/\/[^/]+/);
        return match ? match[0] : 'Unknown';
    }
}

function sanitizeDetails(details) {
    if (!details || typeof details !== 'string') return '';
    if (details.length > 200) {
        details = details.substring(0, 200) + '...';
    }
    return details
        .replace(/sk-[A-Za-z0-9_-]{20,}/g, 'sk-[REDACTED]')
        .replace(/ghp_[A-Za-z0-9]{30,}/g, 'ghp_[REDACTED]')
        .replace(/AKIA[A-Z0-9]{16}/g, 'AKIA[REDACTED]')
        .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
        .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]')
        .replace(/\b4[0-9]{12,15}\b/g, '[CARD]');
}

async function addLog(type, url, details = '', tabId = null) {
    try {
        const logs = await getLogs();

        const newLog = {
            id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
            timestamp: new Date().toISOString(),
            type: type || 'UNKNOWN',
            url: sanitizeUrl(url),
            details: sanitizeDetails(details),
            tabId: tabId
        };

        logs.unshift(newLog);
        if (logs.length > MAX_LOGS) logs.length = MAX_LOGS;

        await chrome.storage.local.set({ [STORAGE_KEYS.LOGS]: logs });
        updateStatsAsync(newLog).catch(() => {});
        notifyLogUpdate(newLog);

        return newLog;
    } catch {
        return null;
    }
}

async function clearLogs() {
    try {
        await chrome.storage.local.set({
            [STORAGE_KEYS.LOGS]: [],
            [STORAGE_KEYS.TOTAL_COUNT]: 0,
            [STORAGE_KEYS.DOMAIN_STATS]: {},
            [STORAGE_KEYS.TYPE_COUNTS]: {}
        });
        notifyLogUpdate(null);
    } catch {
        // fail silently
    }
}

async function getTotalCount() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.TOTAL_COUNT);
        const val = result[STORAGE_KEYS.TOTAL_COUNT];
        return typeof val === 'number' && isFinite(val) ? val : 0;
    } catch {
        return 0;
    }
}

async function updateStatsAsync(log) {
    try {
        const currentTotal = await getTotalCount();
        await chrome.storage.local.set({
            [STORAGE_KEYS.TOTAL_COUNT]: currentTotal + 1
        });
        await updateDomainStats(log);
        await updateTypeCounts(log);
    } catch {
        // fail silently
    }
}

async function updateDomainStats(log) {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.DOMAIN_STATS);
        const stats = result[STORAGE_KEYS.DOMAIN_STATS] || {};
        const domain = getDomainFromUrl(log.url);

        if (!stats[domain]) {
            stats[domain] = {
                count: 0,
                totalRisk: 0,
                types: {},
                firstSeen: log.timestamp,
                lastSeen: log.timestamp
            };
        }

        const domainStats = stats[domain];
        domainStats.count++;
        domainStats.totalRisk += RISK_WEIGHTS[log.type] || 1;
        domainStats.types[log.type] = (domainStats.types[log.type] || 0) + 1;
        domainStats.lastSeen = log.timestamp;

        const domains = Object.keys(stats);
        if (domains.length > MAX_DOMAIN_STATS) {
            const sorted = domains
                .map(d => ({ domain: d, lastSeen: stats[d].lastSeen }))
                .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
            sorted.slice(MAX_DOMAIN_STATS).forEach(({ domain: d }) => {
                delete stats[d];
            });
        }

        await chrome.storage.local.set({ [STORAGE_KEYS.DOMAIN_STATS]: stats });
    } catch {
        // fail silently
    }
}

async function updateTypeCounts(log) {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.TYPE_COUNTS);
        const counts = result[STORAGE_KEYS.TYPE_COUNTS] || {};
        counts[log.type] = (counts[log.type] || 0) + 1;
        await chrome.storage.local.set({ [STORAGE_KEYS.TYPE_COUNTS]: counts });
    } catch {
        // fail silently
    }
}

function notifyLogUpdate(log) {
    try {
        chrome.runtime.sendMessage({
            action: 'log_updated',
            log: log
        }).catch(() => {});
    } catch {
        // popup may be closed
    }
}

// ============================================================================
// RISK CALCULATION
// ============================================================================

function getDomainFromUrl(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return 'Unknown';
    }
}

function calculateDomainRisk(domain, logs) {
    const domainLogs = logs.filter(log => {
        try {
            return getDomainFromUrl(log.url) === domain;
        } catch {
            return false;
        }
    });

    if (domainLogs.length === 0) {
        return { score: 0, level: 'low', count: 0 };
    }

    let totalRisk = 0;
    const typeCounts = {};

    domainLogs.forEach(log => {
        const weight = RISK_WEIGHTS[log.type] || 1;
        totalRisk += weight;
        typeCounts[log.type] = (typeCounts[log.type] || 0) + 1;
    });

    const maxWeight = Math.max(...Object.values(RISK_WEIGHTS), 1);
    const avgWeight = totalRisk / domainLogs.length;
    const score = Math.min(100, Math.round((avgWeight / maxWeight) * 100));

    let level = 'low';
    if (score >= RISK_THRESHOLDS.critical) level = 'critical';
    else if (score >= RISK_THRESHOLDS.high) level = 'high';
    else if (score >= RISK_THRESHOLDS.medium) level = 'medium';

    return { score, level, count: domainLogs.length, types: Object.keys(typeCounts).length };
}

async function getTopRiskyDomains(limit = 10) {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.DOMAIN_STATS);
        const stats = result[STORAGE_KEYS.DOMAIN_STATS] || {};
        const maxWeight = Math.max(...Object.values(RISK_WEIGHTS), 1);

        const domainRisks = Object.entries(stats).map(([domain, data]) => {
            const avgWeight = data.count > 0 ? data.totalRisk / data.count : 0;
            const score = Math.min(100, Math.round((avgWeight / maxWeight) * 100));

            let level = 'low';
            if (score >= RISK_THRESHOLDS.critical) level = 'critical';
            else if (score >= RISK_THRESHOLDS.high) level = 'high';
            else if (score >= RISK_THRESHOLDS.medium) level = 'medium';

            return { domain, score, level, count: data.count, types: Object.keys(data.types || {}).length };
        });

        return domainRisks
            .filter(d => d.count > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, limit);
    } catch {
        return [];
    }
}

async function getCurrentTabRisk(tabId) {
    try {
        const tab = await chrome.tabs.get(tabId);
        if (!tab?.url) return { score: 0, level: 'low', count: 0 };
        const domain = getDomainFromUrl(tab.url);
        const logs = await getLogs();
        return calculateDomainRisk(domain, logs);
    } catch {
        return { score: 0, level: 'low', count: 0 };
    }
}

// ============================================================================
// FIRST-RUN HANDLING
// ============================================================================

async function handleFirstRun() {
    try {
        const result = await chrome.storage.local.get(STORAGE_KEYS.FIRST_RUN);
        if (!result[STORAGE_KEYS.FIRST_RUN]) {
            await chrome.storage.local.set({ [STORAGE_KEYS.FIRST_RUN]: Date.now() });
        }
    } catch {
        // fail silently
    }
}

async function migrateLegacyStorageKeys() {
    try {
        const legacyKeys = Object.keys(LEGACY_KEYS);
        const existing = await chrome.storage.local.get(legacyKeys);
        const updates = {};
        const removals = [];

        for (const [oldKey, newKey] of Object.entries(LEGACY_KEYS)) {
            if (existing[oldKey] !== undefined) {
                // Only migrate if new key doesn't already have data
                const check = await chrome.storage.local.get(newKey);
                if (check[newKey] === undefined) {
                    updates[newKey] = existing[oldKey];
                }
                removals.push(oldKey);
            }
        }

        if (Object.keys(updates).length > 0) {
            await chrome.storage.local.set(updates);
        }
        if (removals.length > 0) {
            await chrome.storage.local.remove(removals);
        }
    } catch {
        // fail silently — migration is best-effort
    }
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

async function handleMessage(message, sender, sendResponse) {
    try {
        switch (message.action) {
            // ---- Logs ----
            case 'get_logs': {
                const logs = await getLogs();
                sendResponse({ success: true, logs });
                break;
            }
            case 'get_total_count': {
                const total = await getTotalCount();
                sendResponse({ success: true, total });
                break;
            }
            case 'client_side_detection': {
                await addLog(
                    message.type || 'UNKNOWN',
                    message.url || sender?.tab?.url || 'Unknown',
                    message.details || '',
                    sender?.tab?.id
                );
                sendResponse({ success: true });
                break;
            }
            case 'clear_logs': {
                await clearLogs();
                sendResponse({ success: true });
                break;
            }

            // ---- Risk ----
            case 'get_top_risky_domains': {
                const domains = await getTopRiskyDomains(message.limit || 10);
                sendResponse({ success: true, domains });
                break;
            }
            case 'get_current_tab_risk': {
                if (sender?.tab?.id) {
                    const risk = await getCurrentTabRisk(sender.tab.id);
                    sendResponse({ success: true, risk });
                } else {
                    try {
                        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                        if (tab?.id) {
                            const risk = await getCurrentTabRisk(tab.id);
                            sendResponse({ success: true, risk });
                        } else {
                            sendResponse({ success: true, risk: { score: 0, level: 'low', count: 0 } });
                        }
                    } catch {
                        sendResponse({ success: true, risk: { score: 0, level: 'low', count: 0 } });
                    }
                }
                break;
            }
            case 'get_type_breakdown': {
                try {
                    const result = await chrome.storage.local.get(STORAGE_KEYS.TYPE_COUNTS);
                    const counts = result[STORAGE_KEYS.TYPE_COUNTS] || {};
                    const totalEvents = Object.values(counts).reduce((a, b) => a + (b || 0), 0);
                    sendResponse({ success: true, breakdown: { counts, totalEvents } });
                } catch (e) {
                    sendResponse({ success: false, error: e.message });
                }
                break;
            }

            // ---- License ----
            case 'activate_license': {
                const result = await activateLicense(message.licenseKey);
                sendResponse(result);
                break;
            }
            case 'deactivate_license': {
                const deactivateResult = await deactivateLicense();
                sendResponse(deactivateResult);
                break;
            }
            case 'get_license_state': {
                const license = await getLicenseState();
                const tier = await getCurrentTier();
                sendResponse({ success: true, license, tier });
                break;
            }
            case 'get_checkout_url': {
                const plan = message.plan || 'monthly';
                sendResponse({ success: true, url: `${CHECKOUT_URL}?plan=${plan}` });
                break;
            }

            // ---- Tier & Settings ----
            case 'get_tier': {
                const currentTier = await getCurrentTier();
                const fullFeatures = await hasFullFeatures();
                sendResponse({ success: true, tier: currentTier, hasFullFeatures: fullFeatures });
                break;
            }
            case 'get_settings': {
                const settings = await getSettings();
                sendResponse({ success: true, settings });
                break;
            }
            case 'update_settings': {
                const updated = await updateSettings(message.settings || {});
                sendResponse({ success: true, settings: updated });
                break;
            }
            case 'check_features': {
                const tier = await getCurrentTier();
                const isPro = tier === TIERS.PRO;
                const settings = await getSettings();
                sendResponse({
                    success: true,
                    tier,
                    isPro,
                    blockingEnabled: isPro && settings.blockingEnabled,
                    redactionEnabled: isPro && settings.redactionEnabled,
                    warningsEnabled: settings.warningsEnabled
                });
                break;
            }

            // ---- Custom Rules ----
            case 'get_custom_rules': {
                const rules = await getCustomRules();
                const rulesLimit = (await getCurrentTier()) === TIERS.PRO ? Infinity : FREE_CUSTOM_RULES_LIMIT;
                sendResponse({ success: true, rules, limit: rulesLimit });
                break;
            }
            case 'add_custom_rule': {
                const addResult = await addCustomRule(message.rule);
                sendResponse(addResult);
                break;
            }
            case 'update_custom_rule': {
                const updateResult = await updateCustomRule(message.ruleId, message.updates);
                sendResponse(updateResult);
                break;
            }
            case 'delete_custom_rule': {
                const deleteResult = await deleteCustomRule(message.ruleId);
                sendResponse(deleteResult);
                break;
            }

            // ---- Legacy compat ----
            case 'get_trial_state': {
                const legacyTier = await getCurrentTier();
                const legacyLicense = await getLicenseState();
                sendResponse({
                    success: true,
                    isActive: legacyTier === TIERS.PRO,
                    daysRemaining: legacyLicense?.expiresAt
                        ? Math.max(0, Math.ceil((legacyLicense.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)))
                        : 0,
                    tier: legacyTier
                });
                break;
            }

            default:
                sendResponse({ success: false, error: 'Unknown action' });
        }
    } catch (error) {
        sendResponse({ success: false, error: error?.message || 'Internal error' });
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

function initialize() {
    try {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            handleMessage(message, sender, sendResponse);
            return true;
        });

        chrome.runtime.onInstalled.addListener((details) => {
            try {
                if (details.reason === 'install') {
                    handleFirstRun();
                }
                // Migrate legacy ai_firewall_* keys on install or update
                migrateLegacyStorageKeys();
            } catch {
                // fail silently
            }
        });

        // Periodic license revalidation
        chrome.alarms?.create('revalidate_license', { periodInMinutes: 60 });
        chrome.alarms?.onAlarm?.addListener((alarm) => {
            if (alarm.name === 'revalidate_license') {
                revalidateLicense();
            }
        });

    } catch {
        // fail silently
    }
}

initialize();
