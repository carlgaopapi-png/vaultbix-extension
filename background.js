/**
 * VaultBix Background Service Worker (v5)
 *
 * Owns:
 *  - Incident logging  (chrome.storage.local)
 *  - Settings + per-site allowlist
 *  - Badge counter on the toolbar icon
 *  - Dashboard tab opener
 *  - Broadcast of settings updates to active tabs
 *
 * 100 % local. No network calls.
 */

const STORAGE_KEYS = {
    INCIDENTS:     'vaultbix_incidents_v5',
    TOTAL_BLOCKED: 'vaultbix_total_blocked_v5',
    SITES_SEEN:    'vaultbix_sites_seen_v5',
    SETTINGS:      'vaultbix_settings_v5',
    ALLOWED_SITES: 'vaultbix_allowed_sites_v5',
    // Enterprise sync
    ENTERPRISE_AUTH: 'vaultbix_enterprise_auth',
    SYNC_QUEUE:     'vaultbix_sync_queue',
    LAST_POLICY_POLL: 'vaultbix_last_policy_poll'
};

const MAX_INCIDENTS = 200;

const DEFAULT_SETTINGS = {
    protectionEnabled: true,
    sensitivity: 'balanced', // strict | balanced | minimal
    // First-run is opt-in: until the user finishes onboarding the content
    // script treats the extension as "warn-only" and never blocks a request,
    // regardless of which sensitivity tier is stored.
    firstRunCompleted: false
};

// ============================================================================
// STORAGE HELPERS
// ============================================================================

async function getIncidents() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.INCIDENTS);
        return Array.isArray(r[STORAGE_KEYS.INCIDENTS]) ? r[STORAGE_KEYS.INCIDENTS] : [];
    } catch { return []; }
}

async function getTotalBlocked() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.TOTAL_BLOCKED);
        return typeof r[STORAGE_KEYS.TOTAL_BLOCKED] === 'number' ? r[STORAGE_KEYS.TOTAL_BLOCKED] : 0;
    } catch { return 0; }
}

async function getSitesSeen() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.SITES_SEEN);
        return r[STORAGE_KEYS.SITES_SEEN] || {};
    } catch { return {}; }
}

async function getSettings() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
        return { ...DEFAULT_SETTINGS, ...(r[STORAGE_KEYS.SETTINGS] || {}) };
    } catch { return { ...DEFAULT_SETTINGS }; }
}

async function getAllowedSites() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.ALLOWED_SITES);
        return r[STORAGE_KEYS.ALLOWED_SITES] || {};
    } catch { return {}; }
}

// ============================================================================
// INCIDENT LOGGING
// ============================================================================

async function logIncident(incident) {
    try {
        const incidents = await getIncidents();
        // Project to safe fields only. The content script has already hashed
        // and stripped raw secret values; we keep only the masked-preview
        // metadata (prefix/length/hash). README claim "never the actual
        // secret values" depends on this projection — do not add a snippet
        // field here without auditing it.
        const safeIncident = {
            id: incident.id,
            timestamp: incident.timestamp || Date.now(),
            destination: incident.destination,
            destinationFull: incident.destinationFull,
            method: incident.method || 'GET',
            siteOrigin: incident.siteOrigin || '',
            blocked: incident.blocked === true,
            risk: incident.risk || 'LOW',
            topType: incident.topType || 'Unknown',
            findings: (incident.findings || []).slice(0, 8).map((f) => ({
                id: f.id,
                name: f.name,
                type: f.type,
                risk: f.risk,
                confidence: f.confidence,
                prefix: f.prefix,
                length: f.length,
                hash: f.hash
            }))
        };
        incidents.unshift(safeIncident);
        if (incidents.length > MAX_INCIDENTS) incidents.length = MAX_INCIDENTS;
        await chrome.storage.local.set({ [STORAGE_KEYS.INCIDENTS]: incidents });

        // Bump per-site counter
        const sitesSeen = await getSitesSeen();
        sitesSeen[safeIncident.siteOrigin || 'unknown'] =
            (sitesSeen[safeIncident.siteOrigin || 'unknown'] || 0) + 1;
        await chrome.storage.local.set({ [STORAGE_KEYS.SITES_SEEN]: sitesSeen });

        // Bump total blocked + badge
        if (safeIncident.blocked) {
            const total = await getTotalBlocked();
            const newTotal = total + 1;
            await chrome.storage.local.set({ [STORAGE_KEYS.TOTAL_BLOCKED]: newTotal });
            updateBadge(newTotal);
        }

        // Queue for enterprise sync (if connected)
        try { await addToSyncQueue(safeIncident); } catch { /* ignore */ }

        // Notify popup so it can refresh in real time
        try {
            chrome.runtime.sendMessage({ action: 'incidents_updated', latest: safeIncident }).catch(() => {});
        } catch { /* popup may be closed */ }

        return safeIncident;
    } catch (e) {
        return null;
    }
}

function updateBadge(total) {
    try {
        const text = total === 0 ? '' : total > 99 ? '99+' : String(total);
        chrome.action.setBadgeText({ text });
        chrome.action.setBadgeBackgroundColor({ color: '#E24B4A' });
    } catch { /* ignore */ }
}

async function refreshBadgeFromStorage() {
    const total = await getTotalBlocked();
    updateBadge(total);
}

// ============================================================================
// STATS
// ============================================================================

function isToday(ts) {
    try {
        const d = new Date(ts);
        const now = new Date();
        return d.toDateString() === now.toDateString();
    } catch { return false; }
}

async function getStats() {
    const incidents = await getIncidents();
    const sitesSeen = await getSitesSeen();
    const totalBlocked = await getTotalBlocked();
    const blockedToday = incidents.filter((i) => i.blocked && isToday(i.timestamp)).length;
    return {
        totalBlocked,
        blockedToday,
        sitesMonitored: Object.keys(sitesSeen).length,
        incidents: incidents.slice(0, 20)
    };
}

// ============================================================================
// SETTINGS / ALLOWLIST
// ============================================================================

async function updateSettings(updates) {
    const current = await getSettings();
    const next = { ...current, ...(updates || {}) };
    await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: next });
    broadcastSettings(next, await getAllowedSites());
    return next;
}

async function setSiteAllowed(hostname, allowed) {
    const sites = await getAllowedSites();
    if (allowed) sites[hostname] = true;
    else delete sites[hostname];
    await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWED_SITES]: sites });
    broadcastSettings(await getSettings(), sites);
    return sites;
}

async function clearHistory() {
    await chrome.storage.local.set({
        [STORAGE_KEYS.INCIDENTS]: [],
        [STORAGE_KEYS.TOTAL_BLOCKED]: 0,
        [STORAGE_KEYS.SITES_SEEN]: {}
    });
    updateBadge(0);
}

function broadcastSettings(settings, allowedSites) {
    // Push live update to all tabs so the content script can react
    try {
        chrome.tabs.query({}, (tabs) => {
            for (const tab of tabs || []) {
                if (!tab.id) continue;
                chrome.tabs.sendMessage(tab.id, {
                    action: 'settings_updated',
                    settings,
                    allowedSites
                }).catch(() => {});
            }
        });
    } catch { /* ignore */ }
}

// ============================================================================
// MESSAGE HANDLER
// ============================================================================

async function handleMessage(message, sender, sendResponse) {
    try {
        switch (message?.action) {
            case 'log_incident': {
                const saved = await logIncident(message.incident);
                sendResponse({ success: true, incident: saved });
                break;
            }
            case 'get_stats': {
                const stats = await getStats();
                const settings = await getSettings();
                const allowedSites = await getAllowedSites();
                sendResponse({ success: true, stats, settings, allowedSites });
                break;
            }
            case 'get_settings': {
                const settings = await getSettings();
                const allowedSites = await getAllowedSites();
                sendResponse({ success: true, settings, allowedSites });
                break;
            }
            case 'update_settings': {
                const settings = await updateSettings(message.settings || {});
                sendResponse({ success: true, settings });
                break;
            }
            case 'set_site_allowed': {
                const sites = await setSiteAllowed(message.hostname, !!message.allowed);
                sendResponse({ success: true, allowedSites: sites });
                break;
            }
            case 'clear_history': {
                await clearHistory();
                sendResponse({ success: true });
                break;
            }
            case 'mark_allowed_once': {
                // Logged for transparency; allow-once is enforced in the content script
                sendResponse({ success: true });
                break;
            }
            case 'open_dashboard': {
                try {
                    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
                } catch { /* ignore */ }
                sendResponse({ success: true });
                break;
            }
            case 'open_onboarding': {
                try {
                    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
                } catch { /* ignore */ }
                sendResponse({ success: true });
                break;
            }
            // ── Enterprise sync handlers ──────────────────────────────
            case 'enterprise_connect': {
                const result = await connectToEnterprise(
                    message.connectToken,
                    message.apiBaseUrl || 'https://vaultbix-web.vercel.app'
                );
                if (result.success) startEnterpriseSync();
                sendResponse(result);
                break;
            }
            case 'enterprise_disconnect': {
                stopEnterpriseSync();
                await clearEnterpriseAuth();
                sendResponse({ success: true });
                break;
            }
            case 'enterprise_status': {
                const auth = await getEnterpriseAuth();
                sendResponse({
                    success: true,
                    connected: !!auth?.extensionToken,
                    orgName: auth?.orgName || null,
                    orgId: auth?.orgId || null
                });
                break;
            }
            case 'mark_first_run_complete': {
                // Persist the chosen sensitivity (if provided) and flip the
                // first-run flag so the content script starts enforcing the
                // user's selection. Falls back to 'balanced' on bad input.
                const chosen = ['strict', 'balanced', 'minimal'].includes(message.sensitivity)
                    ? message.sensitivity
                    : 'balanced';
                const settings = await updateSettings({
                    sensitivity: chosen,
                    firstRunCompleted: true
                });
                sendResponse({ success: true, settings });
                break;
            }
            case 'get_active_tab_host': {
                try {
                    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    let host = '';
                    if (tab?.url) { try { host = new URL(tab.url).hostname; } catch { /* ignore */ } }
                    sendResponse({ success: true, host, tabId: tab?.id || null });
                } catch {
                    sendResponse({ success: true, host: '', tabId: null });
                }
                break;
            }
            default:
                sendResponse({ success: false, error: 'Unknown action' });
        }
    } catch (e) {
        sendResponse({ success: false, error: (e && e.message) || 'Internal error' });
    }
}

// ============================================================================
// ENTERPRISE SYNC
// ============================================================================

const SYNC_INTERVAL_MS = 60 * 1000;       // batch sync every 60 seconds
const POLICY_POLL_INTERVAL_MS = 5 * 60 * 1000; // poll policy every 5 minutes

// Auth stored as plain JSON in chrome.storage.local — relies on
// Chrome's per-extension isolation.
async function getEnterpriseAuth() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.ENTERPRISE_AUTH);
        const value = r[STORAGE_KEYS.ENTERPRISE_AUTH];
        if (!value) return null;
        // Backwards compat: pre-v5.0 installs stored auth as a string blob.
        // If we see a string instead of an object, drop it — the user will reconnect.
        if (typeof value === 'string') {
            await chrome.storage.local.remove(STORAGE_KEYS.ENTERPRISE_AUTH);
            return null;
        }
        return value;
    } catch { return null; }
}

async function setEnterpriseAuth(authData) {
    try {
        await chrome.storage.local.set({ [STORAGE_KEYS.ENTERPRISE_AUTH]: authData });
    } catch { /* ignore */ }
}

async function clearEnterpriseAuth() {
    await chrome.storage.local.remove([STORAGE_KEYS.ENTERPRISE_AUTH, STORAGE_KEYS.SYNC_QUEUE]);
}

async function getSyncQueue() {
    try {
        const r = await chrome.storage.local.get(STORAGE_KEYS.SYNC_QUEUE);
        return Array.isArray(r[STORAGE_KEYS.SYNC_QUEUE]) ? r[STORAGE_KEYS.SYNC_QUEUE] : [];
    } catch { return []; }
}

async function addToSyncQueue(incident) {
    const queue = await getSyncQueue();
    const f = incident.findings?.[0] || {};
    queue.push({
        secretType: incident.topType || 'Unknown',
        secretCategory: f.type || 'UNKNOWN',
        confidence: f.confidence || 'Medium',
        destinationUrl: incident.destinationFull || incident.destination || '',
        secretHash: f.hash || '',          // precomputed by content script
        secretPrefix: f.prefix || '',      // public type marker only ('AKIA', 'sk-ant-'); '' for PII
        secretLength: f.length || 0,
        actionTaken: incident.blocked ? 'BLOCKED' : 'WARNED',
        risk: incident.risk || 'MEDIUM',
        timestamp: incident.timestamp || Date.now(),
    });
    // Cap queue at 500 to prevent storage bloat
    if (queue.length > 500) queue.splice(0, queue.length - 500);
    await chrome.storage.local.set({ [STORAGE_KEYS.SYNC_QUEUE]: queue });
}

async function syncIncidentsToBackend() {
    const auth = await getEnterpriseAuth();
    if (!auth?.extensionToken || !auth?.apiBaseUrl) return;

    const queue = await getSyncQueue();
    if (queue.length === 0) return;

    try {
        const res = await fetch(`${auth.apiBaseUrl}/api/incidents`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.extensionToken}`
            },
            body: JSON.stringify({ incidents: queue })
        });

        if (res.ok) {
            // Clear synced incidents from queue
            await chrome.storage.local.set({ [STORAGE_KEYS.SYNC_QUEUE]: [] });
        } else if (res.status === 401) {
            // Token invalid — disconnect
            await clearEnterpriseAuth();
        }
    } catch { /* network error — will retry next cycle */ }
}

async function pollOrgPolicy() {
    const auth = await getEnterpriseAuth();
    if (!auth?.extensionToken || !auth?.apiBaseUrl) return;

    try {
        const res = await fetch(`${auth.apiBaseUrl}/api/org/policy`, {
            headers: { 'Authorization': `Bearer ${auth.extensionToken}` }
        });

        if (!res.ok) return;
        const policy = await res.json();

        // Map enterprise sensitivity to local setting
        const sensitivityMap = { STRICT: 'strict', BALANCED: 'balanced', MINIMAL: 'minimal' };
        const sensitivity = sensitivityMap[policy.sensitivityMode] || 'balanced';

        const current = await getSettings();
        if (current.sensitivity !== sensitivity) {
            await updateSettings({ sensitivity });
        }

        // Update allowed sites from org policy
        if (policy.allowedSites && Array.isArray(policy.allowedSites)) {
            const sites = await getAllowedSites();
            for (const site of policy.allowedSites) {
                sites[site] = true;
            }
            await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWED_SITES]: sites });
            broadcastSettings(await getSettings(), sites);
        }

        await chrome.storage.local.set({ [STORAGE_KEYS.LAST_POLICY_POLL]: Date.now() });
    } catch { /* network error — will retry */ }
}

async function connectToEnterprise(connectToken, apiBaseUrl) {
    try {
        const res = await fetch(`${apiBaseUrl}/api/auth/extension`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: connectToken })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            return { success: false, error: err.error || 'Connection failed' };
        }

        const data = await res.json();
        await setEnterpriseAuth({
            extensionToken: data.extensionToken,
            userId: data.userId,
            orgId: data.orgId,
            orgName: data.orgName,
            apiBaseUrl
        });

        // Immediately poll policy
        await pollOrgPolicy();

        return { success: true, orgName: data.orgName };
    } catch (e) {
        return { success: false, error: e.message || 'Network error' };
    }
}

// Enterprise sync timers
let syncTimer = null;
let policyTimer = null;

function startEnterpriseSync() {
    if (syncTimer) return; // already running
    syncTimer = setInterval(syncIncidentsToBackend, SYNC_INTERVAL_MS);
    policyTimer = setInterval(pollOrgPolicy, POLICY_POLL_INTERVAL_MS);
}

function stopEnterpriseSync() {
    if (syncTimer) { clearInterval(syncTimer); syncTimer = null; }
    if (policyTimer) { clearInterval(policyTimer); policyTimer = null; }
}

async function maybeStartEnterpriseSync() {
    const auth = await getEnterpriseAuth();
    if (auth?.extensionToken) {
        startEnterpriseSync();
    }
}

// ============================================================================
// INIT
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender, sendResponse);
    return true; // async sendResponse
});

chrome.runtime.onInstalled.addListener((details) => {
    refreshBadgeFromStorage();
    // On a fresh install, open the onboarding page which now includes
    // sign-in prompt. The extension stays in warn-only mode until the
    // user either signs in or explicitly chooses "Use Without Account".
    if (details && details.reason === 'install') {
        try {
            chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
        } catch { /* ignore */ }
    }
});

chrome.runtime.onStartup?.addListener(() => {
    refreshBadgeFromStorage();
});

// Initial badge sync (service-worker wakeup)
refreshBadgeFromStorage();

// Start enterprise sync if previously connected
maybeStartEnterpriseSync();
