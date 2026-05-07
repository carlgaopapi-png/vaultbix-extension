/**
 * VaultBix popup (v5)
 * Renders header status, stats, protection toggle, recent incidents and
 * sensitivity selector. Talks to the background service worker for state.
 */

(() => {
    'use strict';

    const $ = (id) => document.getElementById(id);

    // ─── State ─────────────────────────────────────────────────────────
    let state = {
        stats: { totalBlocked: 0, blockedToday: 0, sitesMonitored: 0, incidents: [] },
        settings: { protectionEnabled: true, sensitivity: 'balanced', firstRunCompleted: false },
        allowedSites: {},
        host: '',
        tabId: null,
        enterprise: { connected: false, orgName: null }
    };

    // ─── Helpers ───────────────────────────────────────────────────────
    function send(msg) {
        return new Promise((resolve) => {
            try {
                chrome.runtime.sendMessage(msg, (resp) => resolve(resp || null));
            } catch { resolve(null); }
        });
    }

    function timeAgo(ts) {
        try {
            const diff = Date.now() - new Date(ts).getTime();
            if (diff < 60_000) return 'Just now';
            if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
            if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} hr ago`;
            const days = Math.floor(diff / 86_400_000);
            if (days < 7) return `${days} d ago`;
            return new Date(ts).toLocaleDateString();
        } catch { return ''; }
    }

    function truncate(s, n) {
        if (!s) return '';
        return s.length <= n ? s : s.slice(0, n - 1) + '…';
    }

    function escapeText(node, text) {
        node.textContent = text == null ? '' : String(text);
    }

    // ─── Render: header / status ───────────────────────────────────────
    function renderHeader() {
        const shield = $('vbShield');
        const status = $('vbStatus');
        const enabled = state.settings.protectionEnabled;
        const blockedToday = state.stats.blockedToday;

        if (!enabled) {
            shield.dataset.state = 'off';
            shield.title = 'Protection paused';
            escapeText(status, 'Protection paused — VaultBix is not scanning');
            status.classList.remove('is-alert');
            return;
        }

        if (blockedToday > 0) {
            shield.dataset.state = 'alert';
            shield.title = `${blockedToday} leaks blocked today`;
            escapeText(status, `${blockedToday} leak${blockedToday === 1 ? '' : 's'} blocked today`);
            status.classList.add('is-alert');
        } else {
            shield.dataset.state = 'active';
            shield.title = 'Protection active';
            escapeText(status, 'Protected — 0 leaks today');
            status.classList.remove('is-alert');
        }
    }

    // ─── Render: stats ─────────────────────────────────────────────────
    function animateNumber(el, target) {
        if (!el) return;
        const start = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
        if (start === target) { el.textContent = target.toLocaleString(); return; }
        const duration = 300;
        const startTime = performance.now();
        function tick(now) {
            const t = Math.min(1, (now - startTime) / duration);
            const eased = 1 - Math.pow(1 - t, 3);
            el.textContent = Math.round(start + (target - start) * eased).toLocaleString();
            if (t < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }

    function renderStats() {
        animateNumber($('vbBlockedToday'),  state.stats.blockedToday);
        animateNumber($('vbBlockedTotal'),  state.stats.totalBlocked);
        animateNumber($('vbSitesMonitored'), state.stats.sitesMonitored);
    }

    // ─── Render: protection toggle ─────────────────────────────────────
    function renderToggle() {
        const pill = $('vbProtectionToggle');
        const domain = $('vbDomain');
        const enabled = state.settings.protectionEnabled;
        pill.setAttribute('aria-checked', enabled ? 'true' : 'false');
        const host = state.host || '—';
        escapeText(domain, enabled ? `Protecting: ${host}` : `Paused on: ${host}`);
    }

    // ─── Render: incidents ─────────────────────────────────────────────
    function buildIncidentNode(incident) {
        const li = document.createElement('li');
        const riskClass = incident.risk === 'HIGH' ? 'is-high'
                        : incident.risk === 'MEDIUM' ? 'is-medium' : 'is-low';
        li.className = `vb-incident ${riskClass} vb-fade-in`;

        const row = document.createElement('div');
        row.className = 'vb-incident__row';

        const typeWrap = document.createElement('div');
        typeWrap.className = 'vb-incident__type-wrap';
        const typeBadge = document.createElement('span');
        typeBadge.className = 'vb-incident__type';
        escapeText(typeBadge, incident.topType || 'Unknown');
        typeWrap.appendChild(typeBadge);

        const chip = document.createElement('span');
        chip.className = 'vb-incident__chip ' + (incident.blocked ? 'is-blocked' : 'is-allowed');
        escapeText(chip, incident.blocked ? 'Blocked' : 'Allowed');

        row.appendChild(typeWrap);
        row.appendChild(chip);

        const meta = document.createElement('div');
        meta.className = 'vb-incident__meta';
        const dest = document.createElement('span');
        dest.className = 'vb-incident__dest';
        escapeText(dest, truncate(incident.destination || '—', 32));
        const time = document.createElement('span');
        time.className = 'vb-incident__time';
        escapeText(time, timeAgo(incident.timestamp));
        meta.appendChild(dest);
        meta.appendChild(time);

        li.appendChild(row);
        li.appendChild(meta);
        return li;
    }

    function renderIncidents() {
        const list = $('vbIncidents');
        list.innerHTML = '';
        const incidents = state.stats.incidents || [];
        if (incidents.length === 0) {
            const li = document.createElement('li');
            li.className = 'vb-empty';
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('class', 'vb-empty__shield');
            svg.setAttribute('viewBox', '0 0 24 24');
            svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor');
            svg.setAttribute('stroke-width', '2');
            svg.setAttribute('stroke-linecap', 'round');
            svg.setAttribute('stroke-linejoin', 'round');
            const p1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            p1.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
            const p2 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            p2.setAttribute('d', 'M9 12l2 2 4-4');
            svg.appendChild(p1); svg.appendChild(p2);
            li.appendChild(svg);
            const text = document.createElement('div');
            text.className = 'vb-empty__text';
            escapeText(text, "No leaks detected — you're safe");
            li.appendChild(text);
            list.appendChild(li);
            return;
        }
        incidents.slice(0, 8).forEach((incident) => {
            list.appendChild(buildIncidentNode(incident));
        });
    }

    // ─── Render: sensitivity ───────────────────────────────────────────
    function renderSensitivity() {
        const wrap = $('vbSensitivity');
        const current = state.settings.sensitivity || 'balanced';
        wrap.querySelectorAll('.vb-segmented__btn').forEach((btn) => {
            btn.classList.toggle('is-active', btn.dataset.value === current);
        });
    }

    // ─── Toast helper ──────────────────────────────────────────────────
    function toast(text, kind) {
        const slot = $('vbToastSlot');
        slot.innerHTML = '';
        const t = document.createElement('div');
        t.className = `vb-toast vb-toast--${kind || 'saved'}`;
        escapeText(t, text);
        slot.appendChild(t);
        requestAnimationFrame(() => t.classList.add('is-show'));
        setTimeout(() => {
            t.classList.remove('is-show');
            setTimeout(() => { try { t.remove(); } catch {} }, 200);
        }, 3000);
    }

    // ─── Data load ─────────────────────────────────────────────────────
    async function loadAll() {
        const tabResp = await send({ action: 'get_active_tab_host' });
        if (tabResp?.success) {
            state.host = tabResp.host || '';
            state.tabId = tabResp.tabId || null;
        }
        const resp = await send({ action: 'get_stats' });
        if (resp?.success) {
            state.stats = resp.stats || state.stats;
            state.settings = resp.settings || state.settings;
            state.allowedSites = resp.allowedSites || {};
        }
        // Check enterprise connection
        const entResp = await send({ action: 'enterprise_status' });
        if (entResp?.success) {
            state.enterprise.connected = !!entResp.connected;
            state.enterprise.orgName = entResp.orgName || null;
        }
        renderAll();
    }

    function renderAll() {
        renderHeader();
        renderStats();
        renderToggle();
        renderIncidents();
        renderSensitivity();
        renderEnterprise();
    }

    // ─── Enterprise UI ───────────────────────────────────────────────
    function renderEnterprise() {
        const section = $('vbEnterprise');
        const orgName = $('vbOrgName');
        const badge = $('vbEntBadge');
        const connectBtn = $('vbConnectBtn');
        const connectLabel = $('vbConnectLabel');

        if (state.enterprise.connected) {
            section.style.display = 'block';
            escapeText(orgName, state.enterprise.orgName || 'Connected');
            escapeText(badge, 'Connected');
            connectBtn.classList.add('is-connected');
            escapeText(connectLabel, 'Connected');
        } else {
            section.style.display = 'none';
            connectBtn.classList.remove('is-connected');
            escapeText(connectLabel, 'Connect to Org');
        }
    }

    // ─── Event wiring ──────────────────────────────────────────────────
    function wireEvents() {
        // Team tier coming in v5.2 — hide until enterprise backend is ready
        $('vbConnectBtn').style.display = 'none';

        $('vbProtectionToggle').addEventListener('click', async () => {
            const next = !state.settings.protectionEnabled;
            state.settings.protectionEnabled = next;
            renderToggle(); renderHeader();
            await send({ action: 'update_settings', settings: { protectionEnabled: next } });
            toast(next ? 'Protection enabled' : 'Protection paused', next ? 'saved' : 'allowed');
        });

        document.querySelectorAll('#vbSensitivity .vb-segmented__btn').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const value = btn.dataset.value;
                state.settings.sensitivity = value;
                renderSensitivity();
                await send({ action: 'update_settings', settings: { sensitivity: value } });
                toast(`Sensitivity: ${value.charAt(0).toUpperCase() + value.slice(1)}`, 'saved');
            });
        });

        $('vbClearHistory').addEventListener('click', async () => {
            await send({ action: 'clear_history' });
            state.stats = { totalBlocked: 0, blockedToday: 0, sitesMonitored: 0, incidents: [] };
            renderAll();
            toast('History cleared', 'saved');
        });

        // Dashboard button — opens enterprise web dashboard
        $('vbOpenDashboard').addEventListener('click', () => {
            chrome.tabs.create({ url: 'https://vaultbix.com/dashboard' });
        });

        // Connect button — opens connect flow or shows token prompt
        $('vbConnectBtn').addEventListener('click', async () => {
            if (state.enterprise.connected) {
                // Already connected — open dashboard
                chrome.tabs.create({ url: 'https://vaultbix.com/dashboard' });
                return;
            }
            // Prompt for connect token
            const token = prompt('Paste your VaultBix connection token from the dashboard:');
            if (!token || !token.trim()) return;
            const apiBase = prompt('Dashboard URL (press OK for default):', 'http://localhost:3000') || 'http://localhost:3000';
            toast('Connecting...', 'saved');
            const resp = await send({
                action: 'enterprise_connect',
                connectToken: token.trim(),
                apiBaseUrl: apiBase.replace(/\/+$/, '')
            });
            if (resp?.success) {
                state.enterprise.connected = true;
                state.enterprise.orgName = resp.orgName || 'Connected';
                renderEnterprise();
                toast('Connected to ' + (resp.orgName || 'organization'), 'saved');
            } else {
                toast(resp?.error || 'Connection failed', 'blocked');
            }
        });

        // Live updates pushed from background when a new incident arrives
        try {
            chrome.runtime.onMessage.addListener((message) => {
                if (message?.action === 'incidents_updated') {
                    loadAll();
                }
            });
        } catch { /* ignore */ }
    }

    // ─── Boot ──────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        wireEvents();
        loadAll();
    });
})();
