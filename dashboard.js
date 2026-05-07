/**
 * VaultBix Dashboard
 * Full-page incident view, fed by the background service worker.
 */

(() => {
    'use strict';

    function send(msg) {
        return new Promise((resolve) => {
            try { chrome.runtime.sendMessage(msg, (resp) => resolve(resp || null)); }
            catch { resolve(null); }
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
            return new Date(ts).toLocaleString();
        } catch { return ''; }
    }

    function escapeText(node, text) {
        node.textContent = text == null ? '' : String(text);
    }

    async function load() {
        const resp = await send({ action: 'get_stats' });
        if (!resp?.success) return;
        const stats = resp.stats || {};

        document.getElementById('dashToday').textContent = (stats.blockedToday || 0).toLocaleString();
        document.getElementById('dashTotal').textContent = (stats.totalBlocked || 0).toLocaleString();
        document.getElementById('dashSites').textContent = (stats.sitesMonitored || 0).toLocaleString();

        const body = document.getElementById('dashBody');
        body.innerHTML = '';
        const incidents = stats.incidents || [];
        if (incidents.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 5;
            td.style.textAlign = 'center';
            td.style.padding = '32px';
            td.style.color = 'var(--vb-text-mute)';
            escapeText(td, 'No incidents yet — VaultBix is monitoring.');
            tr.appendChild(td);
            body.appendChild(tr);
            return;
        }

        for (const inc of incidents) {
            const tr = document.createElement('tr');

            const tdWhen = document.createElement('td');
            escapeText(tdWhen, timeAgo(inc.timestamp));

            const tdType = document.createElement('td');
            escapeText(tdType, inc.topType || 'Unknown');

            const tdSnippet = document.createElement('td');
            tdSnippet.className = 'snippet';
            const first = (inc.findings || [])[0];
            // Render <prefix>+dots. Prefix is the public type marker only
            // (e.g. "AKIA", "sk-ant-"); PII and entropy findings have an
            // empty prefix by design (see KNOWN_PREFIXES in content/main.js)
            // so they render as pure dots — no part of the value leaks.
            // Cap dots at 12 so very long secrets don't blow out the column.
            let preview = '';
            if (first) {
                const prefix = first.prefix || '';
                const total = first.length || 0;
                const dotCount = Math.max(0, Math.min(total - prefix.length, 12));
                preview = prefix + '•'.repeat(dotCount);
            }
            escapeText(tdSnippet, preview);

            const tdDest = document.createElement('td');
            escapeText(tdDest, inc.destination || '');

            const tdStatus = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = 'badge ' + (inc.blocked ? 'blocked' : 'allowed');
            escapeText(badge, inc.blocked ? 'Blocked' : 'Allowed');
            tdStatus.appendChild(badge);

            tr.appendChild(tdWhen);
            tr.appendChild(tdType);
            tr.appendChild(tdSnippet);
            tr.appendChild(tdDest);
            tr.appendChild(tdStatus);
            body.appendChild(tr);
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        load();
        try {
            chrome.runtime.onMessage.addListener((m) => {
                if (m?.action === 'incidents_updated') load();
            });
        } catch { /* ignore */ }
    });
})();
