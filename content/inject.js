/**
 * VaultBix Page-World Interceptor
 *
 * This script is injected into the page's main world (NOT the content-script
 * isolated world) so it can monkey-patch window.fetch and XMLHttpRequest in a
 * way the page itself sees. It then communicates outgoing requests to the
 * content script via window.postMessage.
 *
 * Protocol:
 *   page  -> content : { source: 'vaultbix-page', kind: 'request', id, url, method, body, headers }
 *   content -> page  : { source: 'vaultbix-cs',   kind: 'verdict', id, allow: bool }
 *
 * The page side waits up to BLOCK_TIMEOUT_MS for a verdict before allowing
 * the request through. If the verdict is `allow: false`, the request is
 * cancelled (fetch rejects, XHR aborts, form submission is cancelled).
 */

(() => {
    if (window.__vaultbixInjected) return;
    window.__vaultbixInjected = true;

    const BLOCK_TIMEOUT_MS = 1500;
    const MAX_BODY_SCAN = 50000;
    const pending = new Map();

    function nextId() {
        return 'vb_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
    }

    function bodyToString(body) {
        try {
            if (body == null) return '';
            if (typeof body === 'string') return body.slice(0, MAX_BODY_SCAN);
            if (body instanceof URLSearchParams) return body.toString().slice(0, MAX_BODY_SCAN);
            if (body instanceof FormData) {
                const parts = [];
                for (const [k, v] of body.entries()) {
                    parts.push(`${k}=${typeof v === 'string' ? v : '[file]'}`);
                }
                return parts.join('&').slice(0, MAX_BODY_SCAN);
            }
            if (body instanceof Blob) return '';
            if (body instanceof ArrayBuffer) return '';
            if (typeof body === 'object') {
                try { return JSON.stringify(body).slice(0, MAX_BODY_SCAN); } catch { return ''; }
            }
            return String(body).slice(0, MAX_BODY_SCAN);
        } catch { return ''; }
    }

    function headersToString(headers) {
        try {
            if (!headers) return '';
            if (headers instanceof Headers) {
                const parts = [];
                headers.forEach((v, k) => parts.push(`${k}: ${v}`));
                return parts.join('\n');
            }
            if (Array.isArray(headers)) {
                return headers.map(([k, v]) => `${k}: ${v}`).join('\n');
            }
            if (typeof headers === 'object') {
                return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
            }
            return '';
        } catch { return ''; }
    }

    function askContentScript(payload) {
        return new Promise((resolve) => {
            const id = nextId();
            const timeout = setTimeout(() => {
                if (pending.has(id)) {
                    pending.delete(id);
                    resolve({ allow: true, timedOut: true });
                }
            }, BLOCK_TIMEOUT_MS);

            pending.set(id, (verdict) => {
                clearTimeout(timeout);
                resolve(verdict);
            });

            window.postMessage({
                source: 'vaultbix-page',
                kind: 'request',
                id,
                ...payload
            }, '*');
        });
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.source !== 'vaultbix-cs' || data.kind !== 'verdict') return;
        const handler = pending.get(data.id);
        if (handler) {
            pending.delete(data.id);
            handler(data);
        }
    });

    // ─── fetch monkey-patch ────────────────────────────────────────────────
    const originalFetch = window.fetch;
    window.fetch = async function (input, init) {
        try {
            let url = '';
            let method = 'GET';
            let body = '';
            let headers = '';

            if (typeof input === 'string') {
                url = input;
            } else if (input instanceof URL) {
                url = input.href;
            } else if (input && typeof input === 'object' && 'url' in input) {
                url = input.url;
                method = input.method || 'GET';
                headers = headersToString(input.headers);
                try {
                    if (input.bodyUsed === false && typeof input.clone === 'function') {
                        body = await input.clone().text();
                    }
                } catch { /* ignore */ }
            }

            if (init) {
                if (init.method) method = init.method;
                if (init.headers) headers = headersToString(init.headers);
                if (init.body !== undefined) body = bodyToString(init.body);
            }

            const verdict = await askContentScript({ url, method, body, headers });
            if (verdict && verdict.allow === false) {
                const err = new Error('Blocked by VaultBix: outgoing request contained sensitive data.');
                err.name = 'VaultBixBlocked';
                throw err;
            }
        } catch (e) {
            if (e && e.name === 'VaultBixBlocked') throw e;
            // Any other error in our hook should not break the page
        }
        return originalFetch.apply(this, arguments);
    };

    // ─── XMLHttpRequest monkey-patch ───────────────────────────────────────
    const XHR = window.XMLHttpRequest;
    const originalOpen = XHR.prototype.open;
    const originalSend = XHR.prototype.send;
    const originalSetHeader = XHR.prototype.setRequestHeader;

    XHR.prototype.open = function (method, url) {
        try {
            this.__vbMethod = method;
            this.__vbUrl = url;
            this.__vbHeaders = {};
        } catch { /* ignore */ }
        return originalOpen.apply(this, arguments);
    };

    XHR.prototype.setRequestHeader = function (name, value) {
        try {
            this.__vbHeaders = this.__vbHeaders || {};
            this.__vbHeaders[name] = value;
        } catch { /* ignore */ }
        return originalSetHeader.apply(this, arguments);
    };

    XHR.prototype.send = function (body) {
        const xhr = this;
        try {
            const url = xhr.__vbUrl || '';
            const method = xhr.__vbMethod || 'GET';
            const headers = headersToString(xhr.__vbHeaders || {});
            const bodyStr = bodyToString(body);

            askContentScript({ url, method, body: bodyStr, headers }).then((verdict) => {
                if (verdict && verdict.allow === false) {
                    try { xhr.abort(); } catch { /* ignore */ }
                    try {
                        xhr.dispatchEvent(new Event('vaultbix-blocked'));
                    } catch { /* ignore */ }
                } else {
                    try { originalSend.call(xhr, body); } catch { /* ignore */ }
                }
            });
            return; // We send (or don't) inside the verdict callback
        } catch {
            return originalSend.apply(this, arguments);
        }
    };

    // ─── sendBeacon monkey-patch (best effort, async = no real block) ─────
    if (navigator.sendBeacon) {
        const originalBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function (url, data) {
            try {
                const body = bodyToString(data);
                askContentScript({ url, method: 'POST', body, headers: '' });
            } catch { /* ignore */ }
            return originalBeacon(url, data);
        };
    }
})();
