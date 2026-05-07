/**
 * VaultBix Content Script (v5)
 *
 * Responsibilities:
 *  1. Inject the page-world interceptor (content/inject.js) so window.fetch
 *     and XMLHttpRequest can be monkey-patched.
 *  2. Receive intercepted-request messages from the page world, run local
 *     detection, and reply with an allow/block verdict.
 *  3. Hook every <form> on the page so form-POST submissions are scanned
 *     before they leave the browser (MutationObserver picks up new forms).
 *  4. Show an in-page alert banner when a leak is blocked, with "Allow once"
 *     and "View details" actions.
 *  5. Log incidents to chrome.storage via the background service worker.
 *
 * This file is a CLASSIC content script (not an ES module). All detection
 * logic is bundled inline so there are no import paths to resolve.
 *
 * 100% local. No data leaves the browser.
 */

(() => {
    'use strict';

    if (window.__vaultbixContent) return;
    window.__vaultbixContent = true;

    // ====================================================================
    // CONFIG
    // ====================================================================
    const CONFIG = {
        MAX_SCAN_LENGTH: 50000,
        BANNER_AUTO_DISMISS_MS: 8000,
        ALLOW_ONCE_TTL_MS: 30000
    };

    // ====================================================================
    // DETECTION PATTERNS
    // ====================================================================
    // Each entry: { id, name, type, pattern, risk, validate? }
    // risk: CRITICAL | HIGH | MEDIUM | LOW
    //
    // CRITICAL is reserved for items where leakage means immediate financial,
    // identity-theft, or full-account-compromise impact: AWS keys, SSNs,
    // credit cards, private keys, and live API tokens for paid services
    // (OpenAI, Anthropic, Stripe, GitHub, etc.). In Balanced mode, only
    // CRITICAL findings actually block the request — everything else warns.
    const PATTERNS = [
        // ── API keys ───────────────────────────────────────────────────
        { id: 'openai_proj', name: 'OpenAI Project Key', type: 'API Key', pattern: /sk-proj-[A-Za-z0-9_-]{20,}/g, risk: 'CRITICAL' },
        { id: 'openai',      name: 'OpenAI API Key',     type: 'API Key', pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, risk: 'CRITICAL' },
        { id: 'openai_legacy', name: 'OpenAI API Key', type: 'API Key', pattern: /sk-[A-Za-z0-9]{32,}/g, risk: 'CRITICAL',
          validate: (v) => v.length >= 35 && !v.startsWith('sk-proj-') && !v.startsWith('sk-ant-') },
        { id: 'anthropic',   name: 'Anthropic API Key',  type: 'API Key', pattern: /sk-ant-[A-Za-z0-9_-]{40,}/g, risk: 'CRITICAL' },
        { id: 'aws_access',  name: 'AWS Access Key',     type: 'API Key', pattern: /AKIA[0-9A-Z]{16}/g, risk: 'CRITICAL' },
        { id: 'github_pat',  name: 'GitHub PAT',         type: 'API Key', pattern: /ghp_[A-Za-z0-9]{36}/g, risk: 'CRITICAL' },
        { id: 'github_oauth',name: 'GitHub OAuth',       type: 'API Key', pattern: /gho_[A-Za-z0-9]{36}/g, risk: 'CRITICAL' },
        { id: 'github_app',  name: 'GitHub App Token',   type: 'API Key', pattern: /(ghu|ghs|ghr)_[A-Za-z0-9]{36}/g, risk: 'HIGH' },
        { id: 'stripe_sk',   name: 'Stripe Secret Key',  type: 'API Key', pattern: /sk_live_[A-Za-z0-9]{24,}/g, risk: 'CRITICAL' },
        { id: 'stripe_sk_test', name: 'Stripe Test Key', type: 'API Key', pattern: /sk_test_[A-Za-z0-9]{24,}/g, risk: 'HIGH' },
        { id: 'stripe_rk',   name: 'Stripe Restricted',  type: 'API Key', pattern: /rk_(?:live|test)_[A-Za-z0-9]{24,}/g, risk: 'HIGH' },
        { id: 'stripe_pk',   name: 'Stripe Publishable', type: 'API Key', pattern: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g, risk: 'MEDIUM' },
        { id: 'google_api',  name: 'Google API Key',     type: 'API Key', pattern: /AIza[A-Za-z0-9_-]{35}/g, risk: 'HIGH' },
        { id: 'twilio_sid',  name: 'Twilio Account SID', type: 'API Key', pattern: /AC[a-f0-9]{32}/g, risk: 'HIGH' },
        { id: 'twilio_key',  name: 'Twilio API Key',     type: 'API Key', pattern: /SK[a-f0-9]{32}/g, risk: 'HIGH' },
        { id: 'slack_tok',   name: 'Slack Token',        type: 'API Key', pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g, risk: 'HIGH' },
        { id: 'sendgrid',    name: 'SendGrid Key',       type: 'API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, risk: 'HIGH' },
        { id: 'npm',         name: 'NPM Token',          type: 'API Key', pattern: /npm_[A-Za-z0-9]{36}/g, risk: 'HIGH' },

        // ── JWTs ───────────────────────────────────────────────────────
        { id: 'jwt',         name: 'JWT Token',          type: 'JWT',     pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, risk: 'HIGH' },

        // ── Private keys ───────────────────────────────────────────────
        { id: 'pem_priv',    name: 'Private Key (PEM)',  type: 'Private Key', pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/g, risk: 'CRITICAL' },

        // ── credentials embedded in URLs ───────────────────────────────
        { id: 'url_creds',   name: 'Credentials in URL', type: 'Credentials', pattern: /[a-z][a-z0-9+\-.]*:\/\/[^\s/:@]+:[^\s/:@]+@[^\s]+/gi, risk: 'HIGH' },

        // ── PII ────────────────────────────────────────────────────────
        { id: 'email',       name: 'Email Address',      type: 'PII', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b/g, risk: 'LOW' },
        { id: 'ssn',         name: 'US SSN',             type: 'PII', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, risk: 'CRITICAL',
          validate: (v) => {
              const [a, g, s] = v.split('-').map(Number);
              return a >= 1 && a <= 899 && a !== 666 && g >= 1 && g <= 99 && s >= 1 && s <= 9999;
          } },
        { id: 'cc_visa',     name: 'Credit Card',        type: 'PII', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, risk: 'CRITICAL', validate: luhnCheck },
        { id: 'cc_mc',       name: 'Credit Card',        type: 'PII', pattern: /\b5[1-5][0-9]{14}\b/g, risk: 'CRITICAL', validate: luhnCheck },
        { id: 'cc_amex',     name: 'Credit Card',        type: 'PII', pattern: /\b3[47][0-9]{13}\b/g, risk: 'CRITICAL', validate: luhnCheck },
        { id: 'cc_discover', name: 'Credit Card',        type: 'PII', pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/g, risk: 'CRITICAL', validate: luhnCheck }
    ];

    function luhnCheck(v) {
        const d = v.replace(/\D/g, '');
        if (d.length < 13 || d.length > 19) return false;
        let sum = 0, alt = false;
        for (let i = d.length - 1; i >= 0; i--) {
            let n = parseInt(d[i], 10);
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n; alt = !alt;
        }
        return sum % 10 === 0;
    }

    // ── Shannon entropy detector for high-entropy generic secrets ──────
    //
    // The entropy detector exists to catch obviously-secret-shaped tokens
    // that don't match a known vendor regex. It is *not* allowed to drive
    // a block on its own:
    //   * minimum length raised to 32 chars (was 20)
    //   * minimum entropy raised to 4.5 bits/char (was 4.0)
    //   * confidence is always "Low" — high confidence is only granted when
    //     a regex pattern *also* matches the same span
    //   * risk is always "LOW" so it can never satisfy a Critical-level
    //     blocking rule
    // Anything that slips past those bars produces a warning at most.
    const ENTROPY_MIN_BITS_PER_CHAR = 4.5;
    const ENTROPY_MIN_LENGTH = 32;

    function shannonEntropy(str) {
        if (!str) return 0;
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        let h = 0;
        const len = str.length;
        for (const c in freq) {
            const p = freq[c] / len;
            h -= p * Math.log2(p);
        }
        return h;
    }

    function detectHighEntropySecrets(text) {
        const findings = [];
        const tokenRe = new RegExp(`[A-Za-z0-9_\\-+/=]{${ENTROPY_MIN_LENGTH},}`, 'g');
        let m;
        while ((m = tokenRe.exec(text)) !== null) {
            const value = m[0];
            if (value.length > 200) continue; // skip giant blobs
            const hasUpper = /[A-Z]/.test(value);
            const hasLower = /[a-z]/.test(value);
            const hasDigit = /\d/.test(value);
            if (!(hasUpper && hasLower && hasDigit)) continue;
            // Pre-flight: skip obvious false positives like hex hashes,
            // CSS class blobs, base64 image fragments, etc.
            if (isWhitelistedToken(value)) continue;
            const ent = shannonEntropy(value);
            if (ent < ENTROPY_MIN_BITS_PER_CHAR) continue;
            findings.push({
                id: 'entropy',
                name: 'High-entropy Secret',
                type: 'Secret',
                // Entropy alone never produces HIGH or CRITICAL risk, so
                // the blocking rules below cannot fire on this kind of
                // finding. It will only ever surface as a Low-confidence
                // warning the user can ignore.
                risk: 'LOW',
                value,
                start: m.index,
                end: m.index + value.length,
                confidence: 'Low'
            });
        }
        return findings;
    }

    // ====================================================================
    // FALSE-POSITIVE WHITELIST
    // ====================================================================
    // Strings that match any of these checks are skipped before any
    // detection runs. The goal is to keep the noisy stuff (CSS hashes,
    // base64 images, content-hash filenames, color codes, hex digests)
    // from ever reaching the regex/entropy stages.

    // A token is a *single* candidate string we extracted from a body or
    // URL. Tokens shorter than this are never considered secrets — real
    // API keys are always at least 16 characters.
    const MIN_TOKEN_LENGTH = 16;

    // Quick check for "looks like just hex" — covers SHA-1/256/512 digests,
    // CSS hex colors (#ffffff), and content-hash filenames like
    // `app.f3a1b2c4.js`. We also accept dashes/underscores because Webpack
    // and friends like to throw those in.
    function isMostlyHex(s) {
        if (!s) return false;
        const stripped = s.replace(/[-_.]/g, '');
        if (stripped.length === 0) return false;
        const hexChars = stripped.match(/[0-9a-fA-F]/g);
        if (!hexChars) return false;
        return hexChars.length / stripped.length >= 0.95;
    }

    // Looks like a CSS hex color (#fff, #ffffff, #ffffffff)
    function isHexColor(s) {
        return /^#?[0-9a-fA-F]{3,8}$/.test(s);
    }

    // Looks like a content-hash filename: `main.4f3b2a1c.js`, `app.css?v=ab12cd34`
    function isContentHashFilename(s) {
        return /\.[A-Fa-f0-9]{6,}\.(js|css|mjs|map|woff2?|png|jpg|jpeg|gif|svg)(\?.*)?$/.test(s);
    }

    // Whitelist for an *individual* candidate token (entropy match, etc.)
    function isWhitelistedToken(value) {
        if (!value) return true;
        if (value.length < MIN_TOKEN_LENGTH) return true;
        if (isHexColor(value)) return true;
        if (isMostlyHex(value)) return true;
        if (isContentHashFilename(value)) return true;
        return false;
    }

    // Whitelist for a *whole haystack* — the URL+headers+body we are about
    // to scan. Returns true if we should skip detection entirely.
    function isWhitelistedHaystack(haystack, url) {
        if (!haystack) return true;

        // 1. Data URIs (especially base64 images)
        if (/^data:image\//i.test(haystack.trimStart())) return true;
        if (url && /^data:image\//i.test(url)) return true;

        // 2. URL hash fragment only (e.g. SPA navigation #/foo)
        if (url) {
            try {
                const u = new URL(url, location.href);
                // Pure hash navigation — no body, no query — almost never carries secrets
                if (u.hash && !u.search && !haystack.replace(url, '').trim()) return true;
                // Static asset loads (script src, stylesheet, font, image, etc.)
                if (/\.(js|mjs|css|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|webp|ico|map)(\?|$)/i.test(u.pathname)) {
                    return true;
                }
                // Content-hash filename pattern in the URL path
                if (isContentHashFilename(u.pathname)) return true;
            } catch { /* malformed URL — fall through */ }
        }

        // 3. CSS class / style attribute string (extension is most likely
        //    being asked to scan a serialized DOM fragment)
        if (/\bclass=["'][^"']{0,200}["']/.test(haystack) && haystack.length < 400) {
            // It's mostly markup attributes, no obvious payload
            return true;
        }
        if (/^style\s*=/.test(haystack.trim())) return true;

        return false;
    }

    // ====================================================================
    // QUICK CHECK + FULL DETECTION
    // ====================================================================
    const QUICK_CHECK = [
        /sk-/, /AKIA/, /ghp_/, /gho_/, /ghu_/, /ghs_/, /xox[baprs]-/,
        /-----BEGIN/, /eyJ[A-Za-z0-9]/, /AC[a-f0-9]{20}/, /SK[a-f0-9]{20}/,
        /AIza/, /SG\./, /\d{3}-\d{2}-\d{4}/, /:\/\/[^\s/:@]+:[^\s/:@]+@/
    ];

    function quickCheck(text) {
        if (!text || text.length < 10) return false;
        if (QUICK_CHECK.some((re) => re.test(text))) return true;
        // any token long enough to potentially be a secret
        return /[A-Za-z0-9_\-+/=]{20,}/.test(text);
    }

    function riskToConfidence(risk) {
        if (risk === 'CRITICAL' || risk === 'HIGH') return 'High';
        if (risk === 'MEDIUM') return 'Medium';
        return 'Low';
    }

    // Numeric ordering so we can compare risks easily.
    const RISK_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    function highestRiskOf(findings) {
        let top = null;
        let topRank = 0;
        for (const f of findings) {
            const r = RISK_RANK[f.risk] || 0;
            if (r > topRank) { topRank = r; top = f.risk; }
        }
        return top;
    }

    // ─────────────────────────────────────────────────────────────────
    // Prefix masking. Controls how much of a matched secret survives in
    // the dashboard preview as the "AKIA••••" / "sk-ant-••••" indicator.
    //
    // Two principles:
    //   1. Only ever expose the publicly-known type marker, never random
    //      entropy bytes. `sk-ant-` identifies a key TYPE (public info);
    //      4 chars of an AWS_SECRET would be 4 chars of recoverable entropy.
    //   2. Anything that has no public type marker — PII, raw entropy
    //      hits, embedded-credential matches — gets length 0. The whole
    //      value is sensitive there, so the preview shows only dots.
    //
    // Default for unmapped pattern ids is 4. Comment after each entry
    // shows the literal prefix so reviewers can see this stays harmless.
    const KNOWN_PREFIXES = {
        // ── identified API keys (public type markers) ──
        aws_access_key:         4,  // AKIA
        github_personal_token:  4,  // ghp_
        github_oauth_token:     4,  // gho_
        github_app_token:       4,  // ghu_
        github_server_token:    4,  // ghs_
        github_refresh_token:   4,  // ghr_
        gitlab_token:           6,  // glpat-
        openai_api_key:         3,  // sk-
        openai_project_key:     8,  // sk-proj-
        openai_key_new:         3,  // sk-
        anthropic_api_key:      7,  // sk-ant-
        slack_token:            5,  // xoxb- / xoxp- / xoxa- / xoxs-
        stripe_secret_key:      8,  // sk_live_ / sk_test_
        stripe_restricted_key:  8,  // rk_live_ / rk_test_
        stripe_publishable_key: 8,  // pk_live_ / pk_test_
        google_api_key:         4,  // AIza
        npm_token:              4,  // npm_
        pypi_token:             5,  // pypi-
        sendgrid_key:           3,  // SG.
        jwt:                    3,  // eyJ
        bearer_token:           7,  // "Bearer " (incl. trailing space)
        basic_auth:             6,  // "Basic "  (incl. trailing space)

        // ── SECURITY: length 0 — no prefix exposure ──
        // These pattern ids match values where the first characters are
        // genuinely identifying. Even 4 chars correlates dangerously with
        // timestamp + destination URL: first 4 of an SSN ("123-") leak the
        // area, first 4 of a credit card are the IIN (issuer), first chars
        // of an email reveal the user. Entropy hits are random secrets
        // with no public marker — first 4 chars are recoverable entropy.
        ssn:                    0,
        credit_card_visa:       0,
        credit_card_mastercard: 0,
        credit_card_amex:       0,
        credit_card_discover:   0,
        email:                  0,
        phone_us:               0,
        phone_intl:             0,
        ip_address:             0,
        entropy:                0   // unidentified high-entropy: value IS the secret
    };

    function getPrefix(patId, value) {
        if (!value) return '';
        const len = KNOWN_PREFIXES[patId] != null ? KNOWN_PREFIXES[patId] : 4;
        return value.slice(0, len);
    }

    async function sha256Hex(value) {
        if (!value) return '';
        const data = new TextEncoder().encode(value);
        const buf = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(buf))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Mutates findings in-place: replaces the private f._value with
    // f.hash. The raw secret never leaves the content script after this.
    async function attachHashesAndStripValues(findings) {
        for (const f of findings) {
            if (f._value != null) {
                f.hash = await sha256Hex(f._value);
                delete f._value;
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────────
    // Detection dedup. ChatGPT (and friends) fire many rapid requests
    // per user action — streaming chunks, autocomplete probes, telemetry.
    // Without dedup, one paste of a secret would trigger 100+ identical
    // banners and incident rows.
    //
    // Strategy: keep a small Map of recently-seen hashes with absolute
    // expiry timestamps. If any finding's hash is still in the map, skip
    // the banner and incident log (the verdict still applies). The map
    // is capped at DEDUP_MAX_ENTRIES; expired entries are pruned lazily
    // on each check rather than via setInterval.
    const DEDUP_COOLDOWN_MS = 10_000;
    const DEDUP_MAX_ENTRIES = 50;
    const recentHashes = new Map(); // hash -> expireAt timestamp (ms)

    function pruneExpiredHashes(now) {
        for (const [h, exp] of recentHashes) {
            if (exp <= now) recentHashes.delete(h);
        }
    }

    // Returns true if any of the given hashes is still in the cooldown
    // window (treat as a duplicate). Otherwise registers all hashes for
    // the cooldown window and returns false. Mutates recentHashes.
    function isDuplicateDetection(hashes) {
        if (!hashes || hashes.length === 0) return false;
        const now = Date.now();
        pruneExpiredHashes(now);
        for (const h of hashes) {
            if (recentHashes.has(h)) return true;
        }
        const expireAt = now + DEDUP_COOLDOWN_MS;
        for (const h of hashes) {
            recentHashes.set(h, expireAt);
        }
        // Cap. Drop earliest-expiring entries when over the size limit.
        if (recentHashes.size > DEDUP_MAX_ENTRIES) {
            const sorted = [...recentHashes.entries()].sort((a, b) => a[1] - b[1]);
            for (let i = 0; i < sorted.length - DEDUP_MAX_ENTRIES; i++) {
                recentHashes.delete(sorted[i][0]);
            }
        }
        return false;
    }

    /**
     * Run full detection on a string. Returns:
     *   { findings: Finding[], blocked: bool, topType: string }
     * Finding: { id, name, type, risk, confidence, prefix, length, _value, start, end }
     * `_value` is the raw matched secret. It MUST be hashed + stripped via
     * attachHashesAndStripValues() before the incident leaves this script.
     */
    function detect(text) {
        if (!text || typeof text !== 'string') return { findings: [], topType: null };
        const scanText = text.length > CONFIG.MAX_SCAN_LENGTH ? text.slice(0, CONFIG.MAX_SCAN_LENGTH) : text;

        const findings = [];
        const seenSpans = []; // [[start,end]]
        // Track regex-confirmed spans so an entropy hit landing on the
        // same range can be upgraded to High confidence (the only path
        // to High confidence — entropy alone never qualifies).
        const regexSpans = [];

        function spansOverlap(start, end) {
            for (const [s, e] of seenSpans) {
                if (start < e && end > s) return true;
            }
            return false;
        }

        function regexConfirms(start, end) {
            for (const [s, e] of regexSpans) {
                if (start < e && end > s) return true;
            }
            return false;
        }

        // Layer 1: regex patterns
        for (const pat of PATTERNS) {
            const re = new RegExp(pat.pattern.source, pat.pattern.flags.includes('g') ? pat.pattern.flags : pat.pattern.flags + 'g');
            let m;
            while ((m = re.exec(scanText)) !== null) {
                const value = m[0];
                if (pat.validate && !pat.validate(value)) continue;
                // Skip matches shorter than the minimum-token bar or that
                // look like CSS/hex noise. Vendor patterns already have
                // length floors above 16, but the whitelist is cheap.
                if (isWhitelistedToken(value)) continue;
                if (spansOverlap(m.index, m.index + value.length)) continue;
                seenSpans.push([m.index, m.index + value.length]);
                regexSpans.push([m.index, m.index + value.length]);
                findings.push({
                    id: pat.id,
                    name: pat.name,
                    type: pat.id,                       // was pat.type (always undefined); pat.id is the real identifier
                    risk: pat.risk,
                    confidence: riskToConfidence(pat.risk),
                    prefix: getPrefix(pat.id, value),   // public type marker only; '' for PII / entropy
                    length: value.length,
                    _value: value,                      // private — hashed and stripped before send
                    start: m.index,
                    end: m.index + value.length
                });
            }
        }

        // Layer 2: high-entropy secrets. We do not produce HIGH confidence
        // unless a regex pattern *also* covers the same span. Standalone
        // entropy hits are LOW/Low and warn-only.
        for (const f of detectHighEntropySecrets(scanText)) {
            if (spansOverlap(f.start, f.end)) continue;
            seenSpans.push([f.start, f.end]);
            const confirmed = regexConfirms(f.start, f.end);
            findings.push({
                id: f.id,
                name: f.name,
                type: f.type,
                risk: confirmed ? 'HIGH' : 'LOW',
                confidence: confirmed ? 'High' : 'Low',
                prefix: getPrefix(f.id, f.value),   // f.id === 'entropy' → '' (length-0 mapped)
                length: f.value.length,
                _value: f.value,
                start: f.start,
                end: f.end
            });
        }

        // Sort by position for stable display
        findings.sort((a, b) => a.start - b.start);

        // Determine "top" type for the banner headline (prefer the highest-risk match)
        let topType = null;
        if (findings.length > 0) {
            const ordered = [...findings].sort((a, b) => (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0));
            topType = ordered[0].type;
        }

        return { findings, topType };
    }

    // ====================================================================
    // SETTINGS & ALLOWLIST
    // ====================================================================
    const STORAGE_KEYS = {
        SETTINGS: 'vaultbix_settings_v5',
        ALLOWED_SITES: 'vaultbix_allowed_sites_v5'
    };

    let settings = {
        protectionEnabled: true,
        sensitivity: 'balanced', // strict | balanced | minimal
        // Until the user finishes the onboarding flow, the content script
        // operates in "warn-only" mode regardless of the stored sensitivity.
        firstRunCompleted: false
    };

    let allowedSites = {}; // { hostname: true }
    const allowOnceUntil = new Map(); // hostname -> expiry timestamp

    // ====================================================================
    // USER-INPUT TRACKING
    // ====================================================================
    // VaultBix only scans requests that plausibly carry user-typed data.
    // We listen for input/keydown/paste events on textareas, inputs, and
    // contenteditable elements, and consider the page "actively receiving
    // user input" for a short window after the most recent event. Any
    // request that fires outside that window is allowed through silently.
    //
    // This stops the extension from scanning every analytics ping, image
    // load, telemetry beacon, or framework background fetch — the source
    // of nearly all the false-positive blocks reported in v5.
    const USER_INPUT_WINDOW_MS = 10_000;
    let lastUserInputAt = 0;

    function isUserInputTarget(el) {
        if (!el || el.nodeType !== 1) return false;
        const tag = el.tagName;
        if (tag === 'TEXTAREA') return true;
        if (tag === 'INPUT') {
            const type = (el.type || '').toLowerCase();
            // Skip non-text inputs (radio, checkbox, file, button, etc.)
            const skip = new Set(['button', 'submit', 'reset', 'image', 'file', 'checkbox', 'radio', 'range', 'color']);
            return !skip.has(type);
        }
        if (el.isContentEditable) return true;
        return false;
    }

    function markUserInput(e) {
        try {
            if (isUserInputTarget(e.target)) {
                lastUserInputAt = Date.now();
            }
        } catch { /* ignore */ }
    }

    function hasRecentUserInput() {
        return Date.now() - lastUserInputAt < USER_INPUT_WINDOW_MS;
    }

    // Capture phase so framework stopPropagation calls can't hide events from us.
    document.addEventListener('input',   markUserInput, true);
    document.addEventListener('keydown', markUserInput, true);
    document.addEventListener('paste',   markUserInput, true);

    async function loadSettings() {
        try {
            const r = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, STORAGE_KEYS.ALLOWED_SITES]);
            if (r[STORAGE_KEYS.SETTINGS]) settings = { ...settings, ...r[STORAGE_KEYS.SETTINGS] };
            if (r[STORAGE_KEYS.ALLOWED_SITES]) allowedSites = r[STORAGE_KEYS.ALLOWED_SITES] || {};
        } catch { /* default settings remain */ }
    }

    function siteHostname() {
        try { return location.hostname; } catch { return ''; }
    }

    function isSiteAllowed() {
        const h = siteHostname();
        if (allowedSites[h]) return true;
        const until = allowOnceUntil.get(h);
        if (until && Date.now() < until) return true;
        return false;
    }

    /**
     * Decide whether to block a finding-bearing request given the user's
     * current sensitivity tier.
     *
     *   - first-run not done → warn-only (never block)
     *   - protection paused  → warn-only (never block)
     *   - strict             → block any detection
     *   - balanced           → block CRITICAL only, warn for the rest
     *   - minimal            → never block (warns are also gated to CRITICAL,
     *                          see filterForMinimal below)
     */
    function shouldBlockForRisk(risk) {
        if (!settings.protectionEnabled) return false;
        if (!settings.firstRunCompleted) return false;
        if (settings.sensitivity === 'strict') return true;
        if (settings.sensitivity === 'balanced') return risk === 'CRITICAL';
        return false; // minimal — never block
    }

    /**
     * In Minimal mode the user has explicitly asked to ignore everything
     * that isn't a Critical leak. Drop non-critical findings entirely so
     * we neither warn nor log them.
     */
    function filterForMinimal(findings) {
        if (settings.sensitivity !== 'minimal') return findings;
        return findings.filter((f) => f.risk === 'CRITICAL');
    }

    // ====================================================================
    // PAGE-WORLD INTERCEPTOR
    // ----
    // The interceptor (content/inject.js) is registered as a separate
    // content script with `world: "MAIN"`, so Chrome runs it directly in
    // the page context at document_start. Nothing to inject here.
    // ====================================================================

    // ====================================================================
    // MESSAGE BRIDGE: page world ↔ content script
    // ====================================================================
    function postVerdict(id, allow) {
        window.postMessage({
            source: 'vaultbix-cs',
            kind: 'verdict',
            id,
            allow
        }, '*');
    }

    function destinationFromUrl(url) {
        try {
            const u = new URL(url, location.href);
            return u.hostname || url;
        } catch {
            return url || 'unknown';
        }
    }

    function fullDestination(url) {
        try {
            const u = new URL(url, location.href);
            return u.origin + u.pathname;
        } catch {
            return url || 'unknown';
        }
    }

    async function handlePageRequest(payload) {
        const { id, url, method, body, headers } = payload;

        if (!settings.protectionEnabled || isSiteAllowed()) {
            postVerdict(id, true);
            return;
        }

        // ── Scope filter #1: only inspect requests that plausibly carry
        //    something the user typed. Background telemetry, framework
        //    fetches, image loads, etc. all sail through silently.
        if (!hasRecentUserInput()) {
            postVerdict(id, true);
            return;
        }

        // ── Scope filter #2: pre-flight whitelist (data: URIs, static
        //    asset loads, content-hash filenames, CSS-only payloads).
        if (isWhitelistedHaystack([url || '', headers || '', body || ''].join('\n'), url)) {
            postVerdict(id, true);
            return;
        }

        // Combine all parts of the request that could carry secrets
        const haystack = [url || '', headers || '', body || ''].join('\n');
        if (!quickCheck(haystack)) {
            postVerdict(id, true);
            return;
        }

        let { findings, topType } = detect(haystack);
        // Minimal mode: drop everything that isn't Critical so it never
        // even surfaces a warning.
        findings = filterForMinimal(findings);
        if (findings.length === 0) {
            postVerdict(id, true);
            return;
        }
        // Recompute topType after the minimal-mode filter.
        if (findings.length > 0) {
            const ordered = [...findings].sort((a, b) => (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0));
            topType = ordered[0].type;
        }

        const highestRisk = highestRiskOf(findings) || 'LOW';

        const block = shouldBlockForRisk(highestRisk);
        const destinationHost = destinationFromUrl(url);
        const destinationFull = fullDestination(url);

        const incident = {
            id: 'inc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            timestamp: Date.now(),
            destination: destinationHost,
            destinationFull,
            method: method || 'GET',
            findings,
            topType,
            risk: highestRisk,
            blocked: block,
            siteOrigin: siteHostname()
        };

        // Issue the verdict synchronously to release the intercepted
        // request promptly — hashing, dedup, logging and banner all
        // happen in the async tail below. The verdict applies whether
        // or not this is a duplicate (we still block the network call
        // if `block` is true), but the UI and incident log are skipped
        // when the same hash was seen within the cooldown window.
        postVerdict(id, !block);

        try {
            await attachHashesAndStripValues(incident.findings);
            const hashes = incident.findings.map((f) => f.hash).filter(Boolean);
            if (isDuplicateDetection(hashes)) return;
            sendToBackground({ action: 'log_incident', incident }).catch(() => {});
            showAlertBanner(incident);
        } catch { /* never break the verdict path */ }
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.source !== 'vaultbix-page' || data.kind !== 'request') return;
        handlePageRequest(data);
    });

    // ====================================================================
    // FORM SUBMISSION FALLBACK (catches synchronous form POSTs)
    // ====================================================================
    function extractFormData(form) {
        try {
            const fd = new FormData(form);
            const parts = [];
            for (const [k, v] of fd.entries()) {
                parts.push(`${k}=${typeof v === 'string' ? v : '[file]'}`);
            }
            return parts.join('\n');
        } catch { return ''; }
    }

    async function handleFormSubmit(e) {
        try {
            const form = e.target;
            if (!form || form.tagName !== 'FORM') return;
            if (!settings.protectionEnabled || isSiteAllowed()) return;

            // A form submission is itself an explicit user action, so we
            // count it as user input even if no key has been pressed in
            // the last few seconds.
            lastUserInputAt = Date.now();

            const action = form.action || location.href;
            const method = (form.method || 'GET').toUpperCase();
            const body = extractFormData(form);
            if (isWhitelistedHaystack(body, action)) return;
            if (!quickCheck(body)) return;

            let { findings, topType } = detect(body);
            findings = filterForMinimal(findings);
            if (findings.length === 0) return;
            if (findings.length > 0) {
                const ordered = [...findings].sort((a, b) => (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0));
                topType = ordered[0].type;
            }

            const highestRisk = highestRiskOf(findings) || 'LOW';
            const block = shouldBlockForRisk(highestRisk);

            // Cancel the form submit synchronously — must happen before
            // any await or the form has already been allowed to propagate.
            if (block) {
                e.preventDefault();
                e.stopImmediatePropagation();
            }

            const incident = {
                id: 'inc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
                timestamp: Date.now(),
                destination: destinationFromUrl(action),
                destinationFull: fullDestination(action),
                method,
                findings,
                topType,
                risk: highestRisk,
                blocked: block,
                siteOrigin: siteHostname()
            };

            // Async tail: hash → dedup-check → log + banner if first time.
            // Duplicates within the cooldown window are still blocked above
            // but skip the banner and incident log.
            await attachHashesAndStripValues(incident.findings);
            const hashes = incident.findings.map((f) => f.hash).filter(Boolean);
            if (isDuplicateDetection(hashes)) return;
            sendToBackground({ action: 'log_incident', incident }).catch(() => {});
            showAlertBanner(incident);
        } catch { /* never break the host page */ }
    }

    // Capture-phase listener so we run before the form's own handlers
    document.addEventListener('submit', handleFormSubmit, true);

    // ====================================================================
    // BACKGROUND BRIDGE
    // ====================================================================
    async function sendToBackground(message) {
        try { return await chrome.runtime.sendMessage(message); }
        catch { return null; }
    }

    // Listen for setting changes from popup so behavior updates live
    try {
        chrome.runtime.onMessage.addListener((message) => {
            if (!message) return;
            if (message.action === 'settings_updated') {
                if (message.settings) settings = { ...settings, ...message.settings };
                if (message.allowedSites) allowedSites = message.allowedSites || {};
            }
        });
    } catch { /* ignore */ }

    // ====================================================================
    // IN-PAGE ALERT BANNER
    // ====================================================================
    let activeBanner = null;
    let bannerTimer = null;

    function ensureBannerStyles() {
        if (document.getElementById('vaultbix-banner-styles')) return;
        const style = document.createElement('style');
        style.id = 'vaultbix-banner-styles';
        style.textContent = `
        .vb-banner-host { position: fixed; top: 16px; left: 0; right: 0; z-index: 2147483647;
            display: flex; justify-content: center; pointer-events: none;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, system-ui, sans-serif; }
        .vb-banner { pointer-events: auto; min-width: 360px; max-width: 520px;
            background: #13131a; color: #f4f4f7;
            border: 1px solid #26262f; border-left: 4px solid #FF6B1A;
            border-radius: 12px; box-shadow: 0 8px 28px rgba(0,0,0,0.55);
            padding: 14px 16px; display: flex; gap: 12px; align-items: flex-start;
            transform: translateY(-12px); opacity: 0;
            transition: transform 180ms cubic-bezier(0.16, 1, 0.3, 1),
                        opacity 180ms cubic-bezier(0.16, 1, 0.3, 1); }
        .vb-banner--blocked { border-left-color: #ef4444; }
        .vb-banner--blocked .vb-banner__icon { color: #ef4444; }
        .vb-banner--warn { border-left-color: #FF6B1A; }
        .vb-banner--warn .vb-banner__icon { color: #FF6B1A; }
        .vb-banner.vb-show { transform: translateY(0); opacity: 1; }
        .vb-banner__icon { flex-shrink: 0; width: 24px; height: 24px; color: #FF6B1A; margin-top: 1px; }
        .vb-banner__body { flex: 1; min-width: 0; }
        .vb-banner__title { font-size: 14px; font-weight: 600; line-height: 1.35; color: #f4f4f7; }
        .vb-banner__sub { font-size: 12px; color: #9696a8; margin-top: 4px; line-height: 1.4;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .vb-banner__actions { display: flex; gap: 8px; margin-top: 12px; }
        .vb-btn { font: inherit; font-size: 12px; font-weight: 600; line-height: 1;
            padding: 8px 12px; border-radius: 6px; cursor: pointer;
            border: 1px solid transparent;
            transition: background 150ms cubic-bezier(0.16, 1, 0.3, 1),
                        border-color 150ms cubic-bezier(0.16, 1, 0.3, 1); }
        .vb-btn--ghost { background: transparent; color: #f4f4f7; border-color: #34343f; }
        .vb-btn--ghost:hover { background: #1f1f29; border-color: #3f3f4d; }
        .vb-btn--primary { background: #FF6B1A; color: #0a0a0d; border-color: #FF6B1A; }
        .vb-btn--primary:hover { background: #ff8a45; border-color: #ff8a45; }
        .vb-banner__close { background: none; border: none; cursor: pointer; color: #61616f;
            padding: 0 4px; font-size: 20px; line-height: 1; }
        .vb-banner__close:hover { color: #f4f4f7; }
        `;
        try { (document.head || document.documentElement).appendChild(style); } catch { /* ignore */ }
    }

    function buildBannerNode(incident) {
        const host = document.createElement('div');
        host.className = 'vb-banner-host';

        const banner = document.createElement('div');
        banner.className = 'vb-banner' + (incident.blocked ? ' vb-banner--blocked' : ' vb-banner--warn');
        banner.setAttribute('role', 'alert');

        const findingNames = [...new Set(incident.findings.map((f) => f.type))];
        const verb = incident.blocked ? 'blocked' : 'detected';
        const headline = `VaultBix ${verb} a potential ${incident.topType || 'data'} leak to ${incident.destination}`;
        const sub = `${incident.findings.length} item${incident.findings.length === 1 ? '' : 's'} detected — ${findingNames.join(', ')}`;

        // Build via DOM, no innerHTML, to keep CSP-safe and avoid XSS
        const iconNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(iconNS, 'svg');
        svg.setAttribute('class', 'vb-banner__icon');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '2');
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        const path1 = document.createElementNS(iconNS, 'path');
        path1.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
        const line1 = document.createElementNS(iconNS, 'line');
        line1.setAttribute('x1', '12'); line1.setAttribute('y1', '8');
        line1.setAttribute('x2', '12'); line1.setAttribute('y2', '13');
        const line2 = document.createElementNS(iconNS, 'line');
        line2.setAttribute('x1', '12'); line2.setAttribute('y1', '16');
        line2.setAttribute('x2', '12.01'); line2.setAttribute('y2', '16');
        svg.appendChild(path1); svg.appendChild(line1); svg.appendChild(line2);
        banner.appendChild(svg);

        const body = document.createElement('div');
        body.className = 'vb-banner__body';
        const title = document.createElement('div');
        title.className = 'vb-banner__title';
        title.textContent = headline;
        const subEl = document.createElement('div');
        subEl.className = 'vb-banner__sub';
        subEl.textContent = sub;
        body.appendChild(title); body.appendChild(subEl);

        const actions = document.createElement('div');
        actions.className = 'vb-banner__actions';

        const allowBtn = document.createElement('button');
        allowBtn.className = 'vb-btn vb-btn--ghost';
        allowBtn.textContent = 'Allow once';
        allowBtn.addEventListener('click', () => {
            allowOnceUntil.set(siteHostname(), Date.now() + CONFIG.ALLOW_ONCE_TTL_MS);
            sendToBackground({ action: 'mark_allowed_once', incidentId: incident.id }).catch(() => {});
            dismissBanner();
            // Show toast that allow-once was granted
            showToast('Allow once granted — will expire in 30s', 'amber');
        });

        const detailsBtn = document.createElement('button');
        detailsBtn.className = 'vb-btn vb-btn--primary';
        detailsBtn.textContent = 'View details';
        detailsBtn.addEventListener('click', () => {
            sendToBackground({ action: 'open_dashboard' }).catch(() => {});
            dismissBanner();
        });

        actions.appendChild(allowBtn);
        actions.appendChild(detailsBtn);
        body.appendChild(actions);

        banner.appendChild(body);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'vb-banner__close';
        closeBtn.setAttribute('aria-label', 'Dismiss');
        closeBtn.textContent = '×';
        closeBtn.addEventListener('click', dismissBanner);
        banner.appendChild(closeBtn);

        host.appendChild(banner);
        return { host, banner };
    }

    function dismissBanner() {
        if (!activeBanner) return;
        try {
            activeBanner.banner.classList.remove('vb-show');
            const node = activeBanner.host;
            setTimeout(() => { try { node.remove(); } catch {} }, 200);
        } catch { /* ignore */ }
        activeBanner = null;
        if (bannerTimer) { clearTimeout(bannerTimer); bannerTimer = null; }
    }

    function showAlertBanner(incident) {
        try {
            ensureBannerStyles();
            if (activeBanner) dismissBanner();
            const { host, banner } = buildBannerNode(incident);
            (document.body || document.documentElement).appendChild(host);
            requestAnimationFrame(() => banner.classList.add('vb-show'));
            activeBanner = { host, banner };
            if (bannerTimer) clearTimeout(bannerTimer);
            bannerTimer = setTimeout(dismissBanner, CONFIG.BANNER_AUTO_DISMISS_MS);
        } catch (e) {
            console.warn('[VaultBix] banner error', e);
        }
    }

    // ── lightweight toast for "allow once" feedback ─────────────────────
    function showToast(text, kind) {
        try {
            ensureBannerStyles();
            const t = document.createElement('div');
            t.style.cssText = `
                position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%);
                background: #1a1a24; color: #ffffff;
                padding: 10px 16px; border-radius: 8px;
                font: 13px -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                z-index: 2147483647; opacity: 0; transition: opacity 150ms ease-out;`;
            if (kind === 'red') t.style.background = '#E24B4A';
            else if (kind === 'amber') t.style.background = '#d97706';
            else if (kind === 'violet') t.style.background = '#5B4FCF';
            t.textContent = text;
            document.body.appendChild(t);
            requestAnimationFrame(() => { t.style.opacity = '1'; });
            setTimeout(() => {
                t.style.opacity = '0';
                setTimeout(() => { try { t.remove(); } catch {} }, 200);
            }, 3000);
        } catch { /* ignore */ }
    }

    // ====================================================================
    // BOOTSTRAP
    // ====================================================================
    (async function init() {
        await loadSettings();
        // Page-world interceptor and submit/message listeners are already attached.
    })();
})();
