/**
 * VaultBix Main Content Script
 * Detects sensitive data in AI chat inputs and provides warnings/blocking.
 *
 * Detection is handled by the unified detector (regex + ML + contextual).
 * This file owns adapters, UI, and event wiring only.
 *
 * PRIVACY:
 * - All scanning happens locally in this content script + a Web Worker.
 * - No data is ever sent to any server for detection purposes.
 *
 * @file content/main.js
 * @version 5.0.0
 */

import { quickCheck, detectSensitiveData, redactText, RISK_LEVELS } from './detection/detector.js';

(function () {
    'use strict';

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    const CONFIG = {
        INPUT_DEBOUNCE: 300,
        MUTATION_DEBOUNCE: 150,
        MIN_TEXT_LENGTH: 8,
        MAX_SCAN_LENGTH: 50000,
        ELEMENT_POLL_INTERVAL: 500,
        ELEMENT_MAX_RETRIES: 30,
        TOAST_DURATION: 4000,
        TOAST_DURATION_FREE: 5000,
        MODAL_ANIMATION_MS: 200,
        ENABLE_PASTE_WARNINGS: true,
        FEATURE_CHECK_INTERVAL: 60000
    };

    // ========================================================================
    // FEATURE STATE
    // ========================================================================

    let featureState = {
        tier: 'free',
        isPro: false,
        blockingEnabled: false,
        redactionEnabled: false,
        warningsEnabled: true,
        lastChecked: 0
    };

    let customRules = [];

    async function checkFeatures() {
        try {
            const response = await sendToBackground({ action: 'check_features' });
            if (response?.success) {
                featureState = {
                    tier: response.tier || 'free',
                    isPro: response.isPro === true,
                    blockingEnabled: response.blockingEnabled === true,
                    redactionEnabled: response.redactionEnabled === true,
                    warningsEnabled: response.warningsEnabled !== false,
                    lastChecked: Date.now()
                };
            }
        } catch {
            featureState.lastChecked = Date.now();
        }
        return featureState;
    }

    async function loadCustomRules() {
        try {
            const response = await sendToBackground({ action: 'get_custom_rules' });
            if (response?.success && Array.isArray(response.rules)) {
                customRules = response.rules.filter(r => r.enabled);
            }
        } catch {
            customRules = [];
        }
    }

    async function ensureFeatureState() {
        if (Date.now() - featureState.lastChecked > CONFIG.FEATURE_CHECK_INTERVAL) {
            await checkFeatures();
        }
        return featureState;
    }

    // ========================================================================
    // SITE ADAPTERS
    // ========================================================================

    const ADAPTERS = {
        chatgpt: {
            name: 'ChatGPT',
            match: /^https:\/\/(chat\.openai\.com|chatgpt\.com)/,
            getInput: () => document.querySelector(
                '#prompt-textarea, textarea[data-id="root"], div[contenteditable="true"][class*="ProseMirror"], div.ProseMirror[contenteditable="true"]'
            ),
            getSubmit: () => document.querySelector(
                'button[data-testid="send-button"], button[data-testid="fruitjuice-send-button"], button[aria-label*="Send"]'
            ),
            getForm: () => document.querySelector('form'),
            inputSelector: '#prompt-textarea, div[contenteditable="true"]'
        },
        claude: {
            name: 'Claude',
            match: /^https:\/\/claude\.ai/,
            getInput: () => document.querySelector(
                'div.ProseMirror[contenteditable="true"], div[contenteditable="true"][data-placeholder], fieldset div[contenteditable="true"]'
            ),
            getSubmit: () => document.querySelector(
                'button[aria-label="Send Message"], button[aria-label*="Send"], fieldset button[type="button"]'
            ),
            getForm: () => document.querySelector('form, fieldset'),
            inputSelector: 'div.ProseMirror, div[contenteditable="true"]'
        },
        gemini: {
            name: 'Gemini',
            match: /^https:\/\/gemini\.google\.com/,
            getInput: () => {
                const selectors = [
                    'rich-textarea div[contenteditable="true"]',
                    'div.ql-editor[contenteditable="true"]',
                    'div[contenteditable="true"][aria-label*="prompt" i]',
                    'div[contenteditable="true"][data-placeholder]',
                    'div[contenteditable="true"].text-input',
                    'p[data-placeholder][contenteditable="true"]',
                    '.input-area div[contenteditable="true"]',
                    'textarea[aria-label*="prompt" i]',
                    'textarea'
                ];
                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el) return el;
                }
                try {
                    const inputArea = document.querySelector('.input-area, [class*="input"], [class*="prompt"]');
                    if (inputArea) {
                        const editable = inputArea.querySelector('[contenteditable="true"]');
                        if (editable) return editable;
                    }
                } catch { /* ignore */ }
                return document.querySelector('[contenteditable="true"]');
            },
            getSubmit: () => document.querySelector(
                'button[aria-label*="Send" i], button[aria-label*="Submit" i], button.send-button, button[data-test-id="send-button"]'
            ),
            getForm: () => document.querySelector('form, .input-area-container, [class*="input-area"]'),
            inputSelector: 'rich-textarea, div[contenteditable="true"], textarea, p[contenteditable="true"]'
        },
        copilot: {
            name: 'Microsoft Copilot',
            match: /^https:\/\/(copilot\.microsoft\.com|www\.bing\.com\/(chat|search))/,
            getInput: () => document.querySelector(
                'textarea[name="q"], #searchbox, textarea[placeholder*="message" i], .cib-serp-main textarea'
            ),
            getSubmit: () => document.querySelector(
                'button[aria-label*="Submit"], button[type="submit"], #sb_form_go'
            ),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, #searchbox'
        },
        github_copilot: {
            name: 'GitHub Copilot',
            match: /^https:\/\/github\.com/,
            getInput: () => document.querySelector(
                'textarea.js-comment-field, textarea[name="issue[body]"], textarea[name="pull_request[body]"], .comment-form-textarea'
            ),
            getSubmit: () => document.querySelector(
                'button[type="submit"]:not([disabled]), .btn-primary[type="submit"]'
            ),
            getForm: () => document.querySelector('form.js-new-comment-form, form.new_issue'),
            inputSelector: 'textarea.js-comment-field, .comment-form-textarea'
        },
        poe: {
            name: 'Poe',
            match: /^https:\/\/poe\.com/,
            getInput: () => document.querySelector('textarea[class*="TextArea"], div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[class*="SendButton"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        perplexity: {
            name: 'Perplexity',
            match: /^https:\/\/(www\.)?perplexity\.ai/,
            getInput: () => document.querySelector('textarea[placeholder*="Ask"], div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[aria-label*="Submit"], button[type="submit"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        you: {
            name: 'You.com',
            match: /^https:\/\/you\.com/,
            getInput: () => document.querySelector('textarea, input[type="text"]'),
            getSubmit: () => document.querySelector('button[type="submit"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, input[type="text"]'
        },
        deepseek: {
            name: 'DeepSeek',
            match: /^https:\/\/chat\.deepseek\.com/,
            getInput: () => document.querySelector('textarea, div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[aria-label*="Send" i], button[class*="send" i], button[type="submit"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        grok: {
            name: 'Grok',
            match: /^https:\/\/grok\.x\.ai/,
            getInput: () => document.querySelector('textarea, div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[aria-label*="Send" i], button[type="submit"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        huggingchat: {
            name: 'HuggingChat',
            match: /^https:\/\/huggingface\.co\/chat/,
            getInput: () => document.querySelector('textarea, div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[type="submit"], button[aria-label*="Send" i]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        mistral: {
            name: 'Mistral Le Chat',
            match: /^https:\/\/chat\.mistral\.ai/,
            getInput: () => document.querySelector('textarea, div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[type="submit"], button[aria-label*="Send" i]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        google_ai_studio: {
            name: 'Google AI Studio',
            match: /^https:\/\/labs\.google/,
            getInput: () => document.querySelector('textarea, div[contenteditable="true"]'),
            getSubmit: () => document.querySelector('button[aria-label*="Run" i], button[aria-label*="Send" i], button[type="submit"]'),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        },
        generic: {
            name: 'AI Site',
            match: /.*/,
            getInput: () => {
                const selectors = [
                    'textarea[placeholder*="message" i]',
                    'textarea[placeholder*="chat" i]',
                    'textarea[placeholder*="ask" i]',
                    'div[contenteditable="true"][role="textbox"]',
                    'div.ProseMirror[contenteditable="true"]',
                    'div[contenteditable="true"]',
                    'textarea:not([readonly])'
                ];
                for (const sel of selectors) {
                    try {
                        const el = document.querySelector(sel);
                        if (el) return el;
                    } catch { /* ignore */ }
                }
                return null;
            },
            getSubmit: () => document.querySelector(
                'button[type="submit"], button[aria-label*="send" i], button[aria-label*="submit" i]'
            ),
            getForm: () => document.querySelector('form'),
            inputSelector: 'textarea, div[contenteditable="true"]'
        }
    };

    // ========================================================================
    // STATE
    // ========================================================================

    let state = {
        adapter: null,
        isInitialized: false,
        isProcessing: false,
        modalOpen: false,
        lastScanResult: null,
        observedInputs: new WeakSet(),
        mutationObserver: null,
        initRetryCount: 0
    };

    let toastContainer = null;
    let modalOverlay = null;

    // ========================================================================
    // UTILITIES
    // ========================================================================

    function escapeHtml(text) {
        if (!text) return '';
        try {
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        } catch { return ''; }
    }

    function debounce(fn, delay) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function sendToBackground(message) {
        try {
            return await chrome.runtime.sendMessage(message);
        } catch {
            return null;
        }
    }

    // ========================================================================
    // DETECTION BRIDGE
    // ========================================================================

    /**
     * Run the unified detector on the given text, then also run any
     * user-defined custom rules (loaded from storage).
     */
    async function analyzeText(text) {
        const result = await detectSensitiveData(text, CONFIG.MAX_SCAN_LENGTH);

        // Also run custom rules (user-defined patterns stored via the extension)
        if (customRules.length > 0) {
            const scanText = text.length > CONFIG.MAX_SCAN_LENGTH ? text.substring(0, CONFIG.MAX_SCAN_LENGTH) : text;
            const seenCustom = new Set();

            for (const rule of customRules) {
                try {
                    const regex = new RegExp(rule.pattern, 'gi');
                    let match;
                    while ((match = regex.exec(scanText)) !== null) {
                        const value = match[0];
                        if (seenCustom.has(value)) continue;
                        seenCustom.add(value);
                        result.findings.push({
                            source: 'custom',
                            type: 'CUSTOM_' + rule.id,
                            id: 'custom_' + rule.id,
                            name: rule.name || 'Custom Rule',
                            risk: rule.risk || 'HIGH',
                            text: value,
                            redacted: `[${rule.name || 'REDACTED'}]`,
                            start: match.index,
                            end: match.index + value.length,
                            isCustom: true
                        });
                    }
                } catch { /* invalid regex in custom rule */ }
            }

            // Re-sort after adding custom findings
            result.findings.sort((a, b) => a.start - b.start);

            // Recompute risk & summary
            if (result.findings.length > 0) {
                const risks = result.findings.map(f => f.risk);
                if (risks.includes('CRITICAL')) result.overallRisk = 'CRITICAL';
                else if (risks.includes('HIGH')) result.overallRisk = 'HIGH';
                else if (risks.includes('MEDIUM')) result.overallRisk = 'MEDIUM';
                else result.overallRisk = 'LOW';

                const types = [...new Set(result.findings.map(f => f.name))];
                const typeStr = types.length <= 3
                    ? types.join(', ')
                    : `${types.slice(0, 2).join(', ')} (+${types.length - 2} more)`;
                result.summary = {
                    total: result.findings.length,
                    types,
                    message: `${result.findings.length} sensitive item${result.findings.length > 1 ? 's' : ''} detected: ${typeStr}`
                };
            }
        }

        return result;
    }

    // ========================================================================
    // UI COMPONENTS
    // ========================================================================

    function getToastContainer() {
        if (toastContainer && document.body && document.body.contains(toastContainer)) {
            return toastContainer;
        }
        toastContainer = document.createElement('div');
        toastContainer.className = 'vb-toast-container';
        toastContainer.setAttribute('role', 'alert');
        toastContainer.setAttribute('aria-live', 'polite');
        injectStyles();
        if (document.body) document.body.appendChild(toastContainer);
        return toastContainer;
    }

    function injectStyles() {
        if (document.getElementById('vaultbix-styles')) return;
        const style = document.createElement('style');
        style.id = 'vaultbix-styles';
        style.textContent = `
            .vb-toast-container {
                position: fixed;
                bottom: 24px;
                right: 24px;
                display: flex;
                flex-direction: column;
                gap: 12px;
                z-index: 2147483647;
                pointer-events: none;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            }
            .vb-toast {
                display: flex;
                align-items: flex-start;
                gap: 12px;
                min-width: 320px;
                max-width: 420px;
                padding: 14px 18px;
                background: #16181d;
                border: 1px solid #2a2d35;
                border-radius: 10px;
                box-shadow: 0 4px 24px rgba(0,0,0,0.4);
                color: #f4f5f6;
                font-size: 14px;
                transform: translateX(120%);
                opacity: 0;
                transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
                pointer-events: auto;
            }
            .vb-toast.vb-toast-show { transform: translateX(0); opacity: 1; }
            .vb-toast-danger { border-left: 3px solid #f04438; }
            .vb-toast-warning { border-left: 3px solid #f79009; }
            .vb-toast-success { border-left: 3px solid #12b76a; }
            .vb-toast-info { border-left: 3px solid #00e5bf; }
            .vb-toast-content { flex: 1; }
            .vb-toast-title { font-weight: 600; margin-bottom: 2px; }
            .vb-toast-message { color: #a1a7b3; font-size: 13px; }
            .vb-toast-close {
                background: none; border: none; color: #6b7280;
                cursor: pointer; font-size: 18px; padding: 0; line-height: 1;
            }
            .vb-toast-close:hover { color: #f4f5f6; }
            .vb-modal-overlay {
                position: fixed; inset: 0;
                background: rgba(0,0,0,0.75);
                backdrop-filter: blur(4px);
                display: flex; align-items: flex-end; justify-content: center;
                z-index: 2147483647;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                opacity: 0; transition: opacity 0.2s ease;
            }
            .vb-modal-overlay.vb-modal-show { opacity: 1; }
            .vb-modal {
                width: 100%; max-width: 520px;
                background: #16181d; border-radius: 16px 16px 0 0;
                box-shadow: 0 -8px 48px rgba(0,0,0,0.5);
                overflow: hidden; transform: translateY(100%);
                transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            }
            .vb-modal-overlay.vb-modal-show .vb-modal { transform: translateY(0); }
            .vb-modal-header {
                display: flex; align-items: center; justify-content: space-between;
                padding: 20px 24px; border-bottom: 1px solid #2a2d35;
            }
            .vb-modal-title {
                display: flex; align-items: center; gap: 12px;
                font-size: 18px; font-weight: 600; color: #f4f5f6;
            }
            .vb-risk-badge {
                padding: 4px 10px; border-radius: 12px;
                font-size: 11px; font-weight: 600; text-transform: uppercase;
            }
            .vb-risk-critical { background: rgba(220,38,38,0.15); color: #dc2626; }
            .vb-risk-high { background: rgba(240,68,56,0.15); color: #f04438; }
            .vb-risk-medium { background: rgba(247,144,9,0.15); color: #f79009; }
            .vb-risk-low { background: rgba(18,183,106,0.15); color: #12b76a; }
            .vb-modal-body { padding: 24px; }
            .vb-modal-desc { color: #a1a7b3; font-size: 14px; margin: 0 0 16px; }
            .vb-findings-list {
                background: #0d0f12; border: 1px solid #2a2d35;
                border-radius: 8px; max-height: 200px; overflow-y: auto;
            }
            .vb-finding-item {
                display: flex; align-items: center; justify-content: space-between;
                padding: 12px 16px; border-bottom: 1px solid #2a2d35;
            }
            .vb-finding-item:last-child { border-bottom: none; }
            .vb-finding-label { font-size: 13px; font-weight: 600; color: #f4f5f6; }
            .vb-finding-value {
                font-family: 'JetBrains Mono', monospace; font-size: 12px;
                padding: 4px 8px; background: rgba(240,68,56,0.1);
                border-radius: 4px; color: #f04438;
            }
            .vb-finding-source {
                font-size: 10px; padding: 2px 6px; border-radius: 4px;
                text-transform: uppercase; font-weight: 600; margin-left: 8px;
            }
            .vb-finding-source-ml { background: rgba(99,102,241,0.15); color: #6366f1; }
            .vb-finding-source-regex { background: rgba(0,229,191,0.15); color: #00e5bf; }
            .vb-finding-source-contextual { background: rgba(247,144,9,0.15); color: #f79009; }
            .vb-privacy-notice {
                display: flex; align-items: flex-start; gap: 12px;
                padding: 14px 16px; background: rgba(0,229,191,0.08);
                border: 1px solid rgba(0,229,191,0.2); border-radius: 8px; margin-top: 16px;
            }
            .vb-privacy-notice svg { flex-shrink: 0; color: #00e5bf; }
            .vb-privacy-title { font-size: 13px; font-weight: 600; color: #00e5bf; margin-bottom: 2px; }
            .vb-privacy-desc { font-size: 12px; color: #a1a7b3; }
            .vb-modal-footer {
                display: flex; flex-direction: column; gap: 10px;
                padding: 20px 24px; border-top: 1px solid #2a2d35; background: #0d0f12;
            }
            .vb-btn {
                display: flex; align-items: center; justify-content: center;
                gap: 8px; padding: 12px 20px; border: none; border-radius: 8px;
                font-size: 14px; font-weight: 600; cursor: pointer;
                transition: all 0.15s ease;
            }
            .vb-btn-primary { background: #00e5bf; color: #0d0f12; }
            .vb-btn-primary:hover { background: #00c9a7; transform: translateY(-1px); }
            .vb-btn-secondary { background: transparent; color: #a1a7b3; border: 1px solid #2a2d35; }
            .vb-btn-secondary:hover { background: #1e2128; color: #f4f5f6; }
            .vb-btn-ghost { background: #1e2128; color: #f4f5f6; }
            .vb-btn-ghost:hover { background: #252830; }
        `;
        try { document.head.appendChild(style); } catch { /* ignore */ }
    }

    function showToast({ title = '', message = '', type = 'info', duration = CONFIG.TOAST_DURATION }) {
        try {
            const container = getToastContainer();
            if (!container) return { dismiss: () => {} };
            const toast = document.createElement('div');
            toast.className = `vb-toast vb-toast-${type}`;
            toast.innerHTML = `
                <div class="vb-toast-content">
                    ${title ? `<div class="vb-toast-title">${escapeHtml(title)}</div>` : ''}
                    <div class="vb-toast-message">${escapeHtml(message)}</div>
                </div>
                <button class="vb-toast-close" aria-label="Dismiss">\u00d7</button>
            `;
            container.appendChild(toast);
            requestAnimationFrame(() => { toast.classList.add('vb-toast-show'); });
            const dismiss = () => {
                toast.classList.remove('vb-toast-show');
                setTimeout(() => { try { toast.remove(); } catch {} }, 300);
            };
            try { toast.querySelector('.vb-toast-close').addEventListener('click', dismiss); } catch {}
            if (duration > 0) setTimeout(dismiss, duration);
            return { dismiss };
        } catch {
            return { dismiss: () => {} };
        }
    }

    function showBlockModal({ findings, overallRisk, onRedact, onOverride, onCancel }) {
        try {
            if (modalOverlay) modalOverlay.remove();
            state.modalOpen = true;
            injectStyles();

            const riskClass = overallRisk === 'CRITICAL' ? 'critical' : overallRisk === 'HIGH' ? 'high' : overallRisk === 'MEDIUM' ? 'medium' : 'low';
            const riskInfo = RISK_LEVELS[overallRisk] || RISK_LEVELS.HIGH;
            const riskColor = riskInfo.color;

            const findingsHtml = findings.slice(0, 5).map(f => {
                const sourceClass = f.source === 'ml' ? 'ml' : f.source === 'contextual' ? 'contextual' : 'regex';
                return `
                    <div class="vb-finding-item">
                        <span class="vb-finding-label">
                            ${escapeHtml(f.name)}
                            <span class="vb-finding-source vb-finding-source-${sourceClass}">${sourceClass}</span>
                        </span>
                        <code class="vb-finding-value">${escapeHtml(f.redacted)}</code>
                    </div>
                `;
            }).join('');

            modalOverlay = document.createElement('div');
            modalOverlay.className = 'vb-modal-overlay';
            modalOverlay.innerHTML = `
                <div class="vb-modal">
                    <div class="vb-modal-header">
                        <div class="vb-modal-title">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${riskColor}" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                                <path d="M12 8v4"/><path d="M12 16h.01"/>
                            </svg>
                            Sensitive Data Detected
                        </div>
                        <span class="vb-risk-badge vb-risk-${riskClass}">${overallRisk} Risk</span>
                    </div>
                    <div class="vb-modal-body">
                        <p class="vb-modal-desc">
                            VaultBix detected <strong>${findings.length}</strong> sensitive item${findings.length > 1 ? 's' : ''}
                            that could be exposed to this AI tool.
                        </p>
                        <div class="vb-findings-list">
                            ${findingsHtml}
                            ${findings.length > 5 ? `<div class="vb-finding-item" style="justify-content: center; color: #6b7280;">+ ${findings.length - 5} more items</div>` : ''}
                        </div>
                        <div class="vb-privacy-notice">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                            <div>
                                <div class="vb-privacy-title">100% Local Analysis</div>
                                <div class="vb-privacy-desc">All detection runs in your browser. Nothing is sent to any server.</div>
                            </div>
                        </div>
                    </div>
                    <div class="vb-modal-footer">
                        <button class="vb-btn vb-btn-primary" data-action="redact">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                            Redact &amp; Continue Safely
                        </button>
                        <button class="vb-btn vb-btn-secondary" data-action="override">
                            Send Anyway (logged locally)
                        </button>
                        <button class="vb-btn vb-btn-ghost" data-action="cancel">Cancel</button>
                    </div>
                </div>
            `;

            if (document.body) document.body.appendChild(modalOverlay);
            requestAnimationFrame(() => { modalOverlay.classList.add('vb-modal-show'); });

            const close = () => {
                try {
                    modalOverlay.classList.remove('vb-modal-show');
                    setTimeout(() => {
                        try { modalOverlay.remove(); } catch {}
                        modalOverlay = null;
                        state.modalOpen = false;
                    }, CONFIG.MODAL_ANIMATION_MS);
                } catch { state.modalOpen = false; }
            };

            try {
                modalOverlay.querySelector('[data-action="redact"]').addEventListener('click', () => { close(); onRedact?.(); });
                modalOverlay.querySelector('[data-action="override"]').addEventListener('click', () => { close(); onOverride?.(); });
                modalOverlay.querySelector('[data-action="cancel"]').addEventListener('click', () => { close(); onCancel?.(); });
                modalOverlay.addEventListener('click', (e) => { if (e.target === modalOverlay) { close(); onCancel?.(); } });
            } catch {}

            const handleEscape = (e) => {
                if (e.key === 'Escape') {
                    document.removeEventListener('keydown', handleEscape);
                    close();
                    onCancel?.();
                }
            };
            document.addEventListener('keydown', handleEscape);

            return { close };
        } catch (error) {
            state.modalOpen = false;
            return { close: () => {} };
        }
    }

    // ========================================================================
    // ACTIVITY LOGGING
    // ========================================================================

    async function logActivity(action, findings) {
        try {
            const details = findings.map(f => f.name).join(', ');
            await sendToBackground({
                action: 'client_side_detection',
                type: action,
                details: details,
                url: window.location.href
            });
        } catch {
            // fail silently
        }
    }

    // ========================================================================
    // INPUT HANDLING
    // ========================================================================

    function getInputText(input) {
        if (!input) return '';
        try {
            if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') return input.value || '';
            if (input.isContentEditable) return input.textContent || input.innerText || '';
            return input.value || input.textContent || '';
        } catch { return ''; }
    }

    function setInputText(input, text) {
        if (!input) return false;
        try {
            if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
                input.value = text;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));
                return true;
            }
            if (input.isContentEditable) {
                input.textContent = text;
                input.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
                return true;
            }
        } catch { /* ignore */ }
        return false;
    }

    // ========================================================================
    // CORE DETECTION & BLOCKING
    // ========================================================================

    async function checkAndBlock(input, event) {
        if (state.isProcessing || state.modalOpen) return false;

        const text = getInputText(input);
        if (!text || !quickCheck(text)) return false;

        state.isProcessing = true;
        const { findings, overallRisk, summary } = await analyzeText(text);
        state.lastScanResult = { findings, overallRisk, summary, timestamp: Date.now() };

        if (findings.length === 0) { state.isProcessing = false; return false; }

        const features = await ensureFeatureState();

        if (!features.warningsEnabled) {
            state.isProcessing = false;
            return false;
        }

        // Free mode or blocking disabled: warn only
        if (!features.blockingEnabled) {
            showToast({
                title: 'Sensitive Data Detected',
                message: summary.message,
                type: 'warning',
                duration: CONFIG.TOAST_DURATION_FREE
            });
            logActivity('PROMPT_DETECTED', findings).catch(() => {});
            state.isProcessing = false;
            return false;
        }

        // Blocking enabled but low risk: warn only
        if (overallRisk === 'LOW') {
            showToast({
                title: 'Low Risk Data Detected',
                message: summary.message,
                type: 'warning'
            });
            logActivity('PROMPT_DETECTED', findings).catch(() => {});
            state.isProcessing = false;
            return false;
        }

        // Medium/High/Critical risk with blocking enabled: show modal
        return new Promise((resolve) => {
            showBlockModal({
                findings,
                overallRisk,
                onRedact: async () => {
                    if (features.redactionEnabled) {
                        const redactedContent = redactText(text, findings);
                        const success = setInputText(input, redactedContent);
                        if (success) {
                            showToast({ title: 'Content Redacted', message: 'Sensitive data safely removed', type: 'success' });
                        }
                    }
                    await logActivity('PROMPT_REDACTED', findings);
                    state.isProcessing = false;
                    setTimeout(() => {
                        try { const submitBtn = state.adapter?.getSubmit?.(); if (submitBtn) submitBtn.click(); } catch {}
                    }, 150);
                    resolve(true);
                },
                onOverride: async () => {
                    showToast({ title: 'Override Logged', message: 'Action recorded locally', type: 'warning' });
                    await logActivity('PROMPT_OVERRIDDEN', findings);
                    state.isProcessing = false;
                    setTimeout(() => {
                        try { const submitBtn = state.adapter?.getSubmit?.(); if (submitBtn) submitBtn.click(); } catch {}
                    }, 150);
                    resolve(true);
                },
                onCancel: () => { state.isProcessing = false; resolve(true); }
            });
        });
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    async function handleFormSubmit(e) {
        try {
            const form = e?.target;
            if (!form || form.tagName !== 'FORM') return;
            const input = state.adapter?.getInput?.();
            if (!input || !form.contains(input)) return;
            const shouldBlock = await checkAndBlock(input, e);
            if (shouldBlock) { e.preventDefault(); e.stopImmediatePropagation(); }
        } catch { /* fail silently */ }
    }

    async function handleButtonClick(e) {
        try {
            const button = e?.target?.closest('button');
            if (!button) return;
            const submitButton = state.adapter?.getSubmit?.();
            if (!submitButton || button !== submitButton) return;
            const input = state.adapter?.getInput?.();
            if (!input) return;
            const shouldBlock = await checkAndBlock(input, e);
            if (shouldBlock) { e.preventDefault(); e.stopImmediatePropagation(); e.stopPropagation(); }
        } catch { /* fail silently */ }
    }

    async function handleKeyDown(e) {
        try {
            if (e?.key !== 'Enter' || e.shiftKey) return;
            const input = state.adapter?.getInput?.();
            if (!input) return;
            const activeElement = document.activeElement;
            if (activeElement !== input && !input.contains(activeElement)) return;
            if (input.tagName === 'TEXTAREA' && !e.ctrlKey && !e.metaKey) return;
            const shouldBlock = await checkAndBlock(input, e);
            if (shouldBlock) { e.preventDefault(); e.stopImmediatePropagation(); }
        } catch { /* fail silently */ }
    }

    async function handlePaste(e) {
        try {
            if (!CONFIG.ENABLE_PASTE_WARNINGS) return;
            const features = await ensureFeatureState();
            if (!features.warningsEnabled) return;

            const text = e?.clipboardData?.getData('text') || '';
            if (!text || !quickCheck(text)) return;

            const { findings, overallRisk, summary } = await analyzeText(text);
            if (findings.length > 0 && overallRisk !== 'LOW') {
                showToast({
                    title: 'Sensitive Data in Clipboard',
                    message: summary.message,
                    type: 'warning',
                    duration: CONFIG.TOAST_DURATION_FREE
                });
                await logActivity('PASTE_WARNING', findings);
            }
        } catch { /* fail silently */ }
    }

    // ========================================================================
    // MUTATION OBSERVER
    // ========================================================================

    function setupMutationObserver() {
        try {
            if (state.mutationObserver) state.mutationObserver.disconnect();

            const debouncedCheck = debounce(() => {
                try {
                    const input = state.adapter?.getInput?.();
                    if (input && !state.observedInputs.has(input)) {
                        state.observedInputs.add(input);
                    }
                } catch { /* ignore */ }
            }, CONFIG.MUTATION_DEBOUNCE);

            state.mutationObserver = new MutationObserver((mutations) => {
                try {
                    const hasRelevant = mutations.some(m =>
                        m.type === 'childList' && (m.addedNodes.length > 0 || m.removedNodes.length > 0)
                    );
                    if (hasRelevant) debouncedCheck();
                } catch { /* ignore */ }
            });

            if (document.body) {
                state.mutationObserver.observe(document.body, { childList: true, subtree: true });
            }
        } catch { /* fail silently */ }
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    function selectAdapter() {
        try {
            const url = window.location.href;
            for (const [key, adapter] of Object.entries(ADAPTERS)) {
                if (key !== 'generic' && adapter.match.test(url)) return adapter;
            }
        } catch { /* ignore */ }
        return ADAPTERS.generic;
    }

    async function waitForInput() {
        while (state.initRetryCount < CONFIG.ELEMENT_MAX_RETRIES) {
            try {
                const input = state.adapter?.getInput?.();
                if (input) return input;
            } catch { /* ignore */ }
            state.initRetryCount++;
            await sleep(CONFIG.ELEMENT_POLL_INTERVAL);
        }
        return null;
    }

    async function initialize() {
        if (state.isInitialized) return;
        try {
            state.adapter = selectAdapter();
            await checkFeatures();
            await loadCustomRules();

            const input = await waitForInput();
            if (input) state.observedInputs.add(input);

            document.addEventListener('submit', handleFormSubmit, true);
            document.addEventListener('click', handleButtonClick, true);
            document.addEventListener('keydown', handleKeyDown, true);
            document.addEventListener('paste', handlePaste, true);

            setupMutationObserver();
            injectStyles();

            state.isInitialized = true;
        } catch {
            // fail silently - extension should never crash the host page
        }
    }

    function handleNavigation() {
        state.initRetryCount = 0;
        state.observedInputs = new WeakSet();
        state.adapter = selectAdapter();
        waitForInput().then(input => {
            if (input) state.observedInputs.add(input);
        }).catch(() => {});
    }

    // ========================================================================
    // START
    // ========================================================================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

    try {
        window.addEventListener('pageshow', (e) => {
            if (e?.persisted) { state.isInitialized = false; initialize(); }
        });
    } catch { /* ignore */ }

    try {
        let lastUrl = location.href;
        const urlObserver = new MutationObserver(() => {
            try {
                if (location.href !== lastUrl) { lastUrl = location.href; handleNavigation(); }
            } catch { /* ignore */ }
        });
        if (document.body) {
            urlObserver.observe(document.body, { childList: true, subtree: true });
        }
    } catch { /* ignore */ }

})();
