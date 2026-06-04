/**
 * VaultBix Detection Patterns
 * Consolidated regex patterns for detecting sensitive data.
 *
 * Each pattern has:
 *   id       - unique identifier
 *   name     - human-readable label
 *   pattern  - regex (without global flag; matchAll adds it)
 *   risk     - CRITICAL | HIGH | MEDIUM | LOW
 *   category - grouping for UI / reporting
 *   validate - optional post-match validation function
 */

// ── helpers ────────────────────────────────────────────────────────────────

function luhnCheck(cardNumber) {
    const digits = cardNumber.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let isEven = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let digit = parseInt(digits[i], 10);
        if (isEven) { digit *= 2; if (digit > 9) digit -= 9; }
        sum += digit;
        isEven = !isEven;
    }
    return sum % 10 === 0;
}

// ── main patterns ──────────────────────────────────────────────────────────

export const REGEX_PATTERNS = [
    // ===== API Keys =====
    {
        id: 'openai_api_key',
        name: 'OpenAI API Key',
        pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'openai_project_key',
        name: 'OpenAI Project Key',
        pattern: /sk-proj-[A-Za-z0-9_-]{40,}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'openai_key_new',
        name: 'OpenAI API Key',
        pattern: /sk-[A-Za-z0-9]{32,}/,
        risk: 'CRITICAL',
        category: 'API_KEY',
        validate: (match) => match.length >= 35 && !match.startsWith('sk-proj-') && !match.startsWith('sk-ant-') && !match.includes('T3BlbkFJ')
    },
    {
        id: 'anthropic_api_key',
        name: 'Anthropic API Key',
        pattern: /sk-ant-[A-Za-z0-9_-]{40,}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'aws_access_key',
        name: 'AWS Access Key',
        pattern: /AKIA[0-9A-Z]{16}/,
        risk: 'CRITICAL',
        category: 'API_KEY',
        validate: (match) => /^AKIA[A-Z0-9]{16}$/.test(match)
    },
    {
        id: 'aws_secret_key',
        name: 'AWS Secret Key',
        pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/,
        risk: 'CRITICAL',
        category: 'API_KEY',
        validate: (match, fullText) => {
            const idx = fullText.indexOf(match);
            if (idx === -1) return false;
            const start = Math.max(0, idx - 100);
            const end = Math.min(fullText.length, idx + match.length + 100);
            const ctx = fullText.slice(start, end).toLowerCase();
            return ctx.includes('aws_secret_access_key') || ctx.includes('aws_secret');
        }
    },
    {
        id: 'stripe_secret_key',
        name: 'Stripe Secret Key',
        pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'stripe_restricted_key',
        name: 'Stripe Restricted Key',
        pattern: /rk_(live|test)_[A-Za-z0-9]{24,}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'stripe_publishable_key',
        name: 'Stripe Publishable Key',
        pattern: /pk_(live|test)_[A-Za-z0-9]{24,}/,
        risk: 'MEDIUM',
        category: 'API_KEY'
    },
    {
        id: 'github_personal_token',
        name: 'GitHub Personal Token',
        pattern: /ghp_[A-Za-z0-9]{36}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'github_oauth_token',
        name: 'GitHub OAuth Token',
        pattern: /gho_[A-Za-z0-9]{36}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'github_app_token',
        name: 'GitHub App Token',
        pattern: /ghu_[A-Za-z0-9]{36}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'github_server_token',
        name: 'GitHub Server Token',
        pattern: /ghs_[A-Za-z0-9]{36}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'github_refresh_token',
        name: 'GitHub Refresh Token',
        pattern: /ghr_[A-Za-z0-9]{36}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'gitlab_token',
        name: 'GitLab Token',
        pattern: /glpat-[A-Za-z0-9_-]{20,}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'google_api_key',
        name: 'Google API Key',
        pattern: /AIza[A-Za-z0-9_-]{35}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'google_oauth_client',
        name: 'Google OAuth Client',
        pattern: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'slack_token',
        name: 'Slack Token',
        pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'slack_webhook',
        name: 'Slack Webhook URL',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'discord_token',
        name: 'Discord Token',
        pattern: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'discord_webhook',
        name: 'Discord Webhook',
        pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'sendgrid_key',
        name: 'SendGrid API Key',
        pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
        risk: 'CRITICAL',
        category: 'API_KEY'
    },
    {
        id: 'twilio_key',
        name: 'Twilio API Key',
        pattern: /SK[a-f0-9]{32}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'mailchimp_key',
        name: 'Mailchimp API Key',
        pattern: /[a-f0-9]{32}-us[0-9]{1,2}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'npm_token',
        name: 'NPM Token',
        pattern: /npm_[A-Za-z0-9]{36}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },
    {
        id: 'pypi_token',
        name: 'PyPI Token',
        pattern: /pypi-[A-Za-z0-9_-]{100,}/,
        risk: 'HIGH',
        category: 'API_KEY'
    },

    // ===== Private Keys & Certificates =====
    {
        id: 'private_key',
        name: 'Private Key',
        pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(\s+BLOCK)?-----/,
        risk: 'CRITICAL',
        category: 'PRIVATE_KEY'
    },
    {
        id: 'certificate',
        name: 'Certificate',
        pattern: /-----BEGIN CERTIFICATE-----/,
        risk: 'MEDIUM',
        category: 'PRIVATE_KEY'
    },

    // ===== Credentials =====
    {
        id: 'password_assignment',
        name: 'Embedded Credential',
        pattern: /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?token)\s*[:=]\s*['"`]?[^\s'"`,\n]{8,}/i,
        risk: 'HIGH',
        category: 'CREDENTIAL',
        validate: (match) => {
            const lower = match.toLowerCase();
            const blocklist = ['example', 'xxx', 'placeholder', 'your_', 'enter', 'insert', 'add_', 'change', 'replace', 'here', 'value', '<', '>', '****', '...'];
            if (blocklist.some(b => lower.includes(b))) return false;
            const valMatch = match.match(/[:=]\s*['"`]?(.*)/i);
            if (valMatch) {
                const val = valMatch[1].replace(/['"`]$/, '').toLowerCase();
                const placeholders = ['password', 'changeme', 'undefined', 'null', 'none', 'empty', 'default', 'todo', 'fixme', 'update', 'required', 'needed', 'missing', 'blank', 'nothing', 'sample', 'dummy', 'fake', 'test', 'testing'];
                if (placeholders.includes(val)) return false;
            }
            return true;
        }
    },
    {
        id: 'basic_auth',
        name: 'Basic Auth Header',
        pattern: /Basic\s+[A-Za-z0-9+/=]{10,}/,
        risk: 'HIGH',
        category: 'CREDENTIAL'
    },
    {
        id: 'bearer_token',
        name: 'Bearer Token',
        pattern: /Bearer\s+[A-Za-z0-9_-]{20,}/,
        risk: 'HIGH',
        category: 'CREDENTIAL',
        validate: (match) => {
            const token = match.replace(/^Bearer\s+/i, '').toLowerCase();
            const skipList = ['example', 'test', 'sample', 'your', 'token', 'insert', 'placeholder', 'change', 'replace'];
            return !skipList.some(s => token.includes(s));
        }
    },
    {
        id: 'jwt',
        name: 'JWT Token',
        pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
        risk: 'MEDIUM',
        category: 'CREDENTIAL'
    },

    // ===== Database & Connection Strings =====
    {
        id: 'database_url',
        name: 'Database Connection String',
        pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp|memcached):\/\/[^\s"'`<>]+/i,
        risk: 'CRITICAL',
        category: 'CREDENTIAL'
    },
    {
        id: 'connection_string',
        name: 'Connection String',
        pattern: /(?:Server|Data Source)=[^;]+;(?:Database|Initial Catalog)=[^;]+;(?:User Id|UID)=[^;]+;(?:Password|PWD)=[^;]+/i,
        risk: 'CRITICAL',
        category: 'CREDENTIAL'
    },

    // ===== PII =====
    {
        id: 'ssn',
        name: 'Social Security Number',
        pattern: /\b\d{3}-\d{2}-\d{4}\b/,
        risk: 'CRITICAL',
        category: 'PII',
        validate: (match) => {
            const [area, group, serial] = match.split('-').map(Number);
            return area >= 1 && area <= 899 && area !== 666 &&
                   group >= 1 && group <= 99 &&
                   serial >= 1 && serial <= 9999;
        }
    },
    {
        id: 'credit_card_visa',
        name: 'Credit Card (Visa)',
        pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
        risk: 'CRITICAL',
        category: 'PII',
        validate: (match) => luhnCheck(match)
    },
    {
        id: 'credit_card_mastercard',
        name: 'Credit Card (Mastercard)',
        pattern: /\b5[1-5][0-9]{14}\b/,
        risk: 'CRITICAL',
        category: 'PII',
        validate: (match) => luhnCheck(match)
    },
    {
        id: 'credit_card_amex',
        name: 'Credit Card (Amex)',
        pattern: /\b3[47][0-9]{13}\b/,
        risk: 'CRITICAL',
        category: 'PII',
        validate: (match) => luhnCheck(match)
    },
    {
        id: 'credit_card_discover',
        name: 'Credit Card (Discover)',
        pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/,
        risk: 'CRITICAL',
        category: 'PII',
        validate: (match) => luhnCheck(match)
    },
    {
        id: 'phone_us',
        name: 'Phone Number (US)',
        pattern: /\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
        risk: 'MEDIUM',
        category: 'PII',
        validate: (match, fullText) => {
            const idx = fullText.indexOf(match);
            if (idx === -1) return false;
            if (idx > 0 && /\d/.test(fullText[idx - 1])) return false;
            const afterIdx = idx + match.length;
            if (afterIdx < fullText.length && /\d/.test(fullText[afterIdx])) return false;
            const start = Math.max(0, idx - 150);
            const end = Math.min(fullText.length, afterIdx + 150);
            const ctx = fullText.slice(start, end).toLowerCase();
            return /\b(?:phone\s*(?:number|#|:)|tel[:\s]|mobile[:\s]|cell[:\s]|fax[:\s]|contact\s*(?:number|#|:)|sms[:\s])\b/.test(ctx);
        }
    },
    {
        id: 'phone_intl',
        name: 'Phone Number (International)',
        pattern: /\b\+[1-9]\d{6,14}\b/,
        risk: 'MEDIUM',
        category: 'PII',
        validate: (match, fullText) => {
            const idx = fullText.indexOf(match);
            if (idx === -1) return false;
            const start = Math.max(0, idx - 150);
            const end = Math.min(fullText.length, idx + match.length + 150);
            const ctx = fullText.slice(start, end).toLowerCase();
            return /\b(?:phone\s*(?:number|#|:)|tel[:\s]|mobile[:\s]|cell[:\s]|fax[:\s]|contact\s*(?:number|#|:)|sms[:\s])\b/.test(ctx);
        }
    },
];

// ── contextual patterns (require nearby keywords) ──────────────────────────

export const CONTEXTUAL_PATTERNS = [
    {
        id: 'financial_figure',
        name: 'Financial Figure',
        pattern: /\$[\d,]+(?:\.\d{1,2})?(?:\s*(?:million|billion|trillion|M|B|K|T))?/i,
        contextRequired: /\b(?:revenue|profit|valuation|funding|salary|compensation|budget|forecast|earnings|EBITDA|ARR|MRR|runway|series\s[A-D]|raise|investment|gross|net\sincome|operating|margin|cash\sflow)\b/i,
        contextWindow: 200,
        risk: 'HIGH',
        category: 'FINANCIAL_DATA',
        validate: (match) => {
            // Only flag amounts > $10,000
            const raw = match.replace(/[$,]/g, '');
            const num = parseFloat(raw);
            if (isNaN(num)) return false;
            const suffix = match.match(/(?:million|billion|trillion|M|B|K|T)\s*$/i);
            if (suffix) return true; // Any amount with a scale suffix is significant
            return num >= 10000;
        }
    },
    {
        id: 'salary_figure',
        name: 'Salary / Compensation',
        pattern: /\$[\d,]+(?:\.\d{1,2})?(?:\s*(?:\/\s*(?:year|yr|month|mo|hour|hr|annual)))?/i,
        contextRequired: /\b(?:salary|compensation|pay|wage|bonus|equity|stock\soption|RSU|vesting|offer\sletter|total\scomp|base\spay|OTE)\b/i,
        contextWindow: 200,
        risk: 'HIGH',
        category: 'FINANCIAL_DATA',
        validate: (match) => {
            const raw = match.replace(/[$,]/g, '').replace(/\/.*$/, '');
            const num = parseFloat(raw);
            return !isNaN(num) && num >= 10000;
        }
    }
];

// ── risk level definitions ─────────────────────────────────────────────────

export const RISK_LEVELS = {
    CRITICAL: { label: 'Critical', color: '#dc2626', bgColor: 'rgba(220, 38, 38, 0.12)', priority: 4 },
    HIGH:     { label: 'High',     color: '#f04438', bgColor: 'rgba(240, 68, 56, 0.12)', priority: 3 },
    MEDIUM:   { label: 'Medium',   color: '#f79009', bgColor: 'rgba(247, 144, 9, 0.12)', priority: 2 },
    LOW:      { label: 'Low',      color: '#12b76a', bgColor: 'rgba(18, 183, 106, 0.12)', priority: 1 }
};

// ── quick-check patterns for early exit ────────────────────────────────────

export const QUICK_CHECK_PATTERNS = [
    /sk-/i, /AKIA/, /ghp_/, /gho_/, /ghs_/, /xox[baprs]-/,
    /-----BEGIN/, /password\s*[:=]\s*['"`]?[^\s]{8,}/i, /secret\s*[:=]\s*['"`]?[^\s]{8,}/i, /aws_secret/i, /api[_-]?key/i,
    /\d{3}-\d{2}-\d{4}/, /4\d{15}/, /5[1-5]\d{14}/,
    /Bearer\s/, /eyJ[A-Za-z0-9]/, /mongodb:\/\//, /postgres:\/\//
];
