/**
 * VaultBix Configuration
 *
 * @file shared/config.js
 * @version 4.0.0
 */

const VAULTBIX_CONFIG = {
    API_BASE_URL: 'https://server-vaultbix.vercel.app',
    BASE_URL: 'https://vaultbix.com',
    SUPPORT_URL: 'https://vaultbix.com/contact',
    SUPPORT_EMAIL: 'info@vaultbix.com',
    HELP_URL: 'https://vaultbix.com/faq',
    PRIVACY_URL: 'https://vaultbix.com/privacy',
    TERMS_URL: 'https://vaultbix.com/terms',
    PRICING: {
        MONTHLY: 5,
        YEARLY: 48
    }
};

if (typeof window !== 'undefined') {
    window.VAULTBIX_CONFIG = VAULTBIX_CONFIG;
}

if (typeof globalThis !== 'undefined') {
    globalThis.VAULTBIX_CONFIG = VAULTBIX_CONFIG;
}
