/**
 * VaultBix First-Run Onboarding
 *
 * Lets the user pick a sensitivity tier (strict / balanced / minimal) before
 * the content script ever blocks anything. On finish, it tells the background
 * worker to flip `firstRunCompleted = true` so blocking can engage.
 */
(() => {
    'use strict';

    const root = document.getElementById('vbOnb');
    const cta = document.getElementById('vbOnbCta');
    const modes = Array.from(document.querySelectorAll('.vb-mode'));
    let selected = 'balanced';

    function selectMode(value) {
        selected = value;
        modes.forEach((el) => {
            const isMatch = el.dataset.value === value;
            el.classList.toggle('is-selected', isMatch);
            el.setAttribute('aria-checked', isMatch ? 'true' : 'false');
        });
    }

    modes.forEach((el) => {
        el.addEventListener('click', () => selectMode(el.dataset.value));
        el.addEventListener('keydown', (e) => {
            if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                selectMode(el.dataset.value);
            }
        });
    });

    cta.addEventListener('click', async () => {
        cta.disabled = true;
        try {
            await new Promise((resolve) => {
                try {
                    chrome.runtime.sendMessage(
                        { action: 'mark_first_run_complete', sensitivity: selected },
                        () => resolve()
                    );
                } catch { resolve(); }
            });
        } catch { /* ignore */ }
        root.classList.add('is-finished');
    });

    // Optional enterprise sign-in. Wired here (not as an inline onclick) so it
    // satisfies the extension-pages CSP (script-src 'self'); an inline handler
    // is silently blocked and the button would do nothing.
    const signIn = document.getElementById('vbSignIn');
    if (signIn) {
        signIn.addEventListener('click', () => {
            window.open('https://vaultbix.com/login', '_blank', 'noopener');
        });
    }
})();
