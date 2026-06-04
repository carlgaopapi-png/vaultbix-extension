# VaultBix — AI Data Leak Guard

VaultBix is a Chrome extension that detects API keys, passwords, and sensitive data before you share them with AI tools. **100% local scanning — nothing leaves your browser.**

> ⚠️ **VaultBix is no longer actively maintained.** The code stays up and the extension keeps working — it's open source, so fork it and build on it. Built by Carl and Max, 2025–2026.

## What It Detects

- API Keys (OpenAI, AWS, Stripe, Google, GitHub, and more)
- Passwords & credentials
- Credit card numbers & SSNs
- Private keys & database connection strings
- JWT tokens & webhook URLs
- Custom patterns you define

## How It Works

VaultBix monitors outgoing requests on AI platforms (ChatGPT, Claude, Gemini, Copilot, etc.) and scans for sensitive data using local pattern matching. When a threat is detected, VaultBix shows a banner with the secret type and either warns or blocks based on your sensitivity setting:

- **Strict**: blocks anything detected
- **Balanced** (default): blocks Critical findings, warns on the rest
- **Minimal**: warns on Critical only, ignores everything else

Strict mode blocks any detected secret before it leaves your browser — the request is intercepted and never sent. All detection runs locally in your browser. No data is ever sent to any server for scanning.

## Supported Platforms

| Platform | URLs |
|----------|------|
| ChatGPT | chatgpt.com, chat.openai.com |
| Claude | claude.ai |
| Google Gemini & AI Studio | gemini.google.com, aistudio.google.com |
| Microsoft Copilot | copilot.microsoft.com, m365.cloud.microsoft |
| GitHub Copilot Chat | github.com/copilot, github.com/\*/copilot (Copilot pages only) |
| Perplexity | www.perplexity.ai |
| DeepSeek | chat.deepseek.com |
| Grok | grok.com, x.com/i/grok |
| Poe | poe.com |
| HuggingFace Chat | huggingface.co/chat |
| Mistral Chat | chat.mistral.ai |
| You.com | you.com |

## Install from Source

1. Clone this repo:
   ```
   git clone https://github.com/carlgaopapi-png/vaultbix-extension.git
   ```
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the `vaultbix-extension` folder

## Project Structure

```
vb.ext/
  manifest.json          # Chrome extension manifest (MV3)
  background.js          # Service worker — storage, messaging, enterprise sync
  popup.html             # Extension popup UI
  popup.js               # Popup logic
  style.css              # Shared styles
  dashboard.html         # Full activity dashboard
  dashboard.js           # Dashboard logic
  onboarding.html        # First-run onboarding UI
  onboarding.js          # Onboarding logic
  shared/
    config.js            # URLs and shared config
  content/
    inject.js            # Page-world script — patches fetch/XHR/sendBeacon
    main.js              # Content script — input monitoring, detection, UI
    detection/
      detector.js        # Unified detection engine
      patterns.js        # Regex patterns for secrets (45 patterns)
      ml-detector.js     # Optional ML layer (graceful fallback)
      ml-worker.js       # Web Worker for ML inference
    ui/
      components.css     # Injected component styles
      banner.js          # Inline warning banners
      modal.js           # Blocking modal
      toast.js           # Toast notifications
      highlight.js       # Text highlighting
  icons/
    icon16.png
    icon48.png
    icon128.png
    icon-vb.png          # Source logo (128px)
```

## Privacy

- **Zero network requests** for detection (all local regex matching)
- **Logs stored locally** on your device only (event type, timestamp, site, secret type prefix, length, and SHA-256 hash — never the actual secret values)
- **No analytics, no telemetry, no tracking**
- Optional team sync (off by default): if you explicitly connect to an organization, hash + metadata is sent to your team's backend. Raw secret values never leave your device.

You can verify this yourself — the source code is right here.

## Coming Soon

We're building a Team tier for engineering organizations:
- Team admin dashboard with org-wide incident visibility
- SSO authentication (Google Workspace, Okta)
- Centralized policy controls — admins set blocking rules across the team
- Auto-redaction of detected secrets in-flight
- Custom detection rules per organization
- Audit logs and SIEM integration

**Interested in being a design partner?** Email [founders@vaultbix.com](mailto:founders@vaultbix.com) — we're working with engineering teams of 10-50 right now.

## Contributing

PRs welcome. If you find a secret pattern we're not catching, add it to `content/detection/patterns.js` and open a PR.

## License

MIT
