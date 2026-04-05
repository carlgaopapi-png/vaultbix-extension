# VaultBix — AI Data Leak Guard

VaultBix is a Chrome extension that detects API keys, passwords, and sensitive data before you share them with AI tools. **100% local scanning — nothing leaves your browser.**

## What It Detects

- API Keys (OpenAI, AWS, Stripe, Google, GitHub, and more)
- Passwords & credentials
- Credit card numbers & SSNs
- Private keys & database connection strings
- JWT tokens & webhook URLs
- Custom patterns you define

## How It Works

VaultBix monitors text inputs on AI platforms (ChatGPT, Claude, Gemini, Copilot, etc.) and scans for sensitive data using local pattern matching. When a threat is detected:

- **Free**: Warning toast notification
- **Pro**: Block submission, redact sensitive values, or send anyway

All detection runs locally in your browser. No data is ever sent to any server for scanning.

## Supported Platforms

| Platform | Status |
|----------|--------|
| ChatGPT (chatgpt.com) | Supported |
| Claude (claude.ai) | Supported |
| Gemini (gemini.google.com) | Supported |
| GitHub Copilot Chat | Supported |
| Microsoft Copilot | Supported |
| Perplexity | Supported |
| DeepSeek | Supported |
| Grok | Supported |
| Poe | Supported |
| HuggingFace Chat | Supported |
| Mistral Chat | Supported |
| You.com | Supported |

## Install from Source

1. Clone this repo:
   ```
   git clone https://github.com/vaultbix/vb.ext.git
   ```
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the `vb.ext` folder

## Project Structure

```
vb.ext/
  manifest.json          # Chrome extension manifest (MV3)
  background.js          # Service worker — storage, messaging, license
  popup.html             # Extension popup UI
  popup.js               # Popup logic
  style.css              # Shared styles
  dashboard.html         # Full activity dashboard
  dashboard.js           # Dashboard logic
  shared/
    config.js            # URLs and pricing config
  content/
    main.js              # Content script — input monitoring, UI
    detection/
      detector.js        # Unified detection engine
      patterns.js        # Regex patterns for secrets
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
```

## Privacy

- **Zero network requests** for detection (all local regex matching)
- **Logs stored locally** on your device only (event type, timestamp, site — never the actual secret values)
- **No analytics, no telemetry, no tracking**
- Only network request: Pro license validation (no prompt data sent)

You can verify this yourself — the source code is right here.

## Pro Features

Free tier shows warnings. [VaultBix Pro](https://vaultbix.com) adds:

- Block submissions containing secrets
- Auto-redact sensitive values
- Unlimited custom detection rules
- Full activity dashboard

## Contributing

PRs welcome. If you find a secret pattern we're not catching, add it to `content/detection/patterns.js` and open a PR.

## License

MIT
