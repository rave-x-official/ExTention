# ExTention — No More Tension.

A privacy-first browser extension that sniffs out phishing, malware, and Rickrolls before they waste your time. Bring your **own** VirusTotal API key — nothing leaves your machine.

---

## Why the name?

**Ex + Tention** = Removing the tension from browsing. No more second-guessing that sketchy link your "friend" sent you. No more panic when a URL looks off. ExTention has your back.

---

## Features

- 🛡️ **Privacy-First** — Your API key stays in `chrome.storage.local`. The extension calls VirusTotal directly from the service worker. Nothing is logged, shared, or exfiltrated.
- 🎸 **Rickroll Defense** — Instant, quota-free blocking of classic pranks like `youtube.com/watch?v=dQw4w9WgXcQ`, `rickroll.*` domains, and bit.ly redirects.
- 🔍 **Smart Scanning** — Blocklist (free) → Cache (24h TTL) → VirusTotal API → Optional backend proxy with heuristic scoring.
- 🐍 **Powered by Python** — Optional FastAPI backend acts as a CORS-busting blind proxy. Adds domain heuristics (suspicious TLDs, hyphens, digit-heavy subdomains) to save API calls.
- ⚡ **Real-time** — Checks every page load via content-script messaging. No `tabs.onUpdated` race conditions.

---

## Architecture

```
extension/                Chrome Extension (Manifest V3, React, TypeScript)
├── public/manifest.json
├── src/
│   ├── popup.tsx         React popup — API key + backend URL management
│   ├── background.ts     Service worker — blocklist → cache → VirusTotal
│   ├── content.ts        Content script — full-page red overlay on threat
│   └── utils/
│       ├── api.ts        VirusTotal helpers + backend fallback logic
│       └── blocklist.ts  BLOCKLIST + RICKROLL_BLOCKLIST with regex support
├── index.html
├── vite.config.ts        Vite — builds React popup
├── tsconfig.json
└── package.json

backend/                  Optional FastAPI blind proxy & heuristics
├── main.py
├── requirements.txt
├── Dockerfile
└── data/
    └── rickroll_domains.csv
```

### Privacy Model

| Data | Where stored | Who can access it |
|------|-------------|-------------------|
| VirusTotal API key | `chrome.storage.local` (your browser) | Only you |
| URLs scanned | Never logged; cached locally for 24h | Only you |
| VirusTotal responses | Cached locally | Only you |
| Backend (if used) | Stateless — stores nothing, logs nothing | Not applicable |

---

## Getting a VirusTotal API Key

1. Create a free account at [VirusTotal Community](https://www.virustotal.com/gui/join-us).
2. Go to your [API Key page](https://www.virustotal.com/gui/user/*/apikey).
3. Copy the 64-character hex key.
4. Open the ExTention popup and paste it.

> **Free tier:** 4 requests/min, 500/day. Results are cached for 24 hours.

---

## Installing the Extension (Unpacked)

### Prerequisites
- Node.js 18+
- npm 9+

### Build

```bash
cd extension
npm install
npm run build
```

### Load in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select `extension/dist`

The ExTention icon appears in your toolbar.

---

## Running the Backend (Optional)

Use the backend when the extension can't reach VirusTotal directly (corporate proxy, restrictive CORS, etc.). It's a stateless blind proxy — it forwards your key and URL, runs heuristics, and returns the result. **Nothing is logged.**

### Locally

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Docker

```bash
cd backend
docker build -t extention-backend .
docker run -p 8000:8000 extention-backend
```

### Endpoint

**POST** `/check`

```json
{ "url": "https://example.com", "api_key": "your-key" }
```

Response:
```json
{
  "source": "virustotal",
  "malicious": false,
  "label": "Clean",
  "vt_stats": { "malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 7 },
  "heuristics": { "flags": [], "score": 0, "malicious": false }
}
```

---

## Developer Notes

### Extending the Blocklist

Add new entries to `RICKROLL_BLOCKLIST` or `BLOCKLIST` in `src/utils/blocklist.ts`. Four match types are supported:

| Type | Example | Matches |
|------|---------|---------|
| `domain` | `"malware.example"` | Exact domain match (after stripping `www.`) |
| `url` | `"bit.ly/evil"` | URL substring match (case-insensitive) |
| `substring` | `".tk/login"` | Anywhere in the URL |
| `regex` | `"rickroll\\..*"` | Regex test against domain and full URL |

### Build Commands

```bash
npm run build          # Full production build
npm run dev            # Watch mode (Vite + esbuild in parallel)
```

The popup is built by **Vite** (React). The background service worker and content script are bundled by **esbuild** (ESM and IIFE respectively).

### Fallback Flow

1. Extension tries direct VirusTotal API call.
2. If that fails (CORS / network error) AND a backend URL is configured, the request is forwarded to the backend.
3. If the backend is also unreachable, a "Connection Error" message is shown in the popup.

---

## License

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Copyright (C) 2026 [Your Name]

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)** — see the [LICENSE](./LICENSE) file for the full text.

### Why GPL?

GPL was chosen deliberately to ensure ExTention stays **free, open, and privacy-focused forever**:

- **Copyleft protection** — Anyone who distributes a modified version of ExTention must also release their changes under the same GPL-3.0 license. No one can take this project private, close the source, or sell a proprietary fork.

- **Source code stays public** — The license guarantees you (and everyone else) always have access to the full source code, including any derivative works.

- **No warranties** — The software is provided "as is," with no liability. You run it at your own risk, which is essential for a security tool that handles API keys and URL scanning.

- **Privacy guarantee through transparency** — Because the source must always be available, any privacy-violating modifications would be immediately visible to the community. The "user owns their API key" model is baked into the code and can never be silently removed.

In short: ExTention is yours. GPL makes sure it stays that way.

### What this means for you

| You can | You must |
|---------|----------|
| ✅ Use ExTention for any purpose (personal, commercial, educational) | 📄 Include a copy of the GPL-3.0 license |
| ✅ Modify the code to suit your needs | 🔓 Disclose your source code when distributing |
| ✅ Share copies with others | 🏷️ State significant changes you made |
| ✅ Charge for distribution or support | ⚖️ License derivative works under GPL-3.0
