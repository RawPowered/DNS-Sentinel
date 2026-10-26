<div align="center">

  # DNS-Sentinel

  **Domain and email DNS auditing for messy migrations — MX, SPF, DMARC, SSL, and stack exposure with a Gemini assistant.**

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![React 19](https://img.shields.io/badge/React-19-087EA4?logo=react&logoColor=white)](https://react.dev/)
  [![Gemini](https://img.shields.io/badge/Gemini-3.1%20Pro-4285F4?logo=google&logoColor=white)](https://ai.google.dev/)
  [![Author](https://img.shields.io/badge/GitHub-RawPowered-181717?logo=github)](https://github.com/RawPowered)

</div>

---

## Why this exists

During a **~1 TB GoDaddy Microsoft 365 → Google Workspace** migration (mail, calendars, logs, private data), support teams across GoDaddy, Microsoft, and Namecheap insisted DNS was misconfigured — but the fix path was unclear.

DNS-Sentinel was built to **confirm transfer and connectivity issues** in one place: MX/SPF/DMARC state, SMTP reachability, SSL and security headers, WordPress vs **Vite dist** deployment exposure, plus a **server-side Gemini assistant** for remediation guidance.

**Created by:** [Joseph Edwards (@RawPowered)](https://github.com/RawPowered) · MIT licensed

---

## Core capabilities

| Capability | What it does |
|---|---|
| **Domain audit** | A/MX/NS/TXT, SPF, DMARC, SSL cert, security headers, 0–100 score |
| **Email provider detection** | Google Workspace, M365/Outlook, GoDaddy legacy, Zoho, ProtonMail heuristics |
| **SMTP + MX tests** | Authenticate SMTP; port 25 banner check against primary MX |
| **Stack detection** | WordPress (`/wp-login.php`) vs Vite SPA (`assets/index-*`, ES modules) |
| **Vite deep scan** | Optional probe of `dist/`, manifest, and build artifact exposure |
| **AI assistant** | Server-proxied Gemini — fix guides, security chat, email diagnostics chat |
| **Audit history** | SQLite-backed per-domain history and profile list |

---

## Quick start

**Requirements:** Node.js 18+ · `GEMINI_API_KEY` (optional — audits work without AI)

```powershell
git clone https://github.com/RawPowered/DNS-Sentinel.git
cd DNS-Sentinel
copy .env.example .env.local
# Set GEMINI_API_KEY in .env.local for AI features
.\Launch-DNS-Sentinel.ps1
```

Or:

```bash
npm install
npm run dev
```

Open **http://localhost:3000**

---

## Migration checklist (M365 → Google Workspace)

Use DNS-Sentinel to validate each step:

1. **Pre-cutover** — Run email audit; note current MX (likely `*.outlook.com`) and SPF includes
2. **MX cutover** — Switch to Google MX; re-audit until provider shows Google Workspace and SPF includes `_spf.google.com`
3. **SPF** — Single TXT record; avoid duplicate SPF (RFC 7208 violation)
4. **DMARC** — Add `_dmarc` TXT with policy aligned to your rollout (`p=none` → `quarantine` → `reject`)
5. **Autodiscover / CNAME** — Verify Google Workspace admin console required records
6. **TTL** — Lower TTL before cutover; re-audit after propagation (24–48h)
7. **Post-cutover** — SMTP test + MX banner test; use AI chat for lingering delivery issues

---

## API reference

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/profiles` | List audited domains |
| GET | `/api/history/:domain` | Last 10 audits |
| POST | `/api/analyze` | Full domain audit (`{ domain, deepViteScan? }`) |
| POST | `/api/email/audit` | MXTools-style email health |
| POST | `/api/email/test-smtp` | SMTP verify |
| POST | `/api/email/test-mx` | MX port 25 banner |
| POST | `/api/ai/fix-guide` | AI remediation guide from audit JSON |
| POST | `/api/ai/security-chat` | Contextual security Q&A |
| POST | `/api/ai/mx-chat` | Email migration diagnostics chat |

---

## Project layout

```
DNS-Sentinel/
├── server/
│   ├── index.ts           # Express + Vite middleware
│   ├── db.ts              # SQLite audit history
│   ├── dnsAudit.ts        # Domain analyze orchestration
│   ├── emailAudit.ts      # Provider heuristics + email endpoints
│   ├── frameworkDetect.ts # WP/Vite detect + exposure scan
│   └── aiRoutes.ts        # Server-side Gemini proxy
├── src/
│   ├── App.tsx            # Audit + email UI
│   └── lib/api.ts         # Client API wrappers
└── EnVars/
```

---

## License

MIT — see [LICENSE](LICENSE).
