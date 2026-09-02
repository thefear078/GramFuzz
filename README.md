<p align="center">
  <img src="src/assets/logo.png" alt="GramFuzz Logo" width="160">
</p>

<h1 align="center">GramFuzz</h1>

<p align="center">
  <strong>Ethical DAST Framework for Telegram Bots &amp; Mini Apps</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white" alt="Go 1.25+"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy-red" alt="Security Policy"></a>
</p>

<p align="center">
  <a href="https://github.com/kiurakku">Author: kiurakku (The Fear)</a> &nbsp;|&nbsp;
  <a href="https://t.me/thefear007">Telegram: @thefear007</a>
</p>

![GramFuzz Banner](src/assets/banner.png)

---

GramFuzz is a Dynamic Application Security Testing (DAST) framework built specifically for the Telegram ecosystem — bots, inline keyboards, and Telegram Mini Apps (TMA). It combines automated fuzzing with realistic user simulation to uncover logic flaws, authorization bugs, and third-party API weaknesses **before** attackers do.

> **Authorized use only.** GramFuzz is designed for legal penetration testing and security audits with explicit permission from the system owner.

## Table of Contents

- [Problems Addressed](#problems-addressed)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [The Engine Pipeline](#the-engine-pipeline)
- [Satellite Modules](#satellite-modules)
- [Configuration](#configuration)
- [Reports](#reports)
- [Documentation](#documentation)
- [Ethical Use](#ethical-use)
- [Author & Contact](#author--contact)
- [License](#license)

> **Contributing or extending GramFuzz?** Start with [CLAUDE.md](CLAUDE.md) — a
> one-page orientation to the codebase — and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Problems Addressed

| Vulnerability | Description |
|---|---|
| **InitData forgery** | Backend fails to validate the HMAC hash of Telegram WebApp `initData`, allowing user ID spoofing |
| **BOLA / IDOR** | Unauthorized access to other users' data via ID substitution in API requests |
| **Logic flaws** | Dialog flow errors that bypass paywalls, loyalty systems, or rate limits |
| **Web3 payload swap** | Transaction payload manipulation in TMA before wallet signing |
| **API surface leaks** | Unprotected endpoints and exposed API structure via Mini App traffic |

## Architecture

GramFuzz is a **single Go binary** running a 13-phase pentest pipeline, with
optional Python/TypeScript satellite modules for live interaction. It needs no
bot token or API credentials — everything degrades gracefully to public recon.

```
gramfuzz (Go):  cli -> scanner -> pentest.Run(ctx, cfg)
                profile target | run enabled phases | score | report

  recon          fuzz           attack          webinspect
  phases 1-3,12  phases 4,10    phases 5-9      phase 11
  profile/OSINT  command/BOLA   inj/pay/hook    Mini App SAST

  findings (scoring) | reporter (HTML/JSON/PDF) | assets (wordlists)

  Optional satellites (out of pipeline, independently runnable):
  user-simulator (Py/Telethon) | web-inspector (TS/Playwright)
  attack-runner (Py)           | ai-analyzer (Py/local LLM)
```

The full package map and data flow live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the authoritative module list is
[`internal/catalog`](internal/catalog/catalog.go), rendered by `gramfuzz modules`.

## Quick Start

### Requirements

- Go 1.25+ (the only hard requirement — builds a single static binary)
- Python 3.10+ *(optional)* — `user-simulator`, `attack-runner`, `ai-analyzer`
- Node.js 18+ *(optional)* — `web-inspector`

### Build & Run

```bash
git clone https://github.com/kiurakku/GramFuzz.git
cd GramFuzz

go build -o gramfuzz ./cmd/gramfuzz

# Show ASCII banner and module list
./gramfuzz modules

# Demo scan (no target)
./gramfuzz scan

# Full scan with target
./gramfuzz scan \
  --bot mybot \
  --webapp https://myapp.example.com \
  --backend https://api.example.com \
  --format both
```

### Windows (PowerShell)

```powershell
go build -o gramfuzz.exe .\cmd\gramfuzz
.\gramfuzz.exe modules
.\gramfuzz.exe scan --bot demo_bot --backend https://api.example.com
```

## CLI Reference

| Command | Description |
|---|---|
| `gramfuzz pentest --bot USER` | Full 13-phase engagement (all modules on, 15-min budget) |
| `gramfuzz scan` | Security scan with the configured/default modules |
| `gramfuzz fuzz --backend URL` | BOLA/IDOR fuzzing against API endpoints only |
| `gramfuzz modules [--json]` | List the module catalog (`--json` for machine-readable output) |
| `gramfuzz version` | Print version |

| Flag | Applies to | Description |
|---|---|---|
| `--bot USER` | scan, pentest | Target bot username |
| `--webapp URL` | scan, pentest | Telegram Mini App URL |
| `--backend URL` | scan, pentest, fuzz | Backend API base URL |
| `--format` | scan, pentest | `html` (default) · `json` · `pdf` · `both` · `all` |
| `--output DIR` | all | Report directory (default `./reports`) |
| `--no-banner` | global | Suppress the ASCII banner |
| `-c, --config FILE` | global | Load a JSON configuration file |

## The Engine Pipeline

`pentest`/`scan` run an ordered set of phases, each gated by a config toggle and
short-circuiting when its input is absent. Run `gramfuzz modules` for the live
list; the table below mirrors [`internal/catalog`](internal/catalog/catalog.go).

| # | Phase | Toggle |
|---|---|---|
| 1-3 | Recon · OSINT · Start-param probing | `public_recon` |
| 4 | Command enumeration (ffuf-style) | `command_fuzz` |
| 5 | Injection engine (SQLi/XSS/SSTI/RCE) | `injection_fuzz` |
| 6 | Payment & logic bypass | `payment_logic` |
| 7 | Telegram platform surface | `telegram_surface` |
| 8 | Webhook & SSRF | `webhook_attack` |
| 9 | Bot API abuse | `bot_api_abuse` |
| 10 | API discovery & BOLA (dirbuster) | `bola_fuzzer` |
| 11 | Web App static analysis | `web_inspector` |
| 12 | Infrastructure audit | `public_recon` |
| 13 | Python attack runner | `public_recon` |

Findings carry a **severity** (→ risk 0-10) and a **confidence**; only
`confirmed`/`likely` items drive the headline *actionable* rating, so manual
checks never inflate the score. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Satellite Modules

Optional helpers that run independently of the Go binary — useful for live
interaction the credential-free engine can't perform on its own.

### User Simulator (Python / Telethon)

Simulates human interaction via MTProto: sends `/start`, clicks inline buttons, launches Mini Apps, and intercepts `initData`.

```bash
cd modules/user-simulator
pip install -r requirements.txt
python simulator.py --bot mybot --json
```

### Web App Inspector (TypeScript / Playwright)

Headless Mini App renderer. Intercepts Fetch/XHR, maps API routes, validates transaction payloads.

```bash
cd modules/web-inspector
npm install
npm run inspect -- --url https://myapp.example.com --json
```

### AI Payload Analyzer (Python / Local LLM)

Analyzes request/response context using a locally hosted LLM (Qwen via LM Studio). No data sent to cloud.

```bash
cd modules/ai-analyzer
python analyzer.py --json
python analyzer.py --live --endpoint http://localhost:1234/v1
```

## Configuration

Copy `configs/gramfuzz.json.example` to `gramfuzz.json` and pass it with `-c`.
The `modules` block toggles each engine phase (keys match `gramfuzz modules`):

```json
{
  "target": {
    "bot_username": "mybot",
    "web_app_url": "https://myapp.example.com",
    "backend_url": "https://api.example.com"
  },
  "modules": {
    "public_recon": true,
    "command_fuzz": true,
    "injection_fuzz": true,
    "payment_logic": true,
    "webhook_attack": true,
    "telegram_surface": true,
    "bot_api_abuse": true,
    "bola_fuzzer": true,
    "web_inspector": true,
    "user_simulator": true,
    "ai_analyzer": false
  },
  "reporter": { "format": "html", "output": "./reports" },
  "ai": { "enabled": false, "endpoint": "http://localhost:1234/v1", "model": "qwen2.5" }
}
```

## Reports

Reports are written to `--output` (default `./reports/`) with a timestamped name.
Select formats with `--format`:

- **HTML** (default) — self-contained dark-theme report with severity cards
- **JSON** — machine-readable `{summary, findings}` for CI/CD integration
- **PDF** — branded report (cover + summary + findings) with embedded logo
- **both** — HTML + JSON · **all** — HTML + JSON + PDF

## Documentation

| Doc | For |
|---|---|
| [CLAUDE.md](CLAUDE.md) | One-page orientation for contributors & AI agents |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design reference: pipeline, findings model, reporting |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [`internal/catalog`](internal/catalog/catalog.go) | The authoritative module list (edit here to add one) |

## Ethical Use

GramFuzz is an offensive security tool intended **exclusively** for authorized testing. Using it against systems without explicit written permission from the owner is **prohibited** and may be illegal.

Read [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before use.

## Author & Contact

| Role | Details |
|---|---|
| **Author & Maintainer** | [kiurakku](https://github.com/kiurakku) (The Fear) |
| **Contact** | Telegram: [@thefear007](https://t.me/thefear007) |
| **Repository** | [github.com/kiurakku/GramFuzz](https://github.com/kiurakku/GramFuzz) |

## License

[MIT License](LICENSE) with an ethical use restriction. See [LICENSE](LICENSE) for full terms.

---

<p align="center">
  <img src="src/assets/logo.png" alt="GramFuzz Logo" width="80">
  <br>
  <strong>GramFuzz</strong> — Secure Telegram, One Scan at a Time
</p>
