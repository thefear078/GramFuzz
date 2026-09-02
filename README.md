<p align="center">
  <img src="src/assets/logo.png" alt="GramFuzz Logo" width="160">
</p>

<h1 align="center">GramFuzz</h1>

<p align="center">
  <strong>Ethical DAST Framework for Telegram Bots &amp; Mini Apps</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white" alt="Go 1.23+"></a>
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
- [Modules](#modules)
- [Configuration](#configuration)
- [Reports](#reports)
- [Ethical Use](#ethical-use)
- [Author & Contact](#author--contact)
- [License](#license)

## Problems Addressed

| Vulnerability | Description |
|---|---|
| **InitData forgery** | Backend fails to validate the HMAC hash of Telegram WebApp `initData`, allowing user ID spoofing |
| **BOLA / IDOR** | Unauthorized access to other users' data via ID substitution in API requests |
| **Logic flaws** | Dialog flow errors that bypass paywalls, loyalty systems, or rate limits |
| **Web3 payload swap** | Transaction payload manipulation in TMA before wallet signing |
| **API surface leaks** | Unprotected endpoints and exposed API structure via Mini App traffic |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Engine (Go)                       │
│         Orchestration • Queues • Logging • Reports       │
├──────────────┬──────────────┬──────────────┬─────────────┤
│ User         │ Web App      │ BOLA         │ AI Payload  │
│ Simulator    │ Inspector    │ Fuzzer       │ Analyzer    │
│ (Python)     │ (TypeScript) │ (Go)         │ (Python)    │
│ Telethon     │ Playwright   │ JWT/ID swap  │ Local LLM   │
└──────────────┴──────────────┴──────────────┴─────────────┘
```

## Quick Start

### Requirements

- Go 1.23+
- Python 3.10+ (user-simulator, ai-analyzer modules)
- Node.js 18+ (web-inspector module)

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
| `gramfuzz scan` | Run a full security scan |
| `gramfuzz fuzz --backend URL` | BOLA/IDOR fuzzing against API endpoints |
| `gramfuzz modules` | List available modules |
| `gramfuzz version` | Print version |
| `--no-banner` | Suppress ASCII startup banner |
| `-c, --config FILE` | Load JSON configuration file |

## Modules

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

Copy `configs/gramfuzz.json.example` to `gramfuzz.json`:

```json
{
  "target": {
    "bot_username": "mybot",
    "web_app_url": "https://myapp.example.com",
    "backend_url": "https://api.example.com"
  },
  "modules": {
    "user_simulator": true,
    "web_inspector": true,
    "bola_fuzzer": true,
    "ai_analyzer": false
  }
}
```

## Reports

Reports are saved to `./reports/`:

- **HTML** — visual report with severity classification
- **JSON** — machine-readable format for CI/CD integration

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
