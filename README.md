# GramFuzz

![GramFuzz Banner](src/assets/banner.png)

**Ethical DAST Framework for Telegram Bots & Mini Apps**

GramFuzz — потужний фреймворк динамічного тестування безпеки (DAST), розроблений для екосистеми Telegram. Призначений **виключно** для легального пентесту та аудиту безпеки.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red)](SECURITY.md)

---

## Проблеми, які вирішує GramFuzz

| Вразливість | Опис |
|---|---|
| **InitData forgery** | Відсутня валідація HMAC-хешу initData на бекенді |
| **BOLA / IDOR** | Несанкціонований доступ через підміну user ID |
| **Logic flaws** | Обхід платіжних стін, систем лояльності |
| **Web3 payload swap** | Підміна транзакційного payload перед підписом гаманцем |
| **API surface leaks** | Незахищені ендпоінти, витік структури API |

## Архітектура

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

## Швидкий старт

### Вимоги

- Go 1.23+
- Python 3.10+ (для модулів user-simulator, ai-analyzer)
- Node.js 18+ (для web-inspector)

### Збірка та запуск

```bash
# Клонування
git clone https://github.com/kiurakku/GramFuzz.git
cd GramFuzz

# Збірка CLI
go build -o gramfuzz ./cmd/gramfuzz

# Перегляд банера та модулів
./gramfuzz modules

# Демо-скан (без цілі)
./gramfuzz scan

# Повний скан з ціллю
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

## CLI Команди

| Команда | Опис |
|---|---|
| `gramfuzz scan` | Повний скан безпеки |
| `gramfuzz fuzz --backend URL` | BOLA/IDOR фаззинг |
| `gramfuzz modules` | Список модулів |
| `gramfuzz version` | Версія |
| `--no-banner` | Приховати ASCII-банер |
| `-c, --config` | JSON конфігурація |

## Модулі

### User Simulator (Python)

```bash
cd modules/user-simulator
pip install -r requirements.txt
python simulator.py --bot mybot --json
```

### Web App Inspector (TypeScript)

```bash
cd modules/web-inspector
npm install
npm run inspect -- --url https://myapp.example.com --json
```

### AI Payload Analyzer (Python)

```bash
cd modules/ai-analyzer
python analyzer.py --json
python analyzer.py --live --endpoint http://localhost:1234/v1
```

## Конфігурація

Скопіюйте `configs/gramfuzz.json.example` → `gramfuzz.json`:

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

## Звіти

Звіти зберігаються в `./reports/`:

- **HTML** — візуальний звіт з severity-класифікацією
- **JSON** — машиночитаний формат для CI/CD інтеграції

## Етичне використання

> **УВАГА:** GramFuzz призначений **виключно** для авторизованого тестування безпеки.
> Використання проти систем без явного письмового дозволу власника **заборонено** та може бути незаконним.

Див. [SECURITY.md](SECURITY.md) та [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Ліцензія

[MIT License](LICENSE) — з обмеженням на етичне використання.

---

<p align="center">
  <img src="src/assets/logo.png" alt="GramFuzz Logo" width="120">
  <br>
  <strong>GramFuzz</strong> — Secure Telegram, One Scan at a Time
</p>
