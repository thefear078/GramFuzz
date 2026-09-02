# GramFuzz Architecture

A deeper reference than [`CLAUDE.md`](../CLAUDE.md). Read that first for the
repo map and the "where do I change X" table; this document explains *why* the
pieces fit together the way they do.

## Design goals

1. **Credential-free by default.** GramFuzz must produce useful output with
   nothing but a bot username. Live modes (bot token, MTProto, LLM) are strictly
   opt-in enrichments, never prerequisites.
2. **Scoped, honest reporting.** A scanner that flags every generic vector as
   "critical" is noise. GramFuzz infers what the target *actually does* and
   separates confirmed issues from things a human must still verify.
3. **One source of truth.** Adding a capability should mean editing one list, not
   five. See [`internal/catalog`](../internal/catalog/catalog.go).
4. **Single static binary.** Go, standard library first; one vendored dependency
   (`gofpdf`). The Python/TypeScript modules are optional satellites.

## Layered view

```
┌──────────────────────────────────────────────────────────────┐
│ cmd/gramfuzz            main() → cli.Execute()                 │
├──────────────────────────────────────────────────────────────┤
│ internal/cli            commands, flags, report orchestration  │
├──────────────────────────────────────────────────────────────┤
│ internal/scanner        façade → pentest.Run()                 │
│ internal/pentest        13-phase pipeline, Target context      │
├───────────────┬───────────────┬───────────────┬───────────────┤
│ recon         │ fuzz          │ attack        │ webinspect     │
│ (1-3,12)      │ (4,10)        │ (5-9)         │ (11)           │
├───────────────┴───────────────┴───────────────┴───────────────┤
│ internal/findings       Finding, scoring, Summarize            │
│ internal/reporter       HTML · JSON · PDF                      │
│ internal/assets         embedded wordlists + logo              │
│ internal/{banner,term}  presentation                           │
└──────────────────────────────────────────────────────────────┘
    Satellites (out of pipeline):
    modules/user-simulator (Py) · attack-runner (Py) · web-inspector (TS)
```

## The pentest pipeline

`pentest.Run(ctx, cfg)` builds a `Target` (bot, webapp, backend, and — after
phase 1 — an enriched `recon.Profile`), then runs each **enabled** phase in
order. Phases are gated by a config toggle and bounded by the context timeout
(5 min for `scan`, 15 min for `pentest`). Results accumulate into `[]Finding`,
and an `ENGAGEMENT-SUMMARY` finding is prepended at the end.

| # | Phase | Package | Config toggle |
|---|---|---|---|
| 1 | Reconnaissance | `recon` | `public_recon` |
| 2 | OSINT & Attack Surface | `recon` | `public_recon` |
| 3 | Start Parameter Probing | `recon` | `public_recon` |
| 4 | Command Enumeration | `fuzz` | `command_fuzz` |
| 5 | Injection Engine | `attack` | `injection_fuzz` |
| 6 | Payment & Logic Bypass | `attack` | `payment_logic` |
| 7 | Telegram Platform Surface | `attack` | `telegram_surface` |
| 8 | Webhook & SSRF | `attack` | `webhook_attack` |
| 9 | Bot API Abuse | `attack` | `bot_api_abuse` |
| 10 | API Discovery & BOLA | `fuzz` | `bola_fuzzer` |
| 11 | Web App Static Analysis | `webinspect` | `web_inspector` |
| 12 | Infrastructure Audit | `recon` | `public_recon` |
| 13 | Python Attack Runner | (shells out) | `public_recon` |

> This table mirrors `catalog.Engine()`. If you change the pipeline, update the
> catalog and this table together — the catalog test guards the config wiring,
> but the phase order in `pentest/engine.go` is prose that a human keeps honest.

Most phases short-circuit to `nil` when their input is missing (no bot username,
no backend URL), so an under-specified target simply produces fewer findings
rather than errors.

## Capability inference (why reports are scoped)

Phase 1 fetches the public `t.me/<bot>` page and `recon.AnalyzeCapabilities`
classifies it from title/description/HTML keywords: does it take payments? have a
referral system? a Mini App? admin surface? The resulting `Capabilities`:

- drives a `RECON-ASSESSMENT` finding that tells the reader which vectors apply,
- prioritizes command/payload selection (e.g. `PriorityCommands`), and
- lets later phases skip irrelevant tests instead of emitting playbook noise.

This is the mechanism behind design goal #2. See
[`internal/recon/capabilities.go`](../internal/recon/capabilities.go).

## The Finding model

```go
type Finding struct {
    ID, Severity, Module, Category, Title, Description, Evidence string
    CWE, Remediation, RemediationPlan, PoC, Impact, Steps        string
    Confidence string   // confirmed | likely | manual-test | playbook | info
    Tags       []string
    RiskScore  int       // 0-10, derived from Severity
    Timestamp  time.Time
}
```

- **Severity → RiskScore:** critical 10, high 8, medium 5, low 2, info 1.
- **Confidence → actionability:** only `confirmed`/`likely` are *actionable*.
- **`Summarize`** computes totals, per-severity/confidence/category counts, and
  two ratings: `RiskRating` (from the raw max) and `ActionableRating` (from the
  max *actionable* risk). Reports and the CLI headline use the actionable rating.

Constructors: `New(...)` sets the base fields and score; `.WithMeta(cwe, rem, poc)`
and `.WithDetail(confidence, tags, impact, steps, plan)` layer on the rest. This
keeps call sites readable across dozens of finding definitions.

## Reporting

`reporter` writes to `--output` (default `./reports`) as timestamped files:

- **HTML** — self-contained dark-theme report; executive summary + per-finding
  cards colored by severity.
- **JSON** — `{summary, findings}`; the machine-readable contract for CI/CD.
- **PDF** — branded cover + summary + findings, via `gofpdf`, logo embedded from
  `internal/assets`.

`--format` selects `html` (default), `json`, `pdf`, `both` (HTML+JSON), or `all`.

## Satellite modules

Optional, independently runnable, and **not** required by the Go pipeline:

- **`modules/user-simulator`** (Python/Telethon) — public recon plus, when
  `TELEGRAM_API_ID/HASH` are set, live MTProto interaction and `initData` HMAC
  checks. Phase 13 of the Go engine shells out to the sibling `attack-runner`.
- **`modules/attack-runner`** (Python) — auxiliary payload generation inspired by
  sqlmap/ffuf/nmap/nuclei patterns; invoked by phase 13 when Python is present.
- **`modules/web-inspector`** (TypeScript/Playwright) — headless Mini App
  rendering, Fetch/XHR interception, transaction-payload validation. The Go
  `webinspect` package covers the static-analysis subset without a browser.

## Testing & CI

- `go test ./...` runs everything; `TestFetchProfileIntegration` performs a live
  `t.me` fetch and is skipped under `-short`. **CI uses `-short`** for hermetic
  runs; run the full suite locally when touching `recon`.
- The catalog drift-guard (`internal/catalog/catalog_test.go`) is the safety net
  for the "one source of truth" goal — it cannot be satisfied by documentation
  alone, so it cannot silently rot.
