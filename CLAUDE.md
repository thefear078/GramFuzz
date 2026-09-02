# CLAUDE.md — Orientation for humans & AI agents

> **Read this first, once.** It is the single source of truth for *how the
> project is put together*. You should not need to reverse-engineer the
> architecture from the code or the git history to make a change. If something
> here is wrong or out of date, fix it here — don't work around it.

GramFuzz is an **ethical DAST framework for Telegram bots & Mini Apps**, written
in Go with optional Python/TypeScript helper modules. It profiles a target from
public data, runs a 13-phase pentest pipeline, scores findings, and emits
HTML/JSON/PDF reports. It never needs a bot token or API credentials to run —
everything degrades to public reconnaissance.

## The one rule that keeps this maintainable

**The module list lives in exactly one place: [`internal/catalog`](internal/catalog/catalog.go).**

Historically the list of modules was copy-pasted across the `modules` command,
the engine, the config, the example config, and the README — and they drifted.
Now `catalog.go` is authoritative and a test (`catalog_test.go`) fails the build
if the catalog and `config.ModulesConfig` disagree. When you add or rename a
module, change the catalog; the `modules` command and the docs follow.

## Repo map

| Path | Responsibility |
|---|---|
| `cmd/gramfuzz/` | Entry point. Thin `main()` → `cli.Execute()`. |
| `internal/cli/` | Arg parsing, subcommands (`scan`/`pentest`/`fuzz`/`modules`/`version`), report writing. |
| `internal/catalog/` | **Single source of truth** for the module list + drift-guard test. |
| `internal/config/` | `Config`/`ModulesConfig` structs, JSON loading, defaults. |
| `internal/pentest/` | The pipeline: `Run()` executes the 13 phases in order. |
| `internal/scanner/` | Thin façade (`scanner.New(cfg).Run(ctx)`) over `pentest`. |
| `internal/recon/` | Phases 1-3, 12: profile fetch, OSINT, start-param fuzz, infra audit, capability inference. |
| `internal/fuzz/` | Command enumeration (phase 4) and backend BOLA/IDOR (phase 10). |
| `internal/attack/` | Injection, payment logic, Telegram surface, webhook, Bot API (phases 5-9). |
| `internal/webinspect/` | Mini App static analysis (phase 11). |
| `internal/findings/` | `Finding` type, severity→risk scoring, `Summarize`, confidence model. |
| `internal/reporter/` | HTML + JSON + PDF renderers. |
| `internal/assets/` | Embedded wordlists (`//go:embed`) and logo. |
| `internal/banner/` | ASCII banner + `Version` constant. |
| `internal/term/` | ANSI color helpers (respects `NO_COLOR`). |
| `modules/` | Out-of-pipeline helpers: `user-simulator` (Python), `attack-runner` (Python), `web-inspector` (TypeScript). |
| `docs/` | [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) — deeper design reference. |

## How a scan flows

```
cli.Execute()
  └─ scanner.New(cfg).Run(ctx)
       └─ pentest.Run(ctx, cfg)
            ├─ builds Target{bot, webapp, backend, Profile}
            ├─ runs each enabled phase in order, collecting []Finding
            │    (phase gated by its ConfigKey; ctx timeout bounds the run)
            └─ prepends an ENGAGEMENT-SUMMARY finding
  └─ reporter.Write{HTML,JSON,PDF}(outputDir, findings)
```

Every phase returns `[]findings.Finding`. A finding carries a **severity**
(→ numeric risk 0-10) and a **confidence** (`confirmed`/`likely`/`manual-test`/
`playbook`/`info`). Only `confirmed`/`likely` count toward the *actionable*
rating — that separation is what keeps reports honest (a high-severity
"manual-test" item does not inflate the headline score). See
[`findings/finding.go`](internal/findings/finding.go).

## Common changes — where to touch

- **Add an engine phase/module:** add a `Module` to `internal/catalog/catalog.go`;
  add its bool to `config.ModulesConfig` (with a `json` tag); add the phase to
  the slice in `internal/pentest/engine.go`; enable it in the `pentest` command's
  block in `internal/cli/root.go` and in the defaults in `config.go`. The catalog
  test enforces the config wiring.
- **Add attack payloads:** edit the wordlists in
  `internal/assets/wordlists/*.txt`. They're embedded at build time — no code
  change needed.
- **Change report layout:** HTML/JSON in `internal/reporter/reporter.go`, PDF in
  `internal/reporter/pdf.go`.
- **Bump the version:** `Version` in `internal/banner/banner.go` (also referenced
  in the HTML/PDF footers) and add a `CHANGELOG.md` entry.

## Build, test, run

```bash
go build -o gramfuzz ./cmd/gramfuzz   # or: make build
go test ./...                         # full suite (one test hits t.me live)
go test -short ./...                  # hermetic: skips the network integration test
./gramfuzz modules                    # list capabilities (rendered from the catalog)
./gramfuzz scan                       # demo mode, no target
./gramfuzz pentest --bot mybot --format all
```

Conventions: standard library only in `main` paths (the sole third-party dep is
`gofpdf` for PDF). Keep phases side-effect-free except for HTTP GETs against the
target; never send data to third parties. `NO_COLOR` disables ANSI output.

> **Build gotcha (this machine):** if `go build` reports "not enough space on the
> disk", the C: drive is full. Point Go's cache at a drive with room, e.g.
> `export GOCACHE=/d/go-cache GOTMPDIR=/d/go-tmp`, then rebuild.

## Ethics

Authorized testing only. Every code path assumes explicit permission from the
target owner. See [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
