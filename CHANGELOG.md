# Changelog

All notable changes to GramFuzz are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Single-source-of-truth module catalog** (`internal/catalog`). Every module is
  declared once; the `modules` command renders from it.
- **Drift-guard tests** (`internal/catalog/catalog_test.go`): the build fails if
  the catalog and `config.ModulesConfig` ever disagree, so the module list can no
  longer silently rot.
- **`findings` unit tests**: severity scoring, rating thresholds, and the
  actionable-vs-manual summary contract.
- **Developer docs**: [`CLAUDE.md`](CLAUDE.md) orientation file and
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) design reference, so contributors
  (human or AI) no longer reverse-engineer the design from code or git history.

### Changed
- `modules` command now shows the engine pipeline with phase numbers and the
  config toggle that gates each module, plus auxiliary components.
- README architecture and module/CLI tables rewritten to match the actual
  13-phase Go engine (previously described a different 4-module design).
- `configs/gramfuzz.json.example` now lists every module toggle.
- CI runs `go test -short` for hermetic builds (the live `t.me` integration test
  no longer gates CI on network reachability).

## [0.4.0]

### Added
- Scoped bot reports driven by capability inference (`RECON-ASSESSMENT`).
- CI now uploads Linux and Windows binary artifacts.

### Fixed
- PDF report rendering.

## [0.3.0]

### Added
- Credential-free pentest engine (runs on a bot username alone).
- PDF reports with embedded branding.
- Attack wordlists embedded via `//go:embed`.

## [0.1.0]

### Added
- Initial release: GramFuzz ethical DAST framework for Telegram bots.

[Unreleased]: https://github.com/kiurakku/GramFuzz/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/kiurakku/GramFuzz/releases/tag/v0.4.0
[0.3.0]: https://github.com/kiurakku/GramFuzz/releases/tag/v0.3.0
[0.1.0]: https://github.com/kiurakku/GramFuzz/releases/tag/v0.1.0
