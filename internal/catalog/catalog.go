// Package catalog is the single source of truth for GramFuzz's modules.
//
// Every module the engine can run — and every auxiliary component — is
// declared exactly once, here. The `gramfuzz modules` command renders this
// list, the documentation tables are generated from it, and a drift-guard
// test (catalog_test.go) fails the build if a module here references a config
// key that does not exist, or if a config toggle has no module describing it.
//
// To add a capability, add ONE Module entry below (and, for an engine module,
// the matching bool in config.ModulesConfig and the phase in pentest/engine.go).
// Nothing else needs to know the full list.
package catalog

import "sort"

// Kind distinguishes pipeline phases from auxiliary components.
type Kind string

const (
	// KindEngine is a phase in the Go pentest pipeline (pentest/engine.go).
	KindEngine Kind = "engine"
	// KindAuxiliary is an out-of-pipeline helper (external language module,
	// reporter, etc.) that is not a numbered phase.
	KindAuxiliary Kind = "auxiliary"
)

// Module describes one GramFuzz capability.
type Module struct {
	ID   string // stable slug, e.g. "public-recon"
	Name string // human label, e.g. "Public Recon"
	Lang string // implementation language: "Go", "Python", "TypeScript"
	Kind Kind

	// ConfigKey is the JSON key in config.ModulesConfig that toggles this
	// module, or "" for components that are always on (reporters, banner).
	ConfigKey string

	// Phase is the 1-based position in the pentest pipeline for KindEngine
	// modules, or 0 for auxiliary components. Several phases may share a
	// ConfigKey (e.g. recon phases all gate on "public_recon").
	Phase int

	Summary string
}

// modules is the authoritative, ordered list. Engine phases first (by Phase),
// auxiliary components after.
var modules = []Module{
	{ID: "public-recon", Name: "Public Recon", Lang: "Go", Kind: KindEngine, ConfigKey: "public_recon", Phase: 1,
		Summary: "t.me profiling, leaked-secret scan, bot classification (classic vs Mini App)."},
	{ID: "osint", Name: "OSINT & Attack Surface", Lang: "Go", Kind: KindEngine, ConfigKey: "public_recon", Phase: 2,
		Summary: "Domain/email/IP extraction, deep links, typosquatting, external URL discovery."},
	{ID: "start-fuzz", Name: "Start Parameter Probing", Lang: "Go", Kind: KindEngine, ConfigKey: "public_recon", Phase: 3,
		Summary: "40+ deep-link (?start=) injection probes with reflection detection."},
	{ID: "command-fuzz", Name: "Command Enumeration", Lang: "Go", Kind: KindEngine, ConfigKey: "command_fuzz", Phase: 4,
		Summary: "150+ command probes from an ffuf/dirbuster-style wordlist, capability-scoped."},
	{ID: "injection", Name: "Injection Engine", Lang: "Go", Kind: KindEngine, ConfigKey: "injection_fuzz", Phase: 5,
		Summary: "SQLi / XSS / SSTI / RCE payloads (sqlmap-inspired), scoped to the bot's surface."},
	{ID: "payment-logic", Name: "Payment & Logic Bypass", Lang: "Go", Kind: KindEngine, ConfigKey: "payment_logic", Phase: 6,
		Summary: "Financial bypass, coupon abuse, TON/Stars transaction-logic vectors."},
	{ID: "telegram-surface", Name: "Telegram Platform Surface", Lang: "Go", Kind: KindEngine, ConfigKey: "telegram_surface", Phase: 7,
		Summary: "Platform-specific checks: inline mode, login_url, games, callback_data."},
	{ID: "webhook-attack", Name: "Webhook & SSRF Attacks", Lang: "Go", Kind: KindEngine, ConfigKey: "webhook_attack", Phase: 8,
		Summary: "SSRF, replay, and secret_token bypass probing (nuclei-style) against webhooks."},
	{ID: "bot-api-abuse", Name: "Bot API Abuse", Lang: "Go", Kind: KindEngine, ConfigKey: "bot_api_abuse", Phase: 9,
		Summary: "getMe / getUpdates / getWebhookInfo probing for token & config exposure."},
	{ID: "bola-fuzzer", Name: "API Discovery & BOLA", Lang: "Go", Kind: KindEngine, ConfigKey: "bola_fuzzer", Phase: 10,
		Summary: "90+ API paths + IDOR + auth-header bypass (dirbuster-style) against a backend."},
	{ID: "web-inspector", Name: "Web App Static Analysis", Lang: "Go", Kind: KindEngine, ConfigKey: "web_inspector", Phase: 11,
		Summary: "Mini App static analysis: exposed secrets, JWT handling, CSP weaknesses."},
	{ID: "infra-audit", Name: "Infrastructure Audit", Lang: "Go", Kind: KindEngine, ConfigKey: "public_recon", Phase: 12,
		Summary: "Security-header and TLS audit of discovered external domains."},
	{ID: "attack-runner", Name: "Python Attack Runner", Lang: "Python", Kind: KindEngine, ConfigKey: "public_recon", Phase: 13,
		Summary: "Auxiliary payload generation (sqlmap/nmap/ffuf/nuclei-inspired); optional."},

	{ID: "user-simulator", Name: "User Simulator", Lang: "Python", Kind: KindAuxiliary, ConfigKey: "user_simulator", Phase: 0,
		Summary: "Public recon + optional MTProto live mode (Telethon): /start, buttons, initData."},
	{ID: "ai-analyzer", Name: "AI Payload Analyzer", Lang: "Python", Kind: KindAuxiliary, ConfigKey: "ai_analyzer", Phase: 0,
		Summary: "Context analysis via a locally hosted LLM (LM Studio); no data leaves the host."},
	{ID: "reporter", Name: "Reporter (HTML/JSON/PDF)", Lang: "Go", Kind: KindAuxiliary, ConfigKey: "", Phase: 0,
		Summary: "Always-on. Branded HTML, machine-readable JSON, and PDF reports with risk scoring."},
}

// All returns the modules in canonical order: engine phases by Phase, then
// auxiliary components in declaration order.
func All() []Module {
	out := make([]Module, len(modules))
	copy(out, modules)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == KindEngine
		}
		return out[i].Phase < out[j].Phase
	})
	return out
}

// Engine returns only pipeline-phase modules, ordered by Phase.
func Engine() []Module {
	var out []Module
	for _, m := range All() {
		if m.Kind == KindEngine {
			out = append(out, m)
		}
	}
	return out
}

// Auxiliary returns only out-of-pipeline components.
func Auxiliary() []Module {
	var out []Module
	for _, m := range All() {
		if m.Kind == KindAuxiliary {
			out = append(out, m)
		}
	}
	return out
}

// ConfigKeys returns the set of distinct config keys referenced by modules.
func ConfigKeys() map[string]bool {
	keys := map[string]bool{}
	for _, m := range modules {
		if m.ConfigKey != "" {
			keys[m.ConfigKey] = true
		}
	}
	return keys
}
