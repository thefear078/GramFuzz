package fuzz

import (
	"fmt"
	"strings"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/recon"
)

// CommandVectors generates prioritized command tests scoped to this bot's profile.
func CommandVectors(username string, profile *recon.Profile) []findings.Finding {
	username = strings.TrimPrefix(username, "@")
	caps := recon.AnalyzeCapabilities(profile)
	allCommands := parseWL(assets.CommandsWordlist)
	priority := recon.PriorityCommands(caps, allCommands)

	var list []findings.Finding
	list = append(list, findings.New(
		"CMD-SCOPE", "info", "command-fuzzer", "authz",
		"Command enumeration scoped to target bot",
		fmt.Sprintf("Full wordlist contains %d commands; %d priority probes selected based on @%s public profile. Remaining entries were not reported to reduce noise.", len(allCommands), len(priority), username),
		fmt.Sprintf("/admin, /debug, /help — test manually in Telegram chat with @%s", username),
	).WithDetail(
		findings.ConfidenceInfo,
		[]string{"commands", "scoped", "manual-test"},
		"Hidden admin/debug commands may expose sensitive operations if RBAC is missing.",
		fmt.Sprintf("1. Open chat with @%s\n2. Send each priority command below\n3. Note responses, errors, or data leaks", username),
		"1. Hide admin commands from help menu\n2. Enforce role checks on every handler\n3. Disable debug in production builds",
	))

	for i, cmd := range priority {
		sev := "medium"
		if cmd == "start" || cmd == "help" || cmd == "menu" {
			sev = "low"
		}
		list = append(list, findings.New(
			fmt.Sprintf("CMD-TEST-%02d", i+1), sev, "command-fuzzer", "authz",
			fmt.Sprintf("Manual test: /%s", cmd),
			describeCommandRisk(cmd, caps),
			fmt.Sprintf("/%s  |  /%s@%s", cmd, cmd, username),
		).WithMeta("CWE-862", "Allowlist commands per user role; never expose debug handlers publicly.", "/"+cmd).
			WithDetail(
				findings.ConfidenceManual,
				[]string{"command", cmd, "manual-test"},
				commandImpact(cmd),
				fmt.Sprintf("Send /%s to @%s in Telegram and record the full response.", cmd, username),
				"Restrict handler to authorized Telegram user IDs; return generic error for unauthorized access.",
			))
	}

	// Callback forgery — one consolidated item, not 24 separate findings.
	callbacks := parseWL(assets.CallbackWordlist)
	if len(callbacks) > 0 {
		sample := callbacks[0]
		if len(callbacks) > 3 {
			sample = strings.Join(callbacks[:3], ", ") + ", ..."
		} else {
			sample = strings.Join(callbacks, ", ")
		}
		list = append(list, findings.New(
			"CB-MANUAL", "medium", "command-fuzzer", "injection",
			"Inline callback_data forgery (manual test)",
			fmt.Sprintf("If the bot uses inline keyboards, replay or mutate callback_data (%d patterns in wordlist). Sample: %s", len(callbacks), sample),
			sample,
		).WithMeta("CWE-20", "Sign callback_data with HMAC; validate on server.", sample).
			WithDetail(
				findings.ConfidenceManual,
				[]string{"callback", "inline-keyboard", "manual-test"},
				"Forged callbacks may bypass payment steps or access other users' actions (IDOR).",
				"1. Interact with bot buttons\n2. Capture callback_data (MTProto or logs)\n3. Replay with modified IDs/amounts",
				"Sign payloads; bind to user ID and message ID; expire tokens.",
			))
	}

	return list
}

func describeCommandRisk(cmd string, caps recon.Capabilities) string {
	switch cmd {
	case "admin", "debug", "config", "root", "shell", "exec":
		return "High-value admin/debug command — verify it is restricted to authorized operators only."
	case "export", "backup", "dump", "users":
		return "Data export command — confirm it cannot be triggered by regular users."
	default:
		if caps.HasPayment && (cmd == "balance" || cmd == "pay" || cmd == "wallet") {
			return "Payment-related command — verify amounts cannot be manipulated via arguments."
		}
		return "Standard command probe — check for information disclosure in response."
	}
}

func commandImpact(cmd string) string {
	switch cmd {
	case "admin", "debug", "config":
		return "Unauthorized access to bot administration, logs, or configuration."
	case "export", "backup", "dump":
		return "Mass data exfiltration from bot database or files."
	case "shell", "exec":
		return "Remote code execution if command passes input to system shell."
	default:
		return "Information disclosure or unauthorized feature access."
	}
}

func parseWL(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
