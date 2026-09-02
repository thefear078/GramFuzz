package fuzz

import (
	"fmt"
	"strings"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/recon"
)

// CommandVectors generates command and callback fuzzing from embedded wordlists.
func CommandVectors(username string, profile *recon.Profile) []findings.Finding {
	username = strings.TrimPrefix(username, "@")
	commands := parseWL(assets.CommandsWordlist)
	callbacks := parseWL(assets.CallbackWordlist)

	var list []findings.Finding
	list = append(list, findings.New(
		"CMD-PLAYBOOK", "high", "command-fuzzer", "authz",
		"Command enumeration attack playbook (ffuf/dirbuster-style)",
		fmt.Sprintf("%d commands + %d callback payloads to test on @%s", len(commands), len(callbacks), username),
		"Send each /command in Telegram; fuzz every inline button callback_data",
	).WithMeta("CWE-862", "Hide admin commands; enforce RBAC; disable debug in production.", ""))

	for i, cmd := range commands {
		sev := "low"
		switch cmd {
		case "admin", "debug", "token", "secret", "dump", "shell", "exec", "root", "env", "config", "backup", "export":
			sev = "medium"
		}
		list = append(list, findings.New(
			fmt.Sprintf("CMD-%04d", i+1), sev, "command-fuzzer", "authz",
			fmt.Sprintf("Probe command: /%s", cmd),
			"Unauthorized command may expose admin panel, debug output, or sensitive operations.",
			fmt.Sprintf("/%s  |  /%s@%s", cmd, cmd, username),
		).WithMeta("CWE-862", "Allowlist commands per user role.", "/"+cmd))
	}

	for i, cb := range callbacks {
		list = append(list, findings.New(
			fmt.Sprintf("CB-%03d", i+1), "medium", "command-fuzzer", "injection",
			"Inline callback_data forgery",
			"Replay or mutate callback_data to bypass button authorization.",
			cb,
		).WithMeta("CWE-20", "Sign callback_data with HMAC; validate on server.", cb))
	}

	_ = profile
	return list
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
