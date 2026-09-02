package recon

import (
	"fmt"
	"strings"
)

// Capabilities describes what the target bot likely implements, inferred from public data.
type Capabilities struct {
	BotType         string
	Title           string
	Description     string
	HasPayment      bool
	HasReferral     bool
	HasSubscription bool
	HasStars        bool
	HasVIP          bool
	HasWebApp       bool
	HasBackend      bool
	HasInlineMode   bool
	ExternalURLs    []string
	Keywords        []string
	AttackSurface   []string
	Limitations     []string
}

var (
	paymentKW  = []string{"pay", "payment", "invoice", "buy", "purchase", "price", "checkout", "wallet", "crypto", "ton", "stars", "premium", "vip", "coupon", "discount", "balance", "topup", "top-up", "donate"}
	referralKW = []string{"ref", "referral", "invite", "partner", "affiliate", "bonus", "reward"}
	subKW      = []string{"subscribe", "subscription", "plan", "tier", "membership"}
	adminKW    = []string{"admin", "debug", "config", "manage", "panel", "staff", "moderator"}
)

// AnalyzeCapabilities builds a bot-specific attack surface map from public profile data.
func AnalyzeCapabilities(profile *Profile) Capabilities {
	c := Capabilities{
		BotType:  "classic",
		Keywords: []string{},
		Limitations: []string{
			"Live Bot API probing skipped without BOT_TOKEN",
			"Command handler responses require manual Telegram interaction",
		},
	}
	if profile == nil {
		c.Limitations = append(c.Limitations, "Public profile unavailable — capabilities inferred only from username")
		return c
	}

	c.Title = profile.Title
	c.Description = profile.Description
	c.ExternalURLs = append([]string{}, profile.ExternalURLs...)
	c.HasWebApp = profile.HasWebApp
	c.HasBackend = len(profile.ExternalURLs) > 0
	if profile.HasWebApp {
		c.BotType = "mini-app"
	}

	text := strings.ToLower(profile.Title + " " + profile.Description + " " + profile.RawHTML)
	for _, kw := range paymentKW {
		if strings.Contains(text, kw) {
			c.HasPayment = true
			c.Keywords = appendUnique(c.Keywords, kw)
		}
	}
	for _, kw := range referralKW {
		if strings.Contains(text, kw) {
			c.HasReferral = true
			c.Keywords = appendUnique(c.Keywords, kw)
		}
	}
	for _, kw := range subKW {
		if strings.Contains(text, kw) {
			c.HasSubscription = true
			c.Keywords = appendUnique(c.Keywords, kw)
		}
	}
	if strings.Contains(text, "star") {
		c.HasStars = true
	}
	if strings.Contains(text, "vip") || strings.Contains(text, "premium") {
		c.HasVIP = true
	}

	c.AttackSurface = buildAttackSurface(c, profile)
	return c
}

func buildAttackSurface(c Capabilities, p *Profile) []string {
	var s []string
	s = append(s, "/start deep link parameters (always present for Telegram bots)")
	if c.HasReferral {
		s = append(s, "Referral / invite codes in ?start= payload")
	}
	if c.HasPayment || c.HasStars || c.HasVIP {
		s = append(s, "Payment or monetization flow (verify amount validation server-side)")
	} else {
		s = append(s, "No payment keywords in public profile — Stars/TON/coupon tests not applicable")
	}
	if c.HasSubscription {
		s = append(s, "Subscription tier logic")
	}
	if c.HasWebApp {
		s = append(s, "Telegram Mini App (WebView) — client-side secrets and initData validation")
	}
	if c.HasBackend {
		s = append(s, fmt.Sprintf("Linked infrastructure (%d external URL(s))", len(c.ExternalURLs)))
	} else {
		s = append(s, "No public backend URL — API dirbuster and webhook live probes skipped")
	}
	if p.HasStartBtn {
		s = append(s, "Public Start button — entry point for /start handler fuzzing")
	}
	return s
}

// PriorityCommands returns admin-sensitive commands to manually test for this bot.
func PriorityCommands(c Capabilities, wordlist []string) []string {
	seen := map[string]bool{}
	var out []string

	add := func(cmd string) {
		cmd = strings.TrimPrefix(strings.TrimSpace(cmd), "/")
		if cmd == "" || seen[cmd] {
			return
		}
		seen[cmd] = true
		out = append(out, cmd)
	}

	text := strings.ToLower(c.Title + " " + c.Description)
	for _, kw := range adminKW {
		if strings.Contains(text, kw) {
			add(kw)
		}
	}
	for _, cmd := range []string{"start", "help", "admin", "debug", "settings", "profile", "status", "menu"} {
		add(cmd)
	}
	for _, cmd := range wordlist {
		if len(out) >= 15 {
			break
		}
		switch cmd {
		case "admin", "debug", "config", "token", "secret", "dump", "shell", "exec", "root", "env", "backup", "export", "users", "ban", "stats":
			add(cmd)
		}
	}
	return out
}

// AssessmentText returns a human-readable bot assessment block for reports.
func (c Capabilities) AssessmentText(username string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: @%s\n", username)
	fmt.Fprintf(&b, "Type: %s\n", c.BotType)
	if c.Title != "" {
		fmt.Fprintf(&b, "Title: %s\n", c.Title)
	}
	if c.Description != "" {
		desc := c.Description
		if len(desc) > 280 {
			desc = desc[:280] + "..."
		}
		fmt.Fprintf(&b, "Description: %s\n", desc)
	}
	if len(c.Keywords) > 0 {
		fmt.Fprintf(&b, "Detected themes: %s\n", strings.Join(c.Keywords, ", "))
	} else {
		b.WriteString("Detected themes: none from public text (generic bot surface only)\n")
	}
	b.WriteString("\nRelevant attack surface:\n")
	for _, a := range c.AttackSurface {
		fmt.Fprintf(&b, "  • %s\n", a)
	}
	if len(c.Limitations) > 0 {
		b.WriteString("\nScan limitations:\n")
		for _, l := range c.Limitations {
			fmt.Fprintf(&b, "  • %s\n", l)
		}
	}
	return b.String()
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
