package recon

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/findings"
)

var (
	emailRe     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRe     = regexp.MustCompile(`\+\d{10,15}`)
	domainRe    = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:\.[a-z]{2,})?)`)
	ipRe        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	webAppURLRe = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+\.(?:app|dev|io|com|xyz|site|page)[^\s"'<>]*)`)
)

// ScanProfile performs initial profile reconnaissance.
func ScanProfile(ctx context.Context, username string, profile *Profile, fetchErr error) []findings.Finding {
	username = normalizeUsername(username)
	now := time.Now()
	if fetchErr != nil {
		return []findings.Finding{findings.New(
			"RECON-ERR", "high", "public-recon", "recon",
			"Failed to fetch public bot profile", fetchErr.Error(),
			fmt.Sprintf("https://t.me/%s", username),
		).WithMeta("CWE-200", "Verify bot username is correct and publicly accessible.", "")}
	}

	var list []findings.Finding
	list = append(list, findings.New(
		"RECON-001", "info", "public-recon", "recon",
		"Target profile enumerated",
		fmt.Sprintf("Bot type: %s | Title: %s", profile.BotType(), profile.Title),
		fmt.Sprintf("https://t.me/%s", username),
	))

	if profile.BotType() == "classic" {
		list = append(list, findings.New(
			"RECON-002", "info", "public-recon", "recon",
			"Classic Telegram bot (no Mini App)",
			"Attack surface: /start payloads, command handlers, inline keyboards, referral logic, callback_data.",
			"No Mini App markers detected",
		).WithMeta("", "Focus on logic flaws, authorization in commands, and referral abuse.", ""))
	}

	for _, s := range ScanSecrets(profile.RawHTML) {
		list = append(list, findings.New(
			fmt.Sprintf("RECON-SEC-%s", strings.ToUpper(s.Type)), s.Severity, "public-recon", "secrets",
			fmt.Sprintf("Credential leak: %s", s.Type),
			"Sensitive pattern found in publicly accessible page.",
			s.Value,
		).WithMeta("CWE-798", "Rotate exposed credentials immediately; remove secrets from public pages.", s.Value))
	}

	if profile.Description != "" {
		list = append(list, findings.New(
			"RECON-003", "info", "public-recon", "recon",
			"Bot description collected", profile.Description, profile.Description,
		))
	}

	if len(profile.ExternalURLs) == 0 {
		list = append(list, findings.New(
			"RECON-004", "info", "public-recon", "recon",
			"No external links on public profile",
			"Infrastructure discovery limited to Telegram-native attack surface.",
			"t.me profile",
		))
	}

	_ = now
	_ = ctx
	return list
}

// ScanOSINT extracts OSINT data and maps attack surface.
func ScanOSINT(ctx context.Context, username string, profile *Profile) []findings.Finding {
	if profile == nil {
		var err error
		profile, err = FetchProfile(ctx, username)
		if err != nil {
			return nil
		}
	}

	var list []findings.Finding
	text := profile.RawHTML + " " + profile.Description

	emails := uniqueMatches(emailRe.FindAllString(text, -1))
	for _, e := range emails {
		list = append(list, findings.New(
			"OSINT-EMAIL", "low", "public-recon", "osint",
			"Email address exposed in public profile",
			"May be used for social engineering or credential stuffing.",
			e,
		).WithMeta("CWE-200", "Remove personal emails from public bot descriptions.", e))
	}

	phones := uniqueMatches(phoneRe.FindAllString(text, -1))
	for _, p := range phones {
		list = append(list, findings.New(
			"OSINT-PHONE", "low", "public-recon", "osint",
			"Phone number exposed in public profile", p, p,
		))
	}

	domains := extractMeaningfulDomains(profile)
	for _, d := range domains {
		list = append(list, findings.New(
			"OSINT-DOMAIN", "info", "public-recon", "osint",
			"Infrastructure domain discovered",
			"Domain may host bot backend API. Probe with --backend flag.",
			d,
		).WithMeta("CWE-200", "Ensure backend APIs require authentication and are not publicly enumerable.", "https://"+d))
	}

	if wu := webAppURLRe.FindString(text); wu != "" {
		profile.WebAppURL = wu
		list = append(list, findings.New(
			"OSINT-WEBAPP", "info", "public-recon", "osint",
			"Mini App URL discovered in profile",
			"Auto-detected web app URL for Phase 6 analysis.",
			wu,
		))
	}

	// Deep link attack surface
	deepLinks := []struct{ name, url, desc string }{
		{"start", fmt.Sprintf("https://t.me/%s?start=PAYLOAD", username), "Referral / deep link injection"},
		{"startgroup", fmt.Sprintf("https://t.me/%s?startgroup=PAYLOAD", username), "Group add deep link abuse"},
		{"share", "https://t.me/share/url?url=PAYLOAD", "Share URL injection"},
	}
	for _, dl := range deepLinks {
		list = append(list, findings.New(
			"OSINT-DEEPLINK-"+strings.ToUpper(dl.name), "info", "public-recon", "surface",
			fmt.Sprintf("Deep link vector: %s", dl.name),
			dl.desc,
			dl.url,
		).WithMeta("CWE-20", "Validate and sanitize all deep link parameters server-side.", dl.url))
	}

	// Typosquatting awareness (limited variants)
	base := strings.TrimSuffix(strings.ToLower(username), "bot")
	variants := []string{}
	if base != username {
		variants = append(variants, base)
	}
	if !strings.HasSuffix(strings.ToLower(username), "bot") {
		variants = append(variants, username+"bot")
	}
	for _, v := range variants {
		list = append(list, findings.New(
			"OSINT-TYPOSQUAT", "low", "public-recon", "osint",
			fmt.Sprintf("Similar username variant: @%s", v),
			"Check if typosquatting bots impersonate this bot to phish users.",
			fmt.Sprintf("https://t.me/%s", v),
		))
	}

	return list
}

// ScanStartParams runs active start-parameter probing with reflection detection.
func ScanStartParams(ctx context.Context, username string) []findings.Finding {
	results, vectors := TestStartParams(ctx, username)
	var list []findings.Finding

	unsafeReflection := 0
	for _, r := range results {
		if r.Reflected && !r.EncodedSafe {
			unsafeReflection++
		}
	}

	for _, v := range vectors {
		sev := v.Severity
		desc := v.Description

		// Elevate if we found matching reflection result
		for _, r := range results {
			if r.Payload == v.Name && r.Reflected && !r.EncodedSafe {
				sev = "high"
				desc += " | ACTIVE: Payload reflected unsafely in t.me page HTML"
			}
		}

		list = append(list, findings.New(
			v.ID, sev, "start-fuzzer", "injection",
			fmt.Sprintf("Start param vector: %s", v.Name),
			desc,
			v.PoCLink,
		).WithMeta("CWE-20", "Validate start parameters; use allowlists; never pass raw input to SQL/shell.", v.PoCLink))
	}

	if unsafeReflection > 0 {
		list = append(list, findings.New(
			"START-REFLECT", "high", "start-fuzzer", "injection",
			"Unsafe parameter reflection on t.me landing page",
			fmt.Sprintf("%d payload(s) reflected without encoding in public HTML.", unsafeReflection),
			fmt.Sprintf("https://t.me/%s?start=PAYLOAD", username),
		).WithMeta("CWE-79", "Ensure all user input is HTML-encoded before rendering.", ""))
	}

	return list
}

// ScanInfrastructure audits linked infrastructure.
func ScanInfrastructure(ctx context.Context, urls []string) []findings.Finding {
	audits, webhooks := AuditLinks(ctx, urls)
	var list []findings.Finding

	for _, a := range audits {
		if len(a.Findings) == 0 {
			continue
		}
		sev := "low"
		if !a.IsHTTPS {
			sev = "medium"
		}
		for _, f := range a.Findings {
			if strings.Contains(f, "CORS") {
				sev = "medium"
			}
		}
		list = append(list, findings.New(
			"INFRA-LINK", sev, "infra-audit", "config",
			"Linked infrastructure security issue",
			strings.Join(a.Findings, "; "),
			a.URL,
		).WithMeta("CWE-16", "Enable HSTS, X-Frame-Options, and restrict CORS origins.", a.URL))
	}

	for _, w := range webhooks {
		list = append(list, findings.New(
			"INFRA-WEBHOOK", "high", "infra-audit", "exposure",
			"Exposed webhook endpoint discovered",
			w.Note,
			fmt.Sprintf("%s → HTTP %d", w.URL, w.StatusCode),
		).WithMeta("CWE-306", "Protect webhook endpoints with secret tokens; validate Telegram IP ranges.", w.URL))
	}

	return list
}

// GuessBackendURL tries to infer backend URL from profile external links only.
func GuessBackendURL(profile *Profile) string {
	for _, u := range profile.ExternalURLs {
		lower := strings.ToLower(u)
		if strings.Contains(lower, "api.") || strings.Contains(lower, "/api") {
			return u
		}
	}
	for _, u := range profile.ExternalURLs {
		return u
	}
	return ""
}

func extractMeaningfulDomains(profile *Profile) []string {
	skip := map[string]bool{
		"telegram.org": true, "t.me": true, "telesco.pe": true, "w3.org": true,
		"xmlns": true, "http": true, "https": true, "example.com": true,
	}
	var candidates []string
	for _, u := range profile.ExternalURLs {
		if h := extractHost(u); h != "" && !skip[h] {
			candidates = append(candidates, h)
		}
	}
	if profile.Description != "" {
		for _, m := range domainRe.FindAllString(profile.Description, -1) {
			d := strings.TrimPrefix(strings.TrimPrefix(m, "https://"), "http://")
			if idx := strings.Index(d, "/"); idx > 0 {
				d = d[:idx]
			}
			if d != "" && !skip[d] && !strings.HasSuffix(d, ".css") && !strings.HasSuffix(d, ".js") {
				candidates = append(candidates, d)
			}
		}
	}
	return uniqueMatches(candidates)
}

func uniqueMatches(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range items {
		i = strings.TrimSpace(i)
		if i != "" && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}

// Scan is the legacy entry point — delegates to full pentest phases.
func Scan(ctx context.Context, username string) []findings.Finding {
	profile, err := FetchProfile(ctx, username)
	var all []findings.Finding
	all = append(all, ScanProfile(ctx, username, profile, err)...)
	if profile != nil {
		all = append(all, ScanOSINT(ctx, username, profile)...)
		all = append(all, ScanStartParams(ctx, username)...)
		if len(profile.ExternalURLs) > 0 {
			all = append(all, ScanInfrastructure(ctx, profile.ExternalURLs)...)
		}
	}
	return all
}
