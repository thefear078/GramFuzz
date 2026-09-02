package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
)

var (
	platformDeepLinkRe = regexp.MustCompile(`(?i)(tg://resolve\?domain=[^&]+&start=|path_full:\\?"/[^"]+\?start=|al:(?:ios|android):url" content="tg://resolve)`)
	dangerousCharsRe   = regexp.MustCompile(`[<>"'&\\()]`)
)

type startProbe struct {
	name, payload, category string
}

func loadStartProbes() []startProbe {
	var out []startProbe
	for i, line := range strings.Split(assets.StartPayloadsWordlist, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cat := "generic"
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "ref"), strings.Contains(lower, "invite"):
			cat = "referral"
		case strings.Contains(lower, "pay"), strings.Contains(lower, "star"), strings.Contains(lower, "vip"):
			cat = "payment"
		case strings.Contains(lower, "script"), strings.Contains(lower, "alert"), strings.Contains(lower, "'"):
			cat = "injection"
		case len(line) <= 16 && dangerousCharsRe.MatchString(line) == false:
			cat = "authz"
		}
		out = append(out, startProbe{
			name:     fmt.Sprintf("probe_%03d", i+1),
			payload:  line,
			category: cat,
		})
	}
	return out
}

// StartParamResult holds reflection analysis for a start payload.
type StartParamResult struct {
	Payload      string
	Reflected    bool
	PlatformOnly bool
	Dangerous    bool
	DeepLink     string
}

// TestStartParams probes how t.me reflects start parameters in public pages.
func TestStartParams(ctx context.Context, username string, caps Capabilities) []StartParamResult {
	username = normalizeUsername(username)
	probes := selectStartProbes(caps)
	var results []StartParamResult

	for _, sp := range probes {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		deepLink := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(sp.payload))
		reflected, platformOnly, dangerous := probeStartReflection(ctx, username, sp.payload)
		results = append(results, StartParamResult{
			Payload:      sp.payload,
			Reflected:    reflected,
			PlatformOnly: platformOnly,
			Dangerous:    dangerous,
			DeepLink:     deepLink,
		})
	}
	return results
}

func selectStartProbes(caps Capabilities) []startProbe {
	all := loadStartProbes()
	var selected []startProbe
	seen := map[string]bool{}

	add := func(p startProbe) {
		if seen[p.payload] {
			return
		}
		seen[p.payload] = true
		selected = append(selected, p)
	}

	// Always test a few authz + injection probes.
	for _, p := range all {
		if p.category == "authz" || p.category == "injection" {
			add(p)
		}
		if len(selected) >= 6 {
			break
		}
	}
	if caps.HasReferral {
		for _, p := range all {
			if p.category == "referral" {
				add(p)
			}
		}
		add(startProbe{name: "ref_manual", payload: "ref_test_gramfuzz", category: "referral"})
	}
	if caps.HasPayment || caps.HasStars || caps.HasVIP {
		for _, p := range all {
			if p.category == "payment" {
				add(p)
			}
		}
	}
	if len(selected) < 8 {
		for _, p := range all {
			add(p)
			if len(selected) >= 10 {
				break
			}
		}
	}
	return selected
}

func probeStartReflection(ctx context.Context, username, payload string) (reflected, platformOnly, dangerous bool) {
	link := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(payload))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return false, true, false
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return false, true, false
	}
	defer resp.Body.Close()

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, payload) {
		return false, true, false
	}

	// Simple alphanumeric values appear in Telegram deep-link metadata by design.
	if !dangerousCharsRe.MatchString(payload) {
		return true, true, false
	}

	// Dangerous payload reflected outside expected deep-link contexts.
	if platformDeepLinkRe.MatchString(body) && !strings.Contains(body, "<"+payload) {
		return true, true, false
	}
	return true, false, true
}

// BuildStartFindings converts probe results into contextual findings for this bot.
func BuildStartFindings(username string, caps Capabilities, results []StartParamResult) []findings.Finding {
	username = normalizeUsername(username)
	var list []findings.Finding

	platformReflect := 0
	dangerousReflect := 0
	for _, r := range results {
		if r.Reflected && r.PlatformOnly {
			platformReflect++
		}
		if r.Dangerous {
			dangerousReflect++
		}
	}

	if platformReflect > 0 {
		list = append(list, findings.New(
			"START-PLATFORM", "info", "start-fuzzer", "surface",
			"Telegram platform reflects /start in public t.me metadata",
			fmt.Sprintf("%d probe(s) echoed in t.me deep-link tags (tg://resolve, OpenGraph). This is normal Telegram behavior and does NOT prove your bot backend processes or mishandles the parameter.", platformReflect),
			fmt.Sprintf("https://t.me/%s?start=PAYLOAD", username),
		).WithDetail(
			findings.ConfidenceInfo,
			[]string{"platform:t.me", "deep-link", "false-positive-guard"},
			"No direct impact on bot backend unless you render the same value unsafely in your own UI.",
			"Compare bot response in Telegram after opening a PoC link — platform HTML reflection alone is not a bot finding.",
			"1. Document that t.me landing pages always embed start params in metadata.\n2. Validate start payload only inside your bot handler.\n3. Do not treat t.me HTML reflection as backend XSS.",
		))
	}

	if dangerousReflect > 0 {
		list = append(list, findings.New(
			"START-DANGEROUS-REF", "medium", "start-fuzzer", "injection",
			"Dangerous characters reflected on t.me landing page",
			fmt.Sprintf("%d payload(s) with special characters appeared in public HTML beyond standard deep-link encoding. Review whether Telegram client or your bot echoes them elsewhere.", dangerousReflect),
			fmt.Sprintf("https://t.me/%s?start=<payload>", username),
		).WithMeta("CWE-79", "Never trust start parameters; validate with allowlists before SQL/shell/template use.", "").
			WithDetail(
				findings.ConfidenceLikely,
				[]string{"reflection", "xss-candidate", "start-param"},
				"If the same value is rendered in bot messages or web UI without encoding, stored/reflected XSS or injection may be possible.",
				"1. Open each flagged PoC link in Telegram.\n2. Observe bot reply and any WebView.\n3. Confirm whether payload is stored or executed server-side.",
				"1. Allowlist start param format (e.g. ref_[0-9A-Za-z]{8}).\n2. HTML-encode output in bot messages.\n3. Reject params containing markup or shell metacharacters.",
			))
	}

	// Bot-specific manual tests only.
	manual := buildManualStartTests(username, caps, results)
	list = append(list, manual...)
	return list
}

func buildManualStartTests(username string, caps Capabilities, results []StartParamResult) []findings.Finding {
	var list []findings.Finding
	base := fmt.Sprintf("https://t.me/%s", username)

	if caps.HasReferral {
		link := base + "?start=ref_test_gramfuzz"
		list = append(list, findings.New(
			"START-MANUAL-REF", "medium", "start-fuzzer", "logic",
			"Referral code forgery (manual verification required)",
			"Public profile suggests referral/invite logic. Test whether arbitrary start codes grant rewards or bypass limits.",
			link,
		).WithMeta("CWE-840", "Bind referral codes to issuer; single-use tokens; server-side validation.", link).
			WithDetail(
				findings.ConfidenceManual,
				[]string{"referral", "logic", "start-param"},
				"Attacker could self-refer or hijack another user's referral credit.",
				"1. Open PoC link from Account A.\n2. Repeat from Account B with same link.\n3. Check if rewards duplicate or self-referral is blocked.",
				"1. Use signed referral tokens.\n2. Prevent self-referral by user ID.\n3. Rate-limit reward claims.",
			))
	}

	if caps.HasPayment || caps.HasStars {
		link := base + "?start=pay_test_0"
		list = append(list, findings.New(
			"START-MANUAL-PAY", "high", "start-fuzzer", "logic",
			"Payment deep link tampering (manual verification required)",
			"Payment-related keywords detected. Only test if your bot actually implements Stars/TON/invoices.",
			link,
		).WithMeta("CWE-840", "Never trust client-supplied amounts; validate on server.", link).
			WithDetail(
				findings.ConfidenceManual,
				[]string{"payment", "stars", "logic"},
				"User might obtain goods/subscription without paying or with manipulated amount.",
				"1. Craft start links with pay:0, negative amounts, or currency mismatch.\n2. Complete flow in Telegram.\n3. Verify server rejects invalid amounts.",
				"1. Server-side price lookup by product ID.\n2. Idempotent payment webhooks.\n3. Audit logs for anomalous start params.",
			))
	} else {
		list = append(list, findings.New(
			"START-SKIP-PAY", "info", "start-fuzzer", "logic",
			"Payment start vectors skipped for this bot",
			"No payment/Stars/VIP keywords in public profile — Stars, TON, coupon, and invoice bypass tests were not generated.",
			base,
		).WithDetail(findings.ConfidenceInfo, []string{"scoped", "payment"}, "", "", ""))
	}

	for i, r := range results {
		if i >= 5 {
			break
		}
		if !r.Dangerous && r.PlatformOnly {
			continue
		}
		sev := "low"
		conf := findings.ConfidenceManual
		if r.Dangerous {
			sev = "medium"
		}
		list = append(list, findings.New(
			fmt.Sprintf("START-TEST-%03d", i+1), sev, "start-fuzzer", "injection",
			fmt.Sprintf("Start parameter probe: %s", truncatePayload(r.Payload, 40)),
			"Send this deep link to the bot and inspect handler behavior — does it parse, store, or execute the value?",
			r.DeepLink,
		).WithMeta("CWE-20", "Validate start payload format before use in DB, shell, or templates.", r.DeepLink).
			WithDetail(
				conf,
				[]string{"start-param", "manual-test"},
				"Unhandled start params may reach SQL, logs, or admin workflows.",
				fmt.Sprintf("Open in Telegram: %s\nObserve bot reply, keyboards, and any error messages.", r.DeepLink),
				"Allowlist + length limits on start parameter; log rejected values.",
			))
	}
	return list
}

func truncatePayload(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type AttackVector struct {
	ID          string
	Name        string
	Severity    string
	Description string
	PoCLink     string
	ManualStep  string
}

// GenerateLogicVectors returns test vectors for classic bots without web apps.
func GenerateLogicVectors(username string) []AttackVector {
	username = normalizeUsername(username)
	base := fmt.Sprintf("https://t.me/%s", username)

	return []AttackVector{
		{
			ID: "LOGIC-CMD-001", Name: "command_injection", Severity: "medium",
			Description: "Send crafted commands after /start — test for command parser bypass",
			ManualStep:  "In Telegram: /start then try /admin, /debug, /config, //start, /start@otherbot",
		},
		{
			ID: "LOGIC-CMD-002", Name: "rate_limit", Severity: "low",
			Description: "Rapid-fire /start and button clicks to test rate limiting",
			ManualStep:  "Send /start 50 times rapidly; check if bot throttles or crashes",
		},
		{
			ID: "LOGIC-REF-001", Name: "referral_hijack", Severity: "medium",
			Description: "Test if referral/start codes can be forged or reused across users",
			PoCLink:     base + "?start=ref_test_gramfuzz",
			ManualStep:  "Open PoC link from two different accounts; compare bot behavior",
		},
	}
}
