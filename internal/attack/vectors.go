package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/recon"
)

const userAgent = "GramFuzz/0.4.0 (authorized-security-testing)"

// RunBotAPIAbuse checks for leaked tokens and probes Telegram Bot API.
func RunBotAPIAbuse(ctx context.Context, username string, profile *recon.Profile) []findings.Finding {
	var list []findings.Finding
	token := os.Getenv("BOT_TOKEN")

	if profile != nil {
		for _, s := range recon.ScanSecrets(profile.RawHTML) {
			if s.Type == "telegram_bot_token" {
				list = append(list, findings.New(
					"BOTAPI-LEAK", "critical", "bot-api-abuse", "secrets",
					"Bot token leaked in public profile",
					"Exposed token allows full bot impersonation, message interception, and user data access.",
					s.Value,
				).WithMeta("CWE-798", "Revoke token via @BotFather immediately; rotate and audit access logs.", "").
					WithDetail(
						findings.ConfidenceConfirmed,
						[]string{"secret", "token", "confirmed"},
						"Complete account takeover of the Telegram bot.",
						"Verify token pattern in public t.me page source; attempt getMe with revoked token after rotation.",
						"1. Revoke via @BotFather\n2. Issue new token\n3. Audit repository and CI for leaks",
					))
			}
		}
	}

	if token == "" {
		list = append(list, findings.New(
			"BOTAPI-INFO", "info", "bot-api-abuse", "auth",
			"Bot API live testing skipped (no BOT_TOKEN)",
			"Set BOT_TOKEN env var to enable getMe, getWebhookInfo, getUpdates probing.",
			"api.telegram.org",
		).WithDetail(findings.ConfidenceInfo, []string{"skipped", "bot-api"}, "", "", ""))
		return list
	}

	apiBase := "https://api.telegram.org/bot" + token + "/"
	checks := []struct {
		method, title, cwe string
		sev                string
	}{
		{"getMe", "Bot identity exposed via API", "CWE-200", "info"},
		{"getWebhookInfo", "Webhook configuration leak", "CWE-200", "medium"},
		{"getUpdates", "Pending updates accessible (polling mode)", "CWE-200", "high"},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, c := range checks {
		select {
		case <-ctx.Done():
			return list
		default:
		}
		u := apiBase + c.method
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == 200 && strings.Contains(string(body), `"ok":true`) {
			sev := c.sev
			conf := findings.ConfidenceLikely
			if c.method == "getUpdates" {
				var parsed struct {
					Result []json.RawMessage `json:"result"`
				}
				if json.Unmarshal(body, &parsed) == nil && len(parsed.Result) > 0 {
					sev = "critical"
					conf = findings.ConfidenceConfirmed
				}
			}
			list = append(list, findings.New(
				"BOTAPI-"+strings.ToUpper(c.method), sev, "bot-api-abuse", "exposure",
				c.title,
				fmt.Sprintf("Bot API %s returned ok:true. Review exposed data.", c.method),
				truncate(string(body), 400),
			).WithMeta(c.cwe, "Use webhooks with secret_token; disable getUpdates in production; restrict token access.", u).
				WithDetail(conf, []string{"bot-api", c.method}, "Sensitive bot configuration or user messages may be exposed.", "Call "+c.method+" with provided token and inspect JSON response.", "Restrict token; use webhook mode; enable secret_token header validation."))
		}
	}

	return list
}

// RunInjectionVectors generates prioritized injection manual tests for this bot.
func RunInjectionVectors(username string, profile *recon.Profile) []findings.Finding {
	username = strings.TrimPrefix(username, "@")
	_ = recon.AnalyzeCapabilities(profile)
	payloads := selectInjectionPayloads(parseLines(assets.InjectionWordlist))

	var list []findings.Finding
	list = append(list, findings.New(
		"INJ-SCOPE", "info", "injection-engine", "injection",
		"Injection testing scoped to high-risk payloads",
		fmt.Sprintf("%d prioritized payloads selected from wordlist. Test each as bot message text AND inside ?start= only if your handler parses start params.", len(payloads)),
		fmt.Sprintf("https://t.me/%s", username),
	).WithDetail(
		findings.ConfidenceInfo,
		[]string{"injection", "scoped", "sqli", "xss", "ssti"},
		"Unsanitized input in messages or start params may lead to SQLi, XSS, SSTI, or RCE.",
		"Send payloads in Telegram chat; for start params open deep links and observe bot behavior.",
		"Parameterized queries; HTML encoding; sandbox templates; never eval user input.",
	))

	for i, p := range payloads {
		sev := classifyInjection(p)
		deepLink := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(p))
		list = append(list, findings.New(
			fmt.Sprintf("INJ-TEST-%02d", i+1), sev, "injection-engine", "injection",
			injectionTitle(p),
			injectionDescription(p),
			deepLink,
		).WithMeta(injectionCWE(p), "Input validation + output encoding + WAF rules.", p).
			WithDetail(
				findings.ConfidenceManual,
				injectionTags(p),
				injectionImpact(p),
				fmt.Sprintf("A) Send as message to @%s\nB) Open deep link: %s\nC) Check DB logs/errors for exploitation signs", username, deepLink),
				injectionRemediation(p),
			))
	}
	return list
}

func selectInjectionPayloads(all []string) []string {
	priority := []string{}
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			priority = append(priority, p)
		}
	}
	for _, p := range all {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "union") || strings.Contains(lower, "sleep") ||
			strings.Contains(lower, "script") || strings.Contains(lower, "{{") ||
			strings.Contains(lower, "exec") || strings.Contains(lower, "system") ||
			strings.Contains(lower, "../") {
			add(p)
		}
		if len(priority) >= 10 {
			break
		}
	}
	for _, p := range all {
		add(p)
		if len(priority) >= 10 {
			break
		}
	}
	return priority
}

// RunPaymentLogic generates payment vectors only when profile suggests payment logic.
func RunPaymentLogic(username string, profile *recon.Profile) []findings.Finding {
	caps := recon.AnalyzeCapabilities(profile)
	if !caps.HasPayment && !caps.HasReferral && !caps.HasStars && !caps.HasVIP {
		return []findings.Finding{findings.New(
			"PAY-SKIP", "info", "logic-bypass", "logic",
			"Payment logic tests skipped — not applicable to this bot",
			"No payment, Stars, VIP, or referral keywords in public profile. Generic Stars/TON/coupon vectors were not generated.",
			fmt.Sprintf("https://t.me/%s", username),
		).WithDetail(findings.ConfidenceInfo, []string{"payment", "skipped", "scoped"}, "", "", "")}
	}

	username = strings.TrimPrefix(username, "@")
	base := fmt.Sprintf("https://t.me/%s", username)

	vectors := []struct {
		id, title, payload, desc, cwe, sev, impact, steps, plan string
		onlyReferral                                            bool
	}{
		{
			"PAY-REF-001", "Referral self-loop", "ref:own_id",
			"Test whether a user can refer themselves for infinite rewards.",
			"CWE-840", "medium",
			"Unlimited referral credits or balance inflation.",
			"1. Replace own_id with your Telegram user ID in start link\n2. Complete referral flow\n3. Verify self-referral is rejected",
			"Compare referrer ID with new user ID server-side; block equality.",
			true,
		},
		{
			"PAY-002", "Zero-cost purchase", "pay:0",
			"Attempt checkout with zero or negative amount via start deep link.",
			"CWE-840", "high",
			"Obtain paid features without transaction.",
			"1. Open PoC link\n2. Complete purchase flow\n3. Confirm server rejects amount",
			"Lookup price by product ID on server; never trust client amount.",
			false,
		},
		{
			"PAY-009", "Invoice replay", "invoice:replay_old",
			"Replay a captured successful payment callback or invoice token.",
			"CWE-294", "high",
			"Double-spend or duplicate entitlement grant.",
			"1. Capture legitimate payment webhook\n2. Replay POST to backend\n3. Check idempotency",
			"Store processed payment IDs; reject duplicates.",
			false,
		},
	}

	var list []findings.Finding
	for _, v := range vectors {
		if v.onlyReferral && !caps.HasReferral {
			continue
		}
		if !v.onlyReferral && !caps.HasPayment && !caps.HasStars {
			continue
		}
		link := base + "?start=" + url.QueryEscape(v.payload)
		list = append(list, findings.New(
			v.id, v.sev, "logic-bypass", "logic",
			v.title, v.desc, link,
		).WithMeta(v.cwe, v.plan, link).
			WithDetail(findings.ConfidenceManual, []string{"payment", "logic", "manual-test"}, v.impact, v.steps, v.plan))
	}
	return list
}

// RunWebhookAttacks generates webhook vectors when backend is known; otherwise one info item.
func RunWebhookAttacks(username string, backend string, profile *recon.Profile) []findings.Finding {
	caps := recon.AnalyzeCapabilities(profile)
	if backend == "" {
		return []findings.Finding{findings.New(
			"WH-SKIP", "info", "webhook-attack", "exposure",
			"Webhook live tests skipped — no backend URL",
			"No public backend discovered. Webhook SSRF/takeover checks require --backend or linked infrastructure.",
			"@"+strings.TrimPrefix(username, "@"),
		).WithDetail(findings.ConfidenceInfo, []string{"webhook", "skipped"}, "", "", "")}
	}

	var list []findings.Finding
	list = append(list, findings.New(
		"WH-SCOPE", "info", "webhook-attack", "exposure",
		"Webhook security checks for discovered backend",
		fmt.Sprintf("Probing %s for unauthenticated webhook endpoints.", backend),
		backend,
	).WithDetail(findings.ConfidenceInfo, []string{"webhook", "backend"}, "", "", ""))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list = append(list, probeWebhookEndpoint(ctx, backend)...)

	if caps.HasBackend {
		list = append(list, findings.New(
			"WH-MANUAL-SECRET", "high", "webhook-attack", "exposure",
			"Missing X-Telegram-Bot-Api-Secret-Token validation (manual)",
			"POST crafted Update JSON to webhook without secret_token header.",
			"POST /webhook without secret_token header",
		).WithMeta("CWE-306", "Configure secret_token in setWebhook and validate header.", backend+"/webhook").
			WithDetail(
				findings.ConfidenceManual,
				[]string{"webhook", "auth", "manual-test"},
				"Attacker injects fake Telegram updates (messages, payments).",
				"1. POST sample Update JSON to webhook URL\n2. Omit secret_token header\n3. If 200 OK — vulnerability confirmed",
				"Enable secret_token; reject requests without valid header; allowlist Telegram IP ranges.",
			))
	}
	return list
}

func probeWebhookEndpoint(ctx context.Context, backend string) []findings.Finding {
	var list []findings.Finding
	paths := []string{"/webhook", "/api/webhook", "/telegram/webhook", "/bot/webhook"}
	client := &http.Client{Timeout: 5 * time.Second}

	for _, p := range paths {
		u := strings.TrimRight(backend, "/") + p
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(`{"update_id":1,"message":{"text":"/start"}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			list = append(list, findings.New(
				"WH-LIVE", "critical", "webhook-attack", "exposure",
				"Live webhook accepts unauthenticated Update injection",
				fmt.Sprintf("POST %s returned HTTP 200 — attacker can inject fake Telegram updates.", p),
				truncate(string(body), 200),
			).WithMeta("CWE-306", "Validate X-Telegram-Bot-Api-Secret-Token; verify update structure; rate limit.", u).
				WithDetail(
					findings.ConfidenceConfirmed,
					[]string{"webhook", "confirmed", "injection"},
					"Full control over bot behavior via forged updates.",
					fmt.Sprintf("curl -X POST %s -H 'Content-Type: application/json' -d '{\"update_id\":1}'", u),
					"Require secret_token; validate update schema; return 403 for unsigned requests.",
				))
		}
	}
	return list
}

// RunTelegramSurface maps Telegram-specific attack surface relevant to this bot type.
func RunTelegramSurface(username string, profile *recon.Profile) []findings.Finding {
	u := strings.TrimPrefix(username, "@")
	base := fmt.Sprintf("https://t.me/%s", u)
	caps := recon.AnalyzeCapabilities(profile)

	var list []findings.Finding
	list = append(list, findings.New(
		"TG-SCOPE", "info", "telegram-surface", "surface",
		"Telegram platform surface for this bot type",
		fmt.Sprintf("Bot type: %s — only applicable platform vectors included.", caps.BotType),
		base,
	).WithDetail(findings.ConfidenceInfo, []string{"telegram", "scoped"}, "", "", ""))

	if caps.HasReferral {
		link := base + "?start=ref_test_gramfuzz"
		list = append(list, findings.New(
			"TG-REF", "medium", "telegram-surface", "logic",
			"Deep link referral parameter abuse",
			"Forge or reuse referral codes via ?start= parameter.",
			link,
		).WithMeta("CWE-20", "Validate referral codes server-side.", link).
			WithDetail(findings.ConfidenceManual, []string{"referral", "deep-link"}, "Referral fraud or account linking bypass.", "Open PoC from two accounts; compare rewards.", "Signed tokens; single-use codes."))
	}

	if caps.HasWebApp {
		list = append(list, findings.New(
			"TG-WEBAPP", "high", "telegram-surface", "surface",
			"Mini App initData validation",
			"Verify WebApp initData HMAC and auth_date on every request.",
			caps.ExternalURLs[0],
		).WithMeta("CWE-345", "Validate initData with bot token hash; reject expired auth_date.", "").
			WithDetail(findings.ConfidenceManual, []string{"mini-app", "webapp"}, "User impersonation in Mini App backend.", "Tamper initData in WebView proxy; replay old auth_date.", "Server-side HMAC validation per Telegram docs."))
	} else {
		list = append(list, findings.New(
			"TG-SKIP-WEBAPP", "info", "telegram-surface", "surface",
			"Mini App vectors skipped",
			"Classic bot — menu button SSRF and WebApp initData tests not applicable.",
			base,
		).WithDetail(findings.ConfidenceInfo, []string{"mini-app", "skipped"}, "", "", ""))
	}

	return list
}

func injectionTitle(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "{{"), strings.Contains(lower, "${"), strings.Contains(lower, "<%"):
		return "SSTI / template injection probe"
	case strings.Contains(lower, "script"), strings.Contains(lower, "onerror"):
		return "XSS probe via bot input"
	case strings.Contains(lower, "union"), strings.Contains(lower, "sleep"), strings.Contains(lower, "drop"):
		return "SQL injection probe"
	case strings.Contains(lower, "exec"), strings.Contains(lower, "system"):
		return "Command injection / RCE probe"
	default:
		return "Input validation probe"
	}
}

func injectionDescription(p string) string {
	return fmt.Sprintf("Payload: %s — verify bot does not pass this unsanitized to SQL, shell, logs, or HTML output.", truncate(p, 80))
}

func injectionImpact(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "exec"), strings.Contains(lower, "system"):
		return "Remote code execution on bot server."
	case strings.Contains(lower, "{{"):
		return "Server-side template injection leading to RCE."
	case strings.Contains(lower, "union"):
		return "Database read/write via SQL injection."
	case strings.Contains(lower, "script"):
		return "Cross-site scripting in bot messages or admin panel."
	default:
		return "Data corruption or unauthorized access via malformed input."
	}
}

func injectionTags(p string) []string {
	t := []string{"injection", "manual-test"}
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "{{"):
		t = append(t, "ssti")
	case strings.Contains(lower, "union"):
		t = append(t, "sqli")
	case strings.Contains(lower, "script"):
		t = append(t, "xss")
	case strings.Contains(lower, "exec"):
		t = append(t, "rce")
	}
	return t
}

func injectionRemediation(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "{{"):
		return "Use logic-less templates; sandbox; never render user input in Jinja/Twig/ERB."
	case strings.Contains(lower, "union"):
		return "Parameterized queries; ORM; least-privilege DB user."
	case strings.Contains(lower, "script"):
		return "HTML-encode bot output; Content-Security-Policy on web panels."
	default:
		return "Strict input validation; allowlists; output encoding."
	}
}

func parseLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func classifyInjection(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "exec"), strings.Contains(lower, "system"), strings.Contains(lower, "popen"):
		return "critical"
	case strings.Contains(lower, "script"), strings.Contains(lower, "union"), strings.Contains(lower, "{{"):
		return "high"
	default:
		return "medium"
	}
}

func injectionCWE(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "script"), strings.Contains(lower, "<"):
		return "CWE-79"
	case strings.Contains(lower, "union"), strings.Contains(lower, "drop"):
		return "CWE-89"
	case strings.Contains(lower, "{{"), strings.Contains(lower, "${"):
		return "CWE-1336"
	case strings.Contains(lower, "../"):
		return "CWE-22"
	default:
		return "CWE-74"
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
