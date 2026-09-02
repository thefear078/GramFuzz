package webinspect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/findings"
)

const userAgent = "GramFuzz/0.1.0 (authorized-security-testing)"

var (
	apiEndpointRe = regexp.MustCompile(`(?i)(?:fetch|axios|get|post)\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)
	secretRe      = regexp.MustCompile(`(?i)(?:bot[_-]?token|api[_-]?key|secret|password|private[_-]?key)\s*[:=]\s*["']([^"']{8,})["']`)
	initDataRe    = regexp.MustCompile(`(?i)initData|Telegram\.WebApp\.initData`)
	jwtRe         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// Analyze performs static security analysis on a Telegram Mini App URL.
func Analyze(ctx context.Context, appURL string) []findings.Finding {
	var list []findings.Finding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appURL, nil)
	if err != nil {
		return []findings.Finding{findings.New(
			"WEB-ERR", "medium", "web-inspector", "config",
			"Failed to fetch Mini App", err.Error(), appURL,
		)}
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []findings.Finding{findings.New(
			"WEB-ERR", "medium", "web-inspector", "config",
			"Mini App unreachable", err.Error(), appURL,
		)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	html := string(body)

	list = append(list, findings.New(
		"WEB-001", "info", "web-inspector", "discovery",
		"Mini App fetched successfully",
		fmt.Sprintf("HTTP %d — %d bytes loaded for static analysis.", resp.StatusCode, len(html)),
		appURL,
	))

	endpoints := map[string]bool{}
	for _, m := range apiEndpointRe.FindAllStringSubmatch(html, -1) {
		ep := m[1]
		if strings.HasPrefix(ep, "http") || strings.HasPrefix(ep, "/") {
			endpoints[ep] = true
		}
	}
	i := 0
	for ep := range endpoints {
		i++
		list = append(list, findings.New(
			fmt.Sprintf("WEB-API-%03d", i), "info", "web-inspector", "discovery",
			"API endpoint discovered in client-side code",
			"Endpoint extracted from JavaScript. Map and test for BOLA, missing auth, and injection.",
			ep,
		).WithMeta("CWE-200", "Avoid exposing internal API routes; enforce server-side auth on all endpoints.", ep))
	}

	for _, m := range secretRe.FindAllStringSubmatch(html, -1) {
		list = append(list, findings.New(
			"WEB-SECRET", "critical", "web-inspector", "secrets",
			"Hardcoded secret in Mini App source",
			"Sensitive credential pattern found in client-side JavaScript. Secrets in TMA are visible to all users.",
			mask(m[1]),
		).WithMeta("CWE-798", "Never embed secrets in client code. Use server-side proxy with short-lived tokens.", appURL))
	}

	if initDataRe.MatchString(html) {
		list = append(list, findings.New(
			"WEB-INITDATA", "info", "web-inspector", "auth",
			"initData usage detected in client code",
			"Verify backend validates HMAC-SHA256 of initData with bot token. Never trust client-side initData parsing alone.",
			"Telegram.WebApp.initData reference found",
		).WithMeta("CWE-287", "Validate initData hash server-side per Telegram docs; check auth_date freshness.", ""))
	}

	for _, m := range jwtRe.FindAllString(html, -1) {
		list = append(list, findings.New(
			"WEB-JWT", "high", "web-inspector", "secrets",
			"JWT token found in client-side source",
			"Hardcoded or leaked JWT in Mini App may allow session hijacking or privilege escalation.",
			mask(m),
		).WithMeta("CWE-522", "Do not store JWTs in client code; use httpOnly cookies or short-lived server sessions.", mask(m)))
	}

	if !isHTTPS(appURL) {
		list = append(list, findings.New(
			"WEB-HTTP", "high", "web-inspector", "crypto",
			"Mini App served over insecure HTTP",
			"Telegram Mini Apps must use HTTPS. HTTP allows MITM and initData interception.",
			appURL,
		).WithMeta("CWE-319", "Deploy Mini App exclusively over HTTPS with valid TLS certificate.", appURL))
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		list = append(list, findings.New(
			"WEB-CSP", "medium", "web-inspector", "config",
			"Missing Content-Security-Policy header",
			"Without CSP, XSS in Mini App can exfiltrate initData and user session.",
			appURL,
		).WithMeta("CWE-1021", "Implement strict CSP restricting script sources and frame ancestors.", ""))
	}

	return list
}

func isHTTPS(u string) bool {
	return strings.HasPrefix(strings.ToLower(u), "https://")
}

func mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
