package fuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
)

const userAgent = "GramFuzz/0.3.0 (authorized-security-testing)"

var idMutations = []string{
	"1", "2", "0", "-1", "999999", "999999999", "admin", "me", "null", "undefined",
	"self", "root", "test", "guest", "anonymous",
}

var authBypassHeaders = []map[string]string{
	{"X-Original-URL": "/admin"},
	{"X-Rewrite-URL": "/admin"},
	{"X-Custom-IP-Authorization": "127.0.0.1"},
	{"X-Forwarded-For": "127.0.0.1"},
	{"X-Forwarded-Host": "localhost"},
	{"X-User-Id": "1"},
	{"X-Admin": "true"},
	{"Authorization": "Bearer null"},
	{"Authorization": "Bearer undefined"},
}

// ScanBackend performs ffuf-style path discovery and BOLA/IDOR probing.
func ScanBackend(ctx context.Context, baseURL string) []findings.Finding {
	baseURL = strings.TrimRight(baseURL, "/")
	paths := parseWL(assets.APIPathsWordlist)
	var list []findings.Finding
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}}

	discovered := 0
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return list
		default:
		}
		u := baseURL + path
		code, body, _ := httpProbe(ctx, client, http.MethodGet, u, nil)
		if code == 0 || code == 404 || code == 405 {
			continue
		}
		discovered++
		sev := classifyPathSeverity(path, code)
		list = append(list, findings.New(
			fmt.Sprintf("API-DISC-%04d", discovered), sev, "bola-fuzzer", "discovery",
			fmt.Sprintf("Endpoint discovered [%s]: %s", http.StatusText(code), path),
			fmt.Sprintf("HTTP %d — path responds. Enumerated via embedded wordlist (dirbuster/ffuf pattern).", code),
			truncateBody(body, 200),
		).WithMeta("CWE-200", "Restrict sensitive paths; require auth; use WAF.", u))
	}

	// BOLA / IDOR
	bolaHits := 0
	for _, id := range idMutations {
		for _, tmpl := range []string{"/api/users/%s", "/api/user/%s", "/api/profile/%s", "/api/orders/%s", "/users/%s", "/api/wallet/%s"} {
			p := fmt.Sprintf(tmpl, id)
			u := baseURL + p
			code, body, _ := httpProbe(ctx, client, http.MethodGet, u, nil)
			if code == 200 && len(body) > 10 {
				bolaHits++
				list = append(list, findings.New(
					fmt.Sprintf("BOLA-%04d", bolaHits), "high", "bola-fuzzer", "authz",
					"BOLA/IDOR — cross-user data access",
					fmt.Sprintf("GET %s → HTTP 200 (%d bytes). ID mutation: %s", p, len(body), id),
					truncateBody(body, 300),
				).WithMeta("CWE-639", "Object-level authorization on every endpoint.", "GET "+u))
			}
		}
	}

	// Auth bypass header fuzzing
	for i, hdrs := range authBypassHeaders {
		u := baseURL + "/admin"
		code, body, _ := httpProbe(ctx, client, http.MethodGet, u, hdrs)
		if code == 200 {
			list = append(list, findings.New(
				fmt.Sprintf("AUTH-BYPASS-%02d", i+1), "critical", "bola-fuzzer", "authz",
				"Authentication bypass via header manipulation",
				fmt.Sprintf("GET /admin with forged headers returned HTTP 200"),
				truncateBody(body, 200),
			).WithMeta("CWE-287", "Never trust client headers for auth decisions.", fmt.Sprintf("%v", hdrs)))
		}
	}

	if discovered == 0 && bolaHits == 0 && len(list) == 0 {
		list = append(list, findings.New(
			"API-CLEAN", "info", "bola-fuzzer", "discovery",
			"Backend path bruteforce complete — no exposed endpoints",
			fmt.Sprintf("Tested %d paths (dirbuster/ffuf wordlist). No responsive endpoints without auth.", len(paths)),
			baseURL,
		))
	}

	return list
}

func classifyPathSeverity(path string, code int) string {
	lower := strings.ToLower(path)
	if strings.Contains(lower, ".env") || strings.Contains(lower, ".git") || strings.Contains(lower, "debug") {
		return "critical"
	}
	if strings.Contains(lower, "admin") || strings.Contains(lower, "internal") || strings.Contains(lower, "backup") {
		return "high"
	}
	if strings.Contains(lower, "user") || strings.Contains(lower, "profile") || strings.Contains(lower, "wallet") {
		return "medium"
	}
	if code >= 500 {
		return "medium"
	}
	return "info"
}

func httpProbe(ctx context.Context, client *http.Client, method, url string, headers map[string]string) (int, string, http.Header) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", nil
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), resp.Header
}

func truncateBody(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
