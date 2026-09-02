package recon

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var webhookPaths = []string{
	"/webhook", "/api/webhook", "/telegram/webhook", "/bot/webhook",
	"/tg/webhook", "/callback", "/api/telegram", "/hooks/telegram",
}

// LinkAuditResult holds HTTP security header analysis.
type LinkAuditResult struct {
	URL            string
	StatusCode     int
	IsHTTPS        bool
	MissingHeaders []string
	Findings       []string
}

// AuditLinks checks security headers and probes webhook paths on discovered domains.
func AuditLinks(ctx context.Context, urls []string) ([]LinkAuditResult, []WebhookProbe) {
	var audits []LinkAuditResult
	var probes []WebhookProbe

	seenHosts := map[string]bool{}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}}

	for _, rawURL := range urls {
		select {
		case <-ctx.Done():
			return audits, probes
		default:
		}

		audit := auditURL(ctx, client, rawURL)
		if audit.URL != "" {
			audits = append(audits, audit)
		}

		host := extractHost(rawURL)
		if host != "" && !seenHosts[host] {
			seenHosts[host] = true
			probes = append(probes, probeWebhooks(ctx, client, host)...)
		}
	}

	return audits, probes
}

func auditURL(ctx context.Context, client *http.Client, rawURL string) LinkAuditResult {
	result := LinkAuditResult{URL: rawURL, IsHTTPS: strings.HasPrefix(strings.ToLower(rawURL), "https://")}

	if !result.IsHTTPS {
		result.Findings = append(result.Findings, "insecure HTTP link in public profile")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		req.Method = http.MethodGet
		resp, err = client.Do(req)
		if err != nil {
			result.Findings = append(result.Findings, "unreachable: "+err.Error())
			return result
		}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	required := map[string]bool{
		"Strict-Transport-Security": false,
		"X-Content-Type-Options":    false,
		"X-Frame-Options":           false,
	}
	for h := range required {
		if resp.Header.Get(h) == "" {
			result.MissingHeaders = append(result.MissingHeaders, h)
		}
	}

	if len(result.MissingHeaders) > 0 && result.IsHTTPS {
		result.Findings = append(result.Findings,
			fmt.Sprintf("missing security headers: %s", strings.Join(result.MissingHeaders, ", ")))
	}

	cors := resp.Header.Get("Access-Control-Allow-Origin")
	if cors == "*" {
		result.Findings = append(result.Findings, "CORS wildcard (*) detected")
	}

	return result
}

type WebhookProbe struct {
	URL        string
	StatusCode int
	Notable    bool
	Note       string
}

func probeWebhooks(ctx context.Context, client *http.Client, host string) []WebhookProbe {
	var results []WebhookProbe
	scheme := "https"
	for _, path := range webhookPaths {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		u := fmt.Sprintf("%s://%s%s", scheme, host, path)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(`{}`))
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		notable := resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed
		if notable {
			results = append(results, WebhookProbe{
				URL: u, StatusCode: resp.StatusCode, Notable: true,
				Note: "Endpoint responds — verify if Telegram webhook is exposed",
			})
		}
	}
	return results
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	if idx := strings.Index(rawURL, "/"); idx > 0 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx > 0 {
		rawURL = rawURL[:idx]
	}
	if rawURL == "" || strings.Contains(rawURL, " ") {
		return ""
	}
	return rawURL
}
