package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
)

var startPayloads = func() []struct {
	name, payload, severity, desc string
} {
	var out []struct {
		name, payload, severity, desc string
	}
	lines := strings.Split(assets.StartPayloadsWordlist, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sev := "medium"
		if strings.Contains(line, "script") || strings.Contains(line, "alert") {
			sev = "high"
		}
		if len(line) > 200 {
			sev = "low"
		}
		out = append(out, struct {
			name, payload, severity, desc string
		}{fmt.Sprintf("ref_%03d", i+1), line, sev, "Start parameter injection probe"})
	}
	return out
}()

// StartParamResult holds reflection analysis for a start payload.
type StartParamResult struct {
	Payload     string
	Reflected   bool
	EncodedSafe bool
	DeepLink    string
}

// TestStartParams probes how t.me reflects start parameters in public pages.
func TestStartParams(ctx context.Context, username string) ([]StartParamResult, []AttackVector) {
	username = normalizeUsername(username)
	var results []StartParamResult
	var vectors []AttackVector

	for _, sp := range startPayloads {
		select {
		case <-ctx.Done():
			return results, vectors
		default:
		}

		deepLink := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(sp.payload))
		reflected, encoded := probeStartReflection(ctx, username, sp.payload)

		results = append(results, StartParamResult{
			Payload:     sp.name,
			Reflected:   reflected,
			EncodedSafe: encoded,
			DeepLink:    deepLink,
		})

		vectors = append(vectors, AttackVector{
			ID:          fmt.Sprintf("START-%s", strings.ToUpper(strings.ReplaceAll(sp.name, "ref_", "REF_"))),
			Name:        sp.name,
			Severity:    sp.severity,
			Description: sp.desc,
			PoCLink:     deepLink,
			ManualStep:  fmt.Sprintf("Open link in Telegram and observe bot response to /start %s", sp.payload),
		})
	}

	return results, vectors
}

func probeStartReflection(ctx context.Context, username, payload string) (reflected, encodedSafe bool) {
	link := fmt.Sprintf("https://t.me/%s?start=%s", username, url.QueryEscape(payload))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return false, true
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return false, true
	}
	defer resp.Body.Close()

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	rawPayload := payload
	reflected = strings.Contains(body, rawPayload)
	encodedSafe = !reflected && (strings.Contains(body, url.QueryEscape(payload)) ||
		strings.Contains(body, strings.ReplaceAll(url.QueryEscape(payload), "+", "%20")))

	return reflected, encodedSafe
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
			ID: "LOGIC-CMD-003", Name: "inline_button_fuzz", Severity: "medium",
			Description: "Click all inline buttons and callback_data payloads for IDOR",
			ManualStep:  "Interact with every button; intercept callback_data if using MTProto later",
		},
		{
			ID: "LOGIC-REF-001", Name: "referral_hijack", Severity: "medium",
			Description: "Test if referral/start codes can be forged or reused across users",
			PoCLink:     base + "?start=ref_test_gramfuzz",
			ManualStep:  "Open PoC link from two different accounts; compare bot behavior",
		},
		{
			ID: "LOGIC-REF-002", Name: "self_referral", Severity: "low",
			Description: "Test self-referral loop in loyalty/referral systems",
			PoCLink:     base + "?start=own_user_id",
			ManualStep:  "Replace own_user_id with your Telegram ID in the start link",
		},
	}
}
