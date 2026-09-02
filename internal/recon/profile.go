package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const userAgent = "GramFuzz/0.1.0 (authorized-security-testing)"

var (
	metaContentRe  = regexp.MustCompile(`(?i)<meta[^>]+(?:property|name)=["']([^"']+)["'][^>]+content=["']([^"']*)["']`)
	metaContentRe2 = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']*)["'][^>]+(?:property|name)=["']([^"']+)["']`)
	titleRe        = regexp.MustCompile(`(?i)<div class="tgme_page_title"[^>]*><span[^>]*>([^<]+)</span>`)
	extraRe        = regexp.MustCompile(`(?i)<div class="tgme_page_extra"[^>]*>\s*@?([A-Za-z0-9_]+)`)
	descRe         = regexp.MustCompile(`(?i)<div class="tgme_page_description"[^>]*>([\s\S]*?)</div>`)
	hrefRe         = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
	botTokenRe     = regexp.MustCompile(`\b(\d{8,10}:[A-Za-z0-9_-]{35})\b`)
	apiKeyRe       = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})`)
	webAppRe       = regexp.MustCompile(`(?i)(tgWebApp|Mini App|openWebApp|tgme_action_webapp|data-webapp)`)
	startButtonRe  = regexp.MustCompile(`(?i)tgme_action_button`)
)

// Profile holds publicly available bot metadata from t.me.
type Profile struct {
	Username     string
	Title        string
	Description  string
	Extra        string
	PhotoURL     string
	WebAppURL    string
	HasWebApp    bool
	HasStartBtn  bool
	ExternalURLs []string
	RawHTML      string
	FetchedAt    time.Time
}

// FetchProfile loads the public t.me page for a bot username.
func FetchProfile(ctx context.Context, username string) (*Profile, error) {
	username = normalizeUsername(username)
	url := fmt.Sprintf("https://t.me/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("bot @%s not found on Telegram (404)", username)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for @%s", resp.StatusCode, username)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	html := string(body)
	p := &Profile{
		Username:    username,
		RawHTML:     html,
		FetchedAt:   time.Now(),
		HasWebApp:   webAppRe.MatchString(html),
		HasStartBtn: startButtonRe.MatchString(html),
	}

	p.parseMeta(html)
	p.parseTitle(html)
	p.parseDescription(html)
	p.ExternalURLs = extractExternalURLs(html, username)

	return p, nil
}

func (p *Profile) parseMeta(html string) {
	for _, m := range metaContentRe.FindAllStringSubmatch(html, -1) {
		setMeta(p, m[1], m[2])
	}
	for _, m := range metaContentRe2.FindAllStringSubmatch(html, -1) {
		setMeta(p, m[2], m[1])
	}
}

func setMeta(p *Profile, key, value string) {
	key = strings.ToLower(key)
	value = strings.TrimSpace(value)
	switch key {
	case "og:title":
		if p.Title == "" {
			p.Title = value
		}
	case "og:description", "twitter:description":
		if p.Description == "" && value != "" && !strings.Contains(value, "You can contact @") {
			p.Description = value
		}
	case "og:image":
		if p.PhotoURL == "" {
			p.PhotoURL = value
		}
	}
}

func (p *Profile) parseTitle(html string) {
	if m := titleRe.FindStringSubmatch(html); len(m) > 1 {
		p.Title = strings.TrimSpace(m[1])
	}
	if m := extraRe.FindStringSubmatch(html); len(m) > 1 {
		p.Extra = m[1]
	}
}

func (p *Profile) parseDescription(html string) {
	if m := descRe.FindStringSubmatch(html); len(m) > 1 {
		text := stripTags(m[1])
		if text != "" {
			p.Description = text
		}
	}
}

func extractExternalURLs(html, username string) []string {
	seen := map[string]bool{}
	var urls []string
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		u := strings.TrimSpace(m[1])
		if u == "" || strings.HasPrefix(u, "#") || strings.HasPrefix(u, "tg://") {
			continue
		}
		if strings.HasPrefix(u, "//") {
			u = "https:" + u
		}
		if strings.HasPrefix(u, "/") {
			continue
		}
		lower := strings.ToLower(u)
		if strings.Contains(lower, "telegram.org") || strings.Contains(lower, "t.me/"+username) {
			continue
		}
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			continue
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}

func stripTags(s string) string {
	s = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, " ")
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func normalizeUsername(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "@")
	return u
}

// BotType classifies the target based on public profile data.
func (p *Profile) BotType() string {
	if p.HasWebApp {
		return "mini-app"
	}
	return "classic"
}

// ScanSecrets checks public HTML for leaked credentials.
func ScanSecrets(html string) []SecretMatch {
	var matches []SecretMatch
	for _, m := range botTokenRe.FindAllStringSubmatch(html, -1) {
		matches = append(matches, SecretMatch{
			Type:     "telegram_bot_token",
			Value:    maskSecret(m[1]),
			Severity: "critical",
		})
	}
	for _, m := range apiKeyRe.FindAllStringSubmatch(html, -1) {
		matches = append(matches, SecretMatch{
			Type:     "api_key_pattern",
			Value:    maskSecret(m[1]),
			Severity: "high",
		})
	}
	return matches
}

type SecretMatch struct {
	Type     string
	Value    string
	Severity string
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
