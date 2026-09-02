package recon_test

import (
	"context"
	"strings"
	"testing"

	"github.com/kiurakku/GramFuzz/internal/recon"
)

const sampleHTML = `
<meta property="og:title" content="Test Bot">
<div class="tgme_page_title"><span dir="auto">Test Bot Title</span></div>
<div class="tgme_page_extra">@testbot</div>
<div class="tgme_page_description">Visit https://example.com/api</div>
<a href="https://example.com">Example</a>
<div class="tgme_page_action"><a class="tgme_action_button_new">Start Bot</a></div>
`

func TestScanSecretsClean(t *testing.T) {
	matches := recon.ScanSecrets(sampleHTML)
	if len(matches) > 0 {
		t.Fatalf("expected no secrets, got %d", len(matches))
	}
}

func TestScanSecretsToken(t *testing.T) {
	html := sampleHTML + " leaked 1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	matches := recon.ScanSecrets(html)
	if len(matches) != 1 {
		t.Fatalf("expected 1 token match, got %d", len(matches))
	}
}

func TestFetchProfileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test")
	}
	ctx := context.Background()
	p, err := recon.FetchProfile(ctx, "MaGa4BoT")
	if err != nil {
		t.Fatal(err)
	}
	if p.BotType() != "classic" {
		t.Fatalf("expected classic bot, got %s", p.BotType())
	}
	if !strings.Contains(p.Title, "Bot") && p.Title == "" {
		t.Fatal("expected title from profile")
	}
}
