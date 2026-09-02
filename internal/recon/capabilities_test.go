package recon_test

import (
	"testing"

	"github.com/kiurakku/GramFuzz/internal/recon"
)

func TestAnalyzeCapabilitiesClassicBot(t *testing.T) {
	p := &recon.Profile{
		Title:       "Team Bot",
		Description: "Welcome to our community bot",
		HasWebApp:   false,
	}
	c := recon.AnalyzeCapabilities(p)
	if c.HasPayment {
		t.Fatal("expected no payment for generic bot")
	}
	if c.HasWebApp {
		t.Fatal("expected classic bot")
	}
	if len(c.AttackSurface) == 0 {
		t.Fatal("expected attack surface entries")
	}
}

func TestAnalyzeCapabilitiesPaymentBot(t *testing.T) {
	p := &recon.Profile{
		Title:       "Shop Bot",
		Description: "Buy premium with Telegram Stars and coupons",
	}
	c := recon.AnalyzeCapabilities(p)
	if !c.HasPayment || !c.HasStars {
		t.Fatalf("expected payment/stars detection, got %+v", c)
	}
}

func TestPriorityCommandsLimited(t *testing.T) {
	c := recon.AnalyzeCapabilities(&recon.Profile{Title: "Admin Panel Bot"})
	cmds := recon.PriorityCommands(c, []string{"admin", "debug", "foo", "bar"})
	if len(cmds) > 20 {
		t.Fatalf("too many priority commands: %d", len(cmds))
	}
}
