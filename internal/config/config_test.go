package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kiurakku/GramFuzz/internal/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	if !cfg.Modules.BOLAFuzzer {
		t.Fatal("BOLA fuzzer should be enabled by default")
	}
}

func TestLoadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := `{"target":{"bot_username":"testbot"},"modules":{"ai_analyzer":true}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target.BotUsername != "testbot" {
		t.Fatalf("expected testbot, got %s", cfg.Target.BotUsername)
	}
	if !cfg.Modules.AIAnalyzer {
		t.Fatal("ai_analyzer should be enabled from json")
	}
}
