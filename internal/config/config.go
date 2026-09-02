package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Target   TargetConfig   `json:"target"`
	Modules  ModulesConfig  `json:"modules"`
	Reporter ReporterConfig `json:"reporter"`
	AI       AIConfig       `json:"ai"`
}

type TargetConfig struct {
	BotUsername string `json:"bot_username"`
	WebAppURL   string `json:"web_app_url"`
	BackendURL  string `json:"backend_url"`
}

type ModulesConfig struct {
	UserSimulator bool `json:"user_simulator"`
	WebInspector  bool `json:"web_inspector"`
	BOLAFuzzer    bool `json:"bola_fuzzer"`
	AIAnalyzer    bool `json:"ai_analyzer"`
}

type ReporterConfig struct {
	Format  string `json:"format"`
	Output  string `json:"output"`
	Verbose bool   `json:"verbose"`
}

type AIConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

func Default() *Config {
	return &Config{
		Modules: ModulesConfig{
			UserSimulator: true,
			WebInspector:  true,
			BOLAFuzzer:    true,
			AIAnalyzer:    false,
		},
		Reporter: ReporterConfig{
			Format: "html",
			Output: "./reports",
		},
		AI: AIConfig{
			Enabled:  false,
			Endpoint: "http://localhost:1234/v1",
			Model:    "qwen2.5",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func (c *Config) EnsureOutputDir() error {
	if c.Reporter.Output == "" {
		c.Reporter.Output = "./reports"
	}
	return os.MkdirAll(c.Reporter.Output, 0o755)
}

func ResolvePath(base, rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(base, rel)
}
