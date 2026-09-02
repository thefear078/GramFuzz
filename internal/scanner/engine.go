package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kiurakku/GramFuzz/internal/config"
	"github.com/kiurakku/GramFuzz/internal/term"
)

type Finding struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Module      string    `json:"module"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

type Engine struct {
	cfg      *config.Config
	findings []Finding
	mu       sync.Mutex
}

func New(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Run(ctx context.Context) ([]Finding, error) {
	steps := []struct {
		name    string
		enabled bool
		run     func(context.Context) []Finding
	}{
		{"InitData Validator", e.cfg.Modules.UserSimulator, e.runInitDataCheck},
		{"Web App Inspector", e.cfg.Modules.WebInspector, e.runWebInspector},
		{"BOLA/IDOR Fuzzer", e.cfg.Modules.BOLAFuzzer, e.runBOLAFuzzer},
		{"AI Payload Analyzer", e.cfg.Modules.AIAnalyzer, e.runAIAnalyzer},
	}

	for i, step := range steps {
		select {
		case <-ctx.Done():
			return e.findings, ctx.Err()
		default:
		}

		if !step.enabled {
			term.Yellow("  [SKIP] %s — module disabled\n", step.name)
			continue
		}

		term.Cyan("  [%d/%d] Running %s...\n", i+1, len(steps), step.name)
		results := step.run(ctx)
		e.mu.Lock()
		e.findings = append(e.findings, results...)
		e.mu.Unlock()

		if len(results) > 0 {
			term.Yellow("         → %d finding(s) detected\n", len(results))
		} else {
			term.GreenPrintln("         → No issues in demo mode")
		}
	}

	return e.findings, nil
}

func (e *Engine) runInitDataCheck(ctx context.Context) []Finding {
	_ = ctx
	time.Sleep(300 * time.Millisecond)
	if e.cfg.Target.BotUsername == "" {
		return nil
	}
	return []Finding{{
		ID: "INIT-001", Severity: "info", Module: "user-simulator",
		Title: "InitData validation probe scheduled",
		Description: "User Simulator will verify backend initData HMAC validation when credentials are configured.",
		Evidence: fmt.Sprintf("target=@%s", e.cfg.Target.BotUsername),
		Timestamp: time.Now(),
	}}
}

func (e *Engine) runWebInspector(ctx context.Context) []Finding {
	_ = ctx
	time.Sleep(300 * time.Millisecond)
	if e.cfg.Target.WebAppURL == "" {
		return nil
	}
	return []Finding{{
		ID: "WEB-001", Severity: "info", Module: "web-inspector",
		Title: "Web App traffic capture ready",
		Description: "Headless inspector will intercept Fetch/XHR calls and map API surface.",
		Evidence: e.cfg.Target.WebAppURL, Timestamp: time.Now(),
	}}
}

func (e *Engine) runBOLAFuzzer(ctx context.Context) []Finding {
	_ = ctx
	time.Sleep(300 * time.Millisecond)
	if e.cfg.Target.BackendURL == "" {
		return nil
	}
	return []Finding{{
		ID: "BOLA-001", Severity: "info", Module: "bola-fuzzer",
		Title: "BOLA fuzzing vectors prepared",
		Description: "Fuzzer will mutate user IDs, JWT claims, and session tokens against mapped endpoints.",
		Evidence: e.cfg.Target.BackendURL, Timestamp: time.Now(),
	}}
}

func (e *Engine) runAIAnalyzer(ctx context.Context) []Finding {
	_ = ctx
	time.Sleep(200 * time.Millisecond)
	return nil
}
