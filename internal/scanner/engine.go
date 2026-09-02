package scanner

import (
	"context"

	"github.com/kiurakku/GramFuzz/internal/config"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/pentest"
)

type Finding = findings.Finding

type Engine struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Run(ctx context.Context) ([]Finding, error) {
	return pentest.Run(ctx, e.cfg), nil
}

// RunQuick runs a lightweight scan (recon only).
func (e *Engine) RunQuick(ctx context.Context) ([]Finding, error) {
	quick := *e.cfg
	quick.Modules.CommandFuzz = false
	quick.Modules.BOLAFuzzer = false
	quick.Modules.WebInspector = false
	quick.Modules.AIAnalyzer = false
	return pentest.Run(ctx, &quick), nil
}
