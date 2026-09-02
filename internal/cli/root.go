package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/banner"
	"github.com/kiurakku/GramFuzz/internal/config"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/reporter"
	"github.com/kiurakku/GramFuzz/internal/scanner"
	"github.com/kiurakku/GramFuzz/internal/term"
)

func Execute() {
	args := os.Args[1:]
	if len(args) == 0 {
		banner.Print()
		printUsage()
		return
	}

	noBanner := hasFlag(args, "--no-banner")
	configPath := flagValue(args, "--config", "-c")

	cmd := args[0]
	subArgs := filterGlobalFlags(args[1:])

	if !noBanner && cmd != "help" {
		banner.Print()
	}

	switch cmd {
	case "scan":
		runScanCommand(configPath, subArgs, false)
	case "pentest":
		runScanCommand(configPath, subArgs, true)
	case "fuzz":
		runFuzzCommand(configPath, subArgs)
	case "modules":
		runModulesCommand()
	case "version":
		fmt.Println(banner.Compact())
	case "help", "-h", "--help":
		printUsage()
	default:
		term.RedPrintln("Unknown command: " + cmd)
		printUsage()
		os.Exit(1)
	}
}

func runScanCommand(configPath string, args []string, fullPentest bool) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	bot := fs.String("bot", "", "Target bot username")
	webapp := fs.String("webapp", "", "Telegram Mini App URL")
	backend := fs.String("backend", "", "Backend API base URL")
	output := fs.String("output", "./reports", "Report output directory")
	format := fs.String("format", "html", "Report format: html, json, both")
	_ = fs.Parse(args)

	cfg, err := config.Load(configPath)
	exitErr(err)

	if fullPentest {
		cfg.Modules.PublicRecon = true
		cfg.Modules.CommandFuzz = true
		cfg.Modules.InjectionFuzz = true
		cfg.Modules.PaymentLogic = true
		cfg.Modules.WebhookAttack = true
		cfg.Modules.TelegramSurface = true
		cfg.Modules.BotAPIAbuse = true
		cfg.Modules.BOLAFuzzer = true
		cfg.Modules.WebInspector = true
	}

	if *output != "" {
		cfg.Reporter.Output = *output
	}
	if *format != "" {
		cfg.Reporter.Format = *format
	}
	if *bot != "" {
		cfg.Target.BotUsername = *bot
	}
	if *webapp != "" {
		cfg.Target.WebAppURL = *webapp
	}
	if *backend != "" {
		cfg.Target.BackendURL = *backend
	}

	if fullPentest {
		banner.Divider("Full Penetration Test")
	} else {
		banner.Divider("Security Scan")
	}

	if cfg.Target.BotUsername == "" && cfg.Target.WebAppURL == "" && cfg.Target.BackendURL == "" {
		term.YellowPrintln("  No target specified. Running in demo mode.")
		term.YellowPrintln("  Use: gramfuzz pentest --bot mybot")
		fmt.Println()
	}

	timeout := 5 * time.Minute
	if fullPentest {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	findings, err := scanner.New(cfg).Run(ctx)
	exitErr(err)
	printRiskSummary(findings)
	writeReports(cfg, findings)
}

func runFuzzCommand(configPath string, args []string) {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)
	backend := fs.String("backend", "", "Backend API base URL (required)")
	output := fs.String("output", "./reports", "Report output directory")
	_ = fs.Parse(args)

	if *backend == "" {
		exitErr(fmt.Errorf("--backend is required"))
	}

	cfg, err := config.Load(configPath)
	exitErr(err)

	cfg.Target.BackendURL = *backend
	cfg.Reporter.Output = *output
	cfg.Modules = config.ModulesConfig{BOLAFuzzer: true}

	banner.Divider("BOLA/IDOR Fuzzing")
	ctx, cancel := contextWithTimeout()
	defer cancel()
	findings, err := scanner.New(cfg).Run(ctx)
	exitErr(err)
	writeReports(cfg, findings)
}

func runModulesCommand() {
	banner.Divider("Available Modules")
	modules := []struct{ name, lang, desc string }{
		{"CLI Engine", "Go", "13-phase pentest pipeline with risk scoring"},
		{"Public Recon", "Go", "t.me profiling, secrets, bot classification"},
		{"OSINT Engine", "Go", "Domain/email extraction, deep links, typosquatting"},
		{"Start Fuzzer", "Go", "40+ deep-link injection probes with reflection detection"},
		{"Command Fuzzer", "Go", "150+ commands (ffuf/dirbuster wordlist)"},
		{"Injection Engine", "Go", "SQLi/XSS/SSTI/RCE payloads (sqlmap-inspired)"},
		{"Payment Logic", "Go", "Financial bypass, coupon abuse, TON/Stars vectors"},
		{"Telegram Surface", "Go", "Platform-specific: inline mode, login_url, games"},
		{"Webhook Attacks", "Go", "SSRF, replay, secret_token bypass (nuclei-style)"},
		{"Bot API Abuse", "Go", "getMe/getUpdates/getWebhookInfo probing"},
		{"BOLA Fuzzer", "Go", "90+ API paths + IDOR + auth header bypass"},
		{"Web Inspector", "Go", "Mini App secrets, JWT, CSP analysis"},
		{"Attack Runner", "Python", "sqlmap/ffuf/nmap-inspired auxiliary payloads"},
		{"PDF Reporter", "Go", "Branded PDF report with embedded logo"},
	}
	for _, m := range modules {
		term.YellowBold("  ▸ %s", m.name)
		term.Cyan(" [%s]\n", m.lang)
		term.Dim("    %s\n\n", m.desc)
	}
}

func writeReports(cfg *config.Config, list []scanner.Finding) {
	banner.Divider("Report Generation")
	format := cfg.Reporter.Format

	switch format {
	case "all":
		jp, err := reporter.WriteJSON(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ JSON report: %s\n", jp)
		hp, err := reporter.WriteHTML(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ HTML report: %s\n", hp)
		pp, err := reporter.WritePDF(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ PDF report:  %s\n", pp)
	case "both":
		jp, err := reporter.WriteJSON(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ JSON report: %s\n", jp)
		hp, err := reporter.WriteHTML(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ HTML report: %s\n", hp)
	case "json":
		p, err := reporter.WriteJSON(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ JSON report: %s\n", p)
	case "pdf":
		p, err := reporter.WritePDF(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ PDF report:  %s\n", p)
	default:
		p, err := reporter.WriteHTML(cfg.Reporter.Output, list)
		exitErr(err)
		term.Green("  ✓ HTML report: %s\n", p)
	}

	fmt.Println()
	summary := findings.Summarize(list)
	term.Cyan("  Engagement complete — %d items | Actionable: %s (%d/10) | Manual tests: %d\n",
		len(list), summary.ActionableRating, summary.ActionableMax, summary.ManualTests)
}

func printRiskSummary(list []scanner.Finding) {
	s := findings.Summarize(list)
	if s.Actionable > 0 {
		term.Yellow("\n  ⚠  Actionable risk: %s — %d confirmed/likely finding(s)\n",
			s.ActionableRating, s.Actionable)
	} else if s.ManualTests > 0 {
		term.Yellow("\n  ○  No confirmed issues — %d manual test(s) require verification in Telegram\n",
			s.ManualTests)
	}
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

func exitErr(err error) {
	if err != nil {
		term.Red("Error: %v\n", err)
		os.Exit(1)
	}
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func flagValue(args []string, names ...string) string {
	for i, a := range args {
		for _, name := range names {
			if a == name && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, name+"=") {
				return strings.TrimPrefix(a, name+"=")
			}
		}
	}
	return ""
}

func filterGlobalFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-banner":
			continue
		case "--config", "-c":
			if i+1 < len(args) {
				i++
			}
			continue
		default:
			if strings.HasPrefix(args[i], "--config=") {
				continue
			}
			out = append(out, args[i])
		}
	}
	return out
}

func printUsage() {
	fmt.Print(`Usage:
  gramfuzz pentest [--bot USER] [--format all|pdf|html|json|both]
  gramfuzz scan    [--bot USER] [--webapp URL] [--backend URL] [--format html|json|both]
  gramfuzz fuzz    --backend URL
  gramfuzz modules
  gramfuzz version

Global flags:
  --no-banner       Suppress ASCII banner
  -c, --config FILE JSON config file

Examples:
  gramfuzz pentest --bot MaGa4BoT --format all
  gramfuzz scan --bot mybot --backend https://api.example.com
  gramfuzz fuzz --backend https://api.example.com
`)
}
