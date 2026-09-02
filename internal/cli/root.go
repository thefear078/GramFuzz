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
		runScanCommand(configPath, subArgs)
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

func runScanCommand(configPath string, args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	bot := fs.String("bot", "", "Target bot username")
	webapp := fs.String("webapp", "", "Telegram Mini App URL")
	backend := fs.String("backend", "", "Backend API base URL")
	output := fs.String("output", "./reports", "Report output directory")
	format := fs.String("format", "html", "Report format: html, json, both")
	_ = fs.Parse(args)

	cfg, err := config.Load(configPath)
	exitErr(err)

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

	banner.Divider("Security Scan")
	if cfg.Target.BotUsername == "" && cfg.Target.WebAppURL == "" && cfg.Target.BackendURL == "" {
		term.YellowPrintln("  No target specified. Running in demo mode.")
		term.YellowPrintln("  Use: gramfuzz scan --bot mybot --webapp URL --backend URL")
		fmt.Println()
	}

	findings, err := scanner.New(cfg).Run(contextWithTimeout())
	exitErr(err)
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
	findings, err := scanner.New(cfg).Run(contextWithTimeout())
	exitErr(err)
	writeReports(cfg, findings)
}

func runModulesCommand() {
	banner.Divider("Available Modules")
	modules := []struct{ name, lang, desc string }{
		{"CLI Engine", "Go", "Core orchestrator — request queues, logging, module coordination"},
		{"User Simulator", "Python/Telethon", "MTProto client — bot interaction, initData interception"},
		{"Web App Inspector", "TypeScript/Playwright", "Headless TMA renderer — API mapping, XHR capture"},
		{"BOLA Fuzzer", "Go", "Token & ID mutation engine for access control testing"},
		{"AI Payload Analyzer", "Python/LLM", "Local LLM context analysis — attack vector generation"},
		{"Reporter", "Go", "HTML/JSON reports with reproducible PoC exports"},
	}
	for _, m := range modules {
		term.YellowBold("  ▸ %s", m.name)
		term.Cyan(" [%s]\n", m.lang)
		term.Dim("    %s\n\n", m.desc)
	}
}

func writeReports(cfg *config.Config, findings []scanner.Finding) {
	banner.Divider("Report Generation")
	format := cfg.Reporter.Format

	switch format {
	case "both":
		jp, err := reporter.WriteJSON(cfg.Reporter.Output, findings)
		exitErr(err)
		term.Green("  ✓ JSON report: %s\n", jp)
		hp, err := reporter.WriteHTML(cfg.Reporter.Output, findings)
		exitErr(err)
		term.Green("  ✓ HTML report: %s\n", hp)
	case "json":
		p, err := reporter.WriteJSON(cfg.Reporter.Output, findings)
		exitErr(err)
		term.Green("  ✓ JSON report: %s\n", p)
	default:
		p, err := reporter.WriteHTML(cfg.Reporter.Output, findings)
		exitErr(err)
		term.Green("  ✓ HTML report: %s\n", p)
	}

	fmt.Println()
	term.Cyan("  Scan complete — %d finding(s)\n", len(findings))
}

func contextWithTimeout() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Minute)
	return ctx
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
  gramfuzz scan   [--bot USER] [--webapp URL] [--backend URL] [--format html|json|both]
  gramfuzz fuzz   --backend URL
  gramfuzz modules
  gramfuzz version

Global flags:
  --no-banner       Suppress ASCII banner
  -c, --config FILE JSON config file

Examples:
  gramfuzz scan
  gramfuzz scan --bot mybot --backend https://api.example.com --format both
  gramfuzz fuzz --backend https://api.example.com
`)
}
