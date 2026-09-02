package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/scanner"
)

// WriteJSON exports findings as a JSON report with summary.
func WriteJSON(outputDir string, list []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	report := struct {
		Summary  findings.Summary  `json:"summary"`
		Findings []scanner.Finding `json:"findings"`
	}{
		Summary:  findings.Summarize(list),
		Findings: list,
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.json", timestamp()))
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

// WriteHTML exports findings as an HTML report.
func WriteHTML(outputDir string, list []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	summary := findings.Summarize(list)
	generatedAt := time.Now()
	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.html", timestamp()))
	content := renderHTML(generatedAt, list, summary)
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

func renderHTML(generatedAt time.Time, list []scanner.Finding, summary findings.Summary) string {
	var b strings.Builder
	b.WriteString(htmlReportHead)
	fmt.Fprintf(&b, `<div class="header"><h1>GramFuzz Penetration Test Report</h1><p>Generated: %s &bull; Authorized Testing Only</p></div>`,
		html.EscapeString(generatedAt.Format("2006-01-02 15:04:05 MST")))

	// Executive summary
	fmt.Fprintf(&b, `<div class="executive"><h2>Executive Summary</h2>`)
	fmt.Fprintf(&b, `<div class="risk-badge %s">%s</div>`, strings.ToLower(summary.RiskRating), html.EscapeString(summary.RiskRating))
	fmt.Fprintf(&b, `<p>Total findings: <strong>%d</strong> | Max risk: <strong>%d/10</strong> | Avg risk: <strong>%.1f</strong></p>`, summary.Total, summary.MaxRisk, summary.AvgRisk)
	fmt.Fprintf(&b, `</div>`)

	b.WriteString(`<div class="stats">`)
	fmt.Fprintf(&b, `<div class="stat"><div class="num">%d</div><div class="label">Total</div></div>`, summary.Total)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := summary.BySeverity[sev]; c > 0 {
			fmt.Fprintf(&b, `<div class="stat %s"><div class="num">%d</div><div class="label">%s</div></div>`, sev, c, sev)
		}
	}
	b.WriteString(`</div><div class="findings">`)

	if len(list) == 0 {
		b.WriteString(`<div class="finding info"><h3>No findings</h3><p>Scan completed without detected issues.</p></div>`)
	} else {
		for _, f := range list {
			fmt.Fprintf(&b, `<div class="finding %s">`, html.EscapeString(f.Severity))
			fmt.Fprintf(&b, `<h3>[%s] %s</h3>`, html.EscapeString(f.ID), html.EscapeString(f.Title))
			fmt.Fprintf(&b, `<div class="meta">%s &bull; %s &bull; %s &bull; risk %d/10`,
				html.EscapeString(f.Module), html.EscapeString(f.Category), html.EscapeString(f.Severity), f.RiskScore)
			if f.CWE != "" {
				fmt.Fprintf(&b, ` &bull; %s`, html.EscapeString(f.CWE))
			}
			b.WriteString(`</div>`)
			fmt.Fprintf(&b, `<p>%s</p>`, html.EscapeString(f.Description))
			if f.Evidence != "" {
				fmt.Fprintf(&b, `<div class="evidence"><strong>Evidence:</strong> %s</div>`, html.EscapeString(f.Evidence))
			}
			if f.PoC != "" {
				fmt.Fprintf(&b, `<div class="poc"><strong>PoC:</strong> %s</div>`, html.EscapeString(f.PoC))
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, `<div class="remediation"><strong>Remediation:</strong> %s</div>`, html.EscapeString(f.Remediation))
			}
			b.WriteString(`</div>`)
		}
	}

	b.WriteString(`</div><div class="footer">GramFuzz v0.2.0 &mdash; Ethical DAST for Telegram &bull; github.com/kiurakku/GramFuzz</div></body></html>`)
	return b.String()
}

func timestamp() string {
	return time.Now().Format("20060102-150405")
}

const htmlReportHead = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GramFuzz Penetration Test Report</title>
  <style>
    :root { --gold: #f5c518; --dark: #0d0d0d; --card: #1a1a1a; --text: #e8e8e8; --muted: #888; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--dark); color: var(--text); line-height: 1.6; }
    .header { background: linear-gradient(135deg, #1a1a00 0%, #0d0d0d 50%, #1a1500 100%); padding: 2rem; border-bottom: 2px solid var(--gold); text-align: center; }
    .header h1 { color: var(--gold); font-size: 2rem; letter-spacing: 2px; }
    .header p { color: var(--muted); margin-top: 0.5rem; }
    .executive { max-width: 900px; margin: 1.5rem auto; padding: 1.5rem 2rem; background: var(--card); border: 1px solid #333; border-radius: 8px; text-align: center; }
    .executive h2 { color: var(--gold); margin-bottom: 1rem; }
    .risk-badge { display: inline-block; padding: 0.5rem 2rem; border-radius: 4px; font-weight: bold; font-size: 1.5rem; margin-bottom: 1rem; }
    .risk-badge.critical { background: #ff4444; color: #fff; }
    .risk-badge.high { background: #ff8800; color: #fff; }
    .risk-badge.medium { background: #ffcc00; color: #000; }
    .risk-badge.low { background: #44aa44; color: #fff; }
    .risk-badge.informational { background: #4488ff; color: #fff; }
    .stats { display: flex; gap: 1rem; justify-content: center; padding: 1.5rem; flex-wrap: wrap; }
    .stat { background: var(--card); border: 1px solid #333; border-radius: 8px; padding: 1rem 2rem; text-align: center; }
    .stat .num { font-size: 2rem; color: var(--gold); font-weight: bold; }
    .stat.critical .num { color: #ff4444; }
    .stat.high .num { color: #ff8800; }
    .stat.medium .num { color: #ffcc00; }
    .stat .label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
    .findings { max-width: 900px; margin: 0 auto; padding: 1rem 2rem 3rem; }
    .finding { background: var(--card); border-left: 4px solid var(--gold); border-radius: 4px; padding: 1rem 1.5rem; margin-bottom: 1rem; }
    .finding.critical { border-left-color: #ff4444; }
    .finding.high { border-left-color: #ff8800; }
    .finding.medium { border-left-color: #ffcc00; }
    .finding.low { border-left-color: #44aa44; }
    .finding.info { border-left-color: #4488ff; }
    .finding h3 { color: var(--gold); margin-bottom: 0.25rem; font-size: 1rem; }
    .finding .meta { color: var(--muted); font-size: 0.75rem; margin-bottom: 0.5rem; }
    .finding .evidence, .finding .poc, .finding .remediation { padding: 0.5rem 1rem; border-radius: 4px; font-size: 0.85rem; margin-top: 0.5rem; word-break: break-all; }
    .finding .evidence { background: #111; font-family: monospace; }
    .finding .poc { background: #1a1500; border: 1px solid #443300; }
    .finding .remediation { background: #001a00; border: 1px solid #003300; color: #aaffaa; }
    .footer { text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid #222; }
  </style>
</head>
<body>`
