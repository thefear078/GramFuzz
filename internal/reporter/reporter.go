package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/scanner"
)

// WriteJSON exports findings as a JSON report.
func WriteJSON(outputDir string, findings []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.json", timestamp()))
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

// WriteHTML exports findings as an HTML report.
func WriteHTML(outputDir string, findings []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	bySeverity := map[string]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
	}

	generatedAt := time.Now()
	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.html", timestamp()))

	content := renderHTML(generatedAt, findings, bySeverity)
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

func renderHTML(generatedAt time.Time, findings []scanner.Finding, bySeverity map[string]int) string {
	var b strings.Builder
	b.WriteString(htmlReportHead)
	fmt.Fprintf(&b, `<div class="header"><h1>GramFuzz Security Report</h1><p>Generated: %s &bull; Authorized Testing Only</p></div>`,
		html.EscapeString(generatedAt.Format("2006-01-02 15:04:05 MST")))

	b.WriteString(`<div class="stats">`)
	fmt.Fprintf(&b, `<div class="stat"><div class="num">%d</div><div class="label">Total Findings</div></div>`, len(findings))
	for sev, count := range bySeverity {
		fmt.Fprintf(&b, `<div class="stat"><div class="num">%d</div><div class="label">%s</div></div>`, count, html.EscapeString(sev))
	}
	b.WriteString(`</div><div class="findings">`)

	if len(findings) == 0 {
		b.WriteString(`<div class="finding info"><h3>No findings</h3><p>Scan completed without detected issues.</p></div>`)
	} else {
		for _, f := range findings {
			fmt.Fprintf(&b, `<div class="finding %s">`, html.EscapeString(f.Severity))
			fmt.Fprintf(&b, `<h3>[%s] %s</h3>`, html.EscapeString(f.ID), html.EscapeString(f.Title))
			fmt.Fprintf(&b, `<div class="meta">%s &bull; %s &bull; %s</div>`,
				html.EscapeString(f.Module), html.EscapeString(f.Severity), html.EscapeString(f.Timestamp.Format("15:04:05")))
			fmt.Fprintf(&b, `<p>%s</p>`, html.EscapeString(f.Description))
			if f.Evidence != "" {
				fmt.Fprintf(&b, `<div class="evidence">%s</div>`, html.EscapeString(f.Evidence))
			}
			b.WriteString(`</div>`)
		}
	}

	b.WriteString(`</div><div class="footer">GramFuzz v0.1.0 &mdash; Ethical DAST for Telegram &bull; github.com/kiurakku/GramFuzz</div></body></html>`)
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
  <title>GramFuzz Security Report</title>
  <style>
    :root { --gold: #f5c518; --dark: #0d0d0d; --card: #1a1a1a; --text: #e8e8e8; --muted: #888; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--dark); color: var(--text); line-height: 1.6; }
    .header { background: linear-gradient(135deg, #1a1a00 0%, #0d0d0d 50%, #1a1500 100%); padding: 2rem; border-bottom: 2px solid var(--gold); text-align: center; }
    .header h1 { color: var(--gold); font-size: 2rem; letter-spacing: 2px; }
    .header p { color: var(--muted); margin-top: 0.5rem; }
    .stats { display: flex; gap: 1rem; justify-content: center; padding: 1.5rem; flex-wrap: wrap; }
    .stat { background: var(--card); border: 1px solid #333; border-radius: 8px; padding: 1rem 2rem; text-align: center; }
    .stat .num { font-size: 2rem; color: var(--gold); font-weight: bold; }
    .stat .label { color: var(--muted); font-size: 0.85rem; }
    .findings { max-width: 900px; margin: 0 auto; padding: 1rem 2rem 3rem; }
    .finding { background: var(--card); border-left: 4px solid var(--gold); border-radius: 4px; padding: 1rem 1.5rem; margin-bottom: 1rem; }
    .finding.critical { border-left-color: #ff4444; }
    .finding.high { border-left-color: #ff8800; }
    .finding.medium { border-left-color: #ffcc00; }
    .finding.low { border-left-color: #44aa44; }
    .finding.info { border-left-color: #4488ff; }
    .finding h3 { color: var(--gold); margin-bottom: 0.25rem; }
    .finding .meta { color: var(--muted); font-size: 0.8rem; margin-bottom: 0.5rem; }
    .finding .evidence { background: #111; padding: 0.5rem 1rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; margin-top: 0.5rem; word-break: break-all; }
    .footer { text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid #222; }
  </style>
</head>
<body>`
