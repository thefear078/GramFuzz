package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/kiurakku/GramFuzz/internal/scanner"
)

type reportData struct {
	GeneratedAt time.Time
	Findings    []scanner.Finding
	Total       int
	BySeverity  map[string]int
}

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

	data := reportData{
		GeneratedAt: time.Now(),
		Findings:    findings,
		Total:       len(findings),
		BySeverity:  bySeverity,
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.html", timestamp()))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	if err := tmpl.Execute(file, data); err != nil {
		return "", err
	}
	return filename, nil
}

func timestamp() string {
	return time.Now().Format("20060102-150405")
}

const htmlTemplate = `<!DOCTYPE html>
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
<body>
  <div class="header">
    <h1>⚡ GramFuzz Security Report</h1>
    <p>Generated: {{ .GeneratedAt.Format "2006-01-02 15:04:05 MST" }} • Authorized Testing Only</p>
  </div>
  <div class="stats">
    <div class="stat"><div class="num">{{ .Total }}</div><div class="label">Total Findings</div></div>
    {{ range $sev, $count := .BySeverity }}
    <div class="stat"><div class="num">{{ $count }}</div><div class="label">{{ $sev }}</div></div>
    {{ end }}
  </div>
  <div class="findings">
    {{ if eq .Total 0 }}
    <div class="finding info"><h3>No findings</h3><p>Scan completed without detected issues.</p></div>
    {{ else }}
    {{ range .Findings }}
    <div class="finding {{ .Severity }}">
      <h3>[{{ .ID }}] {{ .Title }}</h3>
      <div class="meta">{{ .Module }} • {{ .Severity }} • {{ .Timestamp.Format "15:04:05" }}</div>
      <p>{{ .Description }}</p>
      {{ if .Evidence }}<div class="evidence">{{ .Evidence }}</div>{{ end }}
    </div>
    {{ end }}
    {{ end }}
  </div>
  <div class="footer">GramFuzz v0.1.0 — Ethical DAST for Telegram • github.com/kiurakku/GramFuzz</div>
</body>
</html>`
