package reporter

import (
	"bytes"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/scanner"
	"github.com/phpdave11/gofpdf"
)

// WritePDF exports a branded PDF penetration test report with logo.
func WritePDF(outputDir string, list []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	summary := findings.Summarize(list)
	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.pdf", timestamp()))

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Logo
	logoPath := filepath.Join(outputDir, ".gramfuzz-logo-tmp.png")
	if err := os.WriteFile(logoPath, assets.LogoPNG, 0o644); err == nil {
		pdf.ImageOptions(logoPath, 85, 10, 40, 0, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
		_ = os.Remove(logoPath)
	}

	pdf.SetY(55)
	pdf.SetFont("Arial", "B", 22)
	pdf.SetTextColor(245, 197, 24)
	pdf.CellFormat(0, 12, "GramFuzz Penetration Test Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s | Authorized Testing Only", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.Ln(8)

	// Executive summary box
	pdf.SetFillColor(26, 26, 26)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(0, 10, "Executive Summary", "", 1, "L", true, 0, "")
	pdf.SetFont("Arial", "", 11)
	riskColor := riskRGB(summary.RiskRating)
	pdf.SetTextColor(riskColor[0], riskColor[1], riskColor[2])
	pdf.CellFormat(0, 8, fmt.Sprintf("Risk Rating: %s", summary.RiskRating), "", 1, "L", true, 0, "")
	pdf.SetTextColor(220, 220, 220)
	pdf.SetFont("Arial", "", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("Total Findings: %d  |  Max Risk: %d/10  |  Avg Risk: %.1f", summary.Total, summary.MaxRisk, summary.AvgRisk), "", 1, "L", true, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Critical: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d",
		summary.BySeverity["critical"], summary.BySeverity["high"], summary.BySeverity["medium"],
		summary.BySeverity["low"], summary.BySeverity["info"]), "", 1, "L", true, 0, "")
	pdf.Ln(6)

	// Findings by severity (top critical/high first)
	sorted := sortByRisk(list)
	pdf.SetFont("Arial", "B", 12)
	pdf.SetTextColor(245, 197, 24)
	pdf.CellFormat(0, 8, "Findings Detail", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	for i, f := range sorted {
		if i > 0 && i%8 == 0 {
			pdf.AddPage()
		}
		renderFinding(pdf, f)
	}

	// Footer on last page
	pdf.SetY(-15)
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(120, 120, 120)
	pdf.CellFormat(0, 5, "GramFuzz v0.3.0 - github.com/kiurakku/GramFuzz - Telegram: @thefear007", "", 0, "C", false, 0, "")

	if err := pdf.OutputFileAndClose(filename); err != nil {
		return "", err
	}
	return filename, nil
}

func renderFinding(pdf *gofpdf.Fpdf, f scanner.Finding) {
	sevColor := severityRGB(f.Severity)
	pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 9)
	pdf.CellFormat(0, 5, fmt.Sprintf(" [%s] %s - %s ", strings.ToUpper(f.Severity), f.ID, f.Title), "", 1, "L", true, 0, "")

	pdf.SetTextColor(60, 60, 60)
	pdf.SetFont("Arial", "", 8)
	meta := fmt.Sprintf("%s | %s | Risk %d/10", f.Module, f.Category, f.RiskScore)
	if f.CWE != "" {
		meta += " | " + f.CWE
	}
	pdf.CellFormat(0, 4, meta, "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(30, 30, 30)
	pdf.MultiCell(0, 4, f.Description, "", "L", false)

	if f.Evidence != "" {
		pdf.SetFont("Courier", "", 7)
		pdf.SetTextColor(80, 80, 80)
		pdf.MultiCell(0, 3, "Evidence: "+truncatePDF(f.Evidence, 300), "", "L", false)
	}
	if f.PoC != "" {
		pdf.SetTextColor(100, 80, 0)
		pdf.MultiCell(0, 3, "PoC: "+truncatePDF(f.PoC, 200), "", "L", false)
	}
	if f.Remediation != "" {
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(0, 100, 0)
		pdf.MultiCell(0, 3, "Fix: "+f.Remediation, "", "L", false)
	}
	pdf.Ln(3)
}

func sortByRisk(list []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, len(list))
	copy(out, list)
	// simple bubble by risk score desc
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].RiskScore > out[i].RiskScore {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func severityRGB(sev string) [3]int {
	switch sev {
	case "critical":
		return [3]int{255, 68, 68}
	case "high":
		return [3]int{255, 136, 0}
	case "medium":
		return [3]int{255, 204, 0}
	case "low":
		return [3]int{68, 170, 68}
	default:
		return [3]int{68, 136, 255}
	}
}

func riskRGB(rating string) [3]int {
	switch rating {
	case "CRITICAL":
		return [3]int{255, 68, 68}
	case "HIGH":
		return [3]int{255, 136, 0}
	case "MEDIUM":
		return [3]int{255, 204, 0}
	default:
		return [3]int{68, 170, 68}
	}
}

func truncatePDF(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Validate logo decodes (compile-time check for embed).
func init() {
	_, _, err := image.Decode(bytes.NewReader(assets.LogoPNG))
	if err != nil {
		// logo optional fallback
	}
}
