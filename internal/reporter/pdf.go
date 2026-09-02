package reporter

import (
	"bytes"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kiurakku/GramFuzz/internal/assets"
	"github.com/kiurakku/GramFuzz/internal/banner"
	"github.com/kiurakku/GramFuzz/internal/findings"
	"github.com/kiurakku/GramFuzz/internal/scanner"
	"github.com/phpdave11/gofpdf"
)

const pdfFooterBrand = `GramFuzz by "the fear"`

const (
	colBgR, colBgG, colBgB          = 0, 0, 0
	colTextR, colTextG, colTextB    = 255, 255, 255
	colMutedR, colMutedG, colMutedB = 180, 180, 180
	colGoldR, colGoldG, colGoldB    = 245, 197, 24
)

var nonASCIIRe = regexp.MustCompile(`[^\x09\x0A\x0D\x20-\x7E]`)

type infoRow struct {
	label, value string
}

// WritePDF exports a branded PDF penetration test report with logo.
func WritePDF(outputDir string, list []scanner.Finding) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	summary := findings.Summarize(list)
	target := extractTarget(list)
	filename := filepath.Join(outputDir, fmt.Sprintf("gramfuzz-report-%s.pdf", timestamp()))

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(16, 16, 18)
	pdf.SetAutoPageBreak(true, 20)

	// Background only in header (never paint over content in footer).
	pdf.SetHeaderFunc(func() {
		pdf.SetFillColor(colBgR, colBgG, colBgB)
		pdf.Rect(0, 0, 210, 297, "F")
	})

	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.CellFormat(0, 6, pdfSafe(fmt.Sprintf("%s  |  Page %d", pdfFooterBrand, pdf.PageNo())), "", 0, "C", false, 0, "")
	})

	pdf.AddPage()
	renderCoverPage(pdf, registerLogo(pdf), target, summary)
	renderSummaryPage(pdf, summary, target)
	renderFindingsPages(pdf, list)

	return filename, pdf.OutputFileAndClose(filename)
}

func registerLogo(pdf *gofpdf.Fpdf) string {
	const name = "gramfuzz-logo"
	reader := bytes.NewReader(assets.LogoPNG)
	if pdf.RegisterImageOptionsReader(name, gofpdf.ImageOptions{ImageType: "PNG"}, reader) != nil {
		return name
	}
	return ""
}

func renderCoverPage(pdf *gofpdf.Fpdf, logoName, target string, summary findings.Summary) {
	pdf.SetXY(16, 18)

	if logoName != "" {
		pdf.Image(logoName, 78, 18, 50, 45, false, "", 0, "")
		pdf.SetXY(16, 70)
	}

	pdfLine(pdf, "B", 28, colGoldR, colGoldG, colGoldB, "GramFuzz", "C")
	pdfLine(pdf, "", 14, colTextR, colTextG, colTextB, "Penetration Test Report", "C")
	pdf.Ln(4)

	pdf.SetDrawColor(colGoldR, colGoldG, colGoldB)
	pdf.SetLineWidth(0.3)
	y := pdf.GetY()
	pdf.Line(50, y, 160, y)
	pdf.Ln(8)

	pdfLine(pdf, "B", 11, colGoldR, colGoldG, colGoldB, "Target", "C")
	pdfLine(pdf, "", 13, colTextR, colTextG, colTextB, pdfSafe(target), "C")
	pdf.Ln(6)

	for _, row := range []infoRow{
		{"Generated", time.Now().Format("2006-01-02 15:04:05 MST")},
		{"Version", "v" + banner.Version},
		{"Author", "kiurakku / The Fear"},
		{"Contact", "@thefear007"},
		{"Repository", "github.com/kiurakku/GramFuzz"},
		{"Actionable risk", fmt.Sprintf("%s (%d/10)", summary.ActionableRating, summary.ActionableMax)},
		{"Report items", fmt.Sprintf("%d total, %d manual tests", summary.Total, summary.ManualTests)},
	} {
		pdfInfoRow(pdf, row.label, row.value)
	}

	pdf.Ln(4)
	pdf.SetX(16)
	pdf.SetFont("Arial", "I", 9)
	pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
	pdf.MultiCell(0, 4.5, pdfSafe(
		"Ethical DAST for Telegram bots. Manual-test items must be verified inside Telegram before treating them as confirmed vulnerabilities.",
	), "", "C", false)
}

func renderSummaryPage(pdf *gofpdf.Fpdf, summary findings.Summary, target string) {
	pdf.AddPage()
	pdf.SetXY(16, 16)

	pdfHeading(pdf, "Executive Summary")

	risk := riskRGB(summary.ActionableRating)
	pdfLine(pdf, "B", 13, risk[0], risk[1], risk[2],
		fmt.Sprintf("Actionable Risk: %s (%d/10)", summary.ActionableRating, summary.ActionableMax), "L")
	pdf.Ln(3)

	for _, row := range []infoRow{
		{"Target", pdfSafe(target)},
		{"Total items", fmt.Sprintf("%d", summary.Total)},
		{"Actionable", fmt.Sprintf("%d confirmed/likely", summary.Actionable)},
		{"Manual tests", fmt.Sprintf("%d pending", summary.ManualTests)},
		{"Critical / High", fmt.Sprintf("%d / %d", summary.BySeverity["critical"], summary.BySeverity["high"])},
	} {
		pdfInfoRow(pdf, row.label, row.value)
	}

	pdf.Ln(4)
	pdfHeading(pdf, "How to read this report")
	for _, line := range []string{
		"confirmed / likely - observed automatically, fix first",
		"manual-test - open PoC in Telegram and verify bot response",
		"info - recon or skipped modules, not a confirmed vulnerability",
		"Payment/Stars tests only when bot profile suggests monetization",
	} {
		pdfBullet(pdf, line)
	}
}

func renderFindingsPages(pdf *gofpdf.Fpdf, list []scanner.Finding) {
	pdf.AddPage()
	pdf.SetXY(16, 16)
	pdfHeading(pdf, "Findings Detail")
	pdf.Ln(2)

	for _, f := range sortByActionable(list) {
		if pdf.GetY() > 265 {
			pdf.AddPage()
			pdf.SetXY(16, 16)
			pdfHeading(pdf, "Findings Detail (continued)")
			pdf.Ln(2)
		}
		renderFinding(pdf, f)
		pdf.Ln(3)
	}
}

func renderFinding(pdf *gofpdf.Fpdf, f scanner.Finding) {
	sev := severityRGB(f.Severity)

	// Colored severity strip (only place we use fill).
	pdf.SetFillColor(sev[0], sev[1], sev[2])
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(0, 7, pdfSafe(fmt.Sprintf(" [%s] %s", strings.ToUpper(f.Severity), f.Title)), "", 1, "L", true, 0, "")

	meta := fmt.Sprintf("%s | %s | risk %d/10", f.ID, f.Module, f.RiskScore)
	if f.Confidence != "" {
		meta += " | " + f.Confidence
	}
	if f.CWE != "" {
		meta += " | " + f.CWE
	}
	pdfLine(pdf, "", 8, colMutedR, colMutedG, colMutedB, meta, "L")

	if len(f.Tags) > 0 {
		pdfLine(pdf, "", 8, 140, 200, 255, "tags: "+pdfSafe(strings.Join(f.Tags, ", ")), "L")
	}

	pdfField(pdf, "Description", f.Description)
	pdfField(pdf, "Impact", f.Impact)
	pdfField(pdf, "Evidence", truncatePDF(f.Evidence, 600))
	if f.PoC != "" && f.PoC != f.Evidence {
		pdfField(pdf, "PoC", truncatePDF(f.PoC, 400))
	}
	pdfField(pdf, "Verification", f.Steps)
	pdfField(pdf, "Quick fix", f.Remediation)
	pdfField(pdf, "Remediation plan", f.RemediationPlan)

	pdf.SetDrawColor(60, 60, 60)
	pdf.SetLineWidth(0.1)
	pdf.Line(16, pdf.GetY()+1, 194, pdf.GetY()+1)
	pdf.Ln(2)
}

func pdfHeading(pdf *gofpdf.Fpdf, text string) {
	pdfLine(pdf, "B", 15, colGoldR, colGoldG, colGoldB, text, "L")
	pdf.Ln(2)
}

func pdfInfoRow(pdf *gofpdf.Fpdf, label, value string) {
	pdf.SetX(16)
	pdf.SetFont("Arial", "B", 9)
	pdf.SetTextColor(colGoldR, colGoldG, colGoldB)
	pdf.CellFormat(42, 6, label+":", "", 0, "L", false, 0, "")
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(colTextR, colTextG, colTextB)
	pdf.CellFormat(0, 6, pdfSafe(value), "", 1, "L", false, 0, "")
}

func pdfField(pdf *gofpdf.Fpdf, label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	pdf.SetX(16)
	pdf.SetFont("Arial", "B", 8)
	pdf.SetTextColor(colGoldR, colGoldG, colGoldB)
	pdf.CellFormat(0, 4, label+":", "", 1, "L", false, 0, "")
	pdf.SetX(16)
	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(colTextR, colTextG, colTextB)
	pdf.MultiCell(0, 4, pdfSafe(value), "", "L", false)
	pdf.Ln(1)
}

func pdfBullet(pdf *gofpdf.Fpdf, text string) {
	pdf.SetX(16)
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(colTextR, colTextG, colTextB)
	pdf.CellFormat(0, 5, "- "+pdfSafe(text), "", 1, "L", false, 0, "")
}

func pdfLine(pdf *gofpdf.Fpdf, style string, size float64, r, g, b int, text, align string) {
	pdf.SetFont("Arial", style, size)
	pdf.SetTextColor(r, g, b)
	pdf.CellFormat(0, size*0.45, pdfSafe(text), "", 1, align, false, 0, "")
}

func extractTarget(list []scanner.Finding) string {
	for _, f := range list {
		if f.ID == "ENGAGEMENT-SUMMARY" || f.ID == "RECON-001" {
			if f.Evidence != "" {
				return f.Evidence
			}
		}
	}
	for _, f := range list {
		if strings.HasPrefix(f.Evidence, "@") || strings.Contains(f.Evidence, "t.me/") {
			return f.Evidence
		}
	}
	return "Unknown target"
}

func sortByActionable(list []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, len(list))
	copy(out, list)
	confRank := map[string]int{
		findings.ConfidenceConfirmed: 4,
		findings.ConfidenceLikely:    3,
		findings.ConfidenceManual:    2,
		findings.ConfidencePlaybook:  1,
		findings.ConfidenceInfo:      0,
		"":                           1,
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			ci, cj := confRank[out[i].Confidence], confRank[out[j].Confidence]
			if cj > ci || (cj == ci && out[j].RiskScore > out[i].RiskScore) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func severityRGB(sev string) [3]int {
	switch sev {
	case "critical":
		return [3]int{190, 40, 40}
	case "high":
		return [3]int{210, 100, 20}
	case "medium":
		return [3]int{190, 150, 30}
	case "low":
		return [3]int{50, 130, 60}
	default:
		return [3]int{50, 90, 170}
	}
}

func riskRGB(rating string) [3]int {
	switch rating {
	case "CRITICAL":
		return [3]int{255, 90, 90}
	case "HIGH":
		return [3]int{255, 160, 60}
	case "MEDIUM":
		return [3]int{255, 220, 80}
	default:
		return [3]int{130, 230, 130}
	}
}

func pdfSafe(s string) string {
	if s == "" {
		return ""
	}
	s = nonASCIIRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

func truncatePDF(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	_, _, err := image.Decode(bytes.NewReader(assets.LogoPNG))
	if err != nil {
		// logo optional fallback
	}
}
