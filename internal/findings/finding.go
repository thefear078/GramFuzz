package findings

import "time"

// Finding represents a discovered security issue.
type Finding struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Module      string    `json:"module"`
	Category    string    `json:"category,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	CWE         string    `json:"cwe,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	RiskScore   int       `json:"risk_score"`
	PoC         string    `json:"poc,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// New creates a finding with computed risk score from severity.
func New(id, severity, module, category, title, description, evidence string) Finding {
	return Finding{
		ID: id, Severity: severity, Module: module, Category: category,
		Title: title, Description: description, Evidence: evidence,
		RiskScore: SeverityScore(severity), Timestamp: time.Now(),
	}
}

// WithMeta adds CWE, remediation, and PoC to a finding.
func (f Finding) WithMeta(cwe, remediation, poc string) Finding {
	f.CWE = cwe
	f.Remediation = remediation
	f.PoC = poc
	return f
}

// SeverityScore maps severity label to numeric risk (0-10).
func SeverityScore(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 2
	default:
		return 1
	}
}

// Summary computes engagement statistics.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	MaxRisk    int            `json:"max_risk"`
	AvgRisk    float64        `json:"avg_risk"`
	RiskRating string         `json:"risk_rating"`
}

func Summarize(list []Finding) Summary {
	s := Summary{
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
	}
	var riskSum int
	for _, f := range list {
		s.Total++
		s.BySeverity[f.Severity]++
		if f.Category != "" {
			s.ByCategory[f.Category]++
		}
		if f.RiskScore > s.MaxRisk {
			s.MaxRisk = f.RiskScore
		}
		riskSum += f.RiskScore
	}
	if s.Total > 0 {
		s.AvgRisk = float64(riskSum) / float64(s.Total)
	}
	switch {
	case s.MaxRisk >= 9:
		s.RiskRating = "CRITICAL"
	case s.MaxRisk >= 7:
		s.RiskRating = "HIGH"
	case s.MaxRisk >= 4:
		s.RiskRating = "MEDIUM"
	case s.MaxRisk >= 2:
		s.RiskRating = "LOW"
	default:
		s.RiskRating = "INFORMATIONAL"
	}
	return s
}
