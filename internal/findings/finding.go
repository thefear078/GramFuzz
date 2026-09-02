package findings

import (
	"strings"
	"time"
)

// Confidence levels for findings.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceManual    = "manual-test"
	ConfidencePlaybook  = "playbook"
	ConfidenceInfo      = "info"
)

// Finding represents a discovered security issue.
type Finding struct {
	ID              string    `json:"id"`
	Severity        string    `json:"severity"`
	Module          string    `json:"module"`
	Category        string    `json:"category,omitempty"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Evidence        string    `json:"evidence"`
	CWE             string    `json:"cwe,omitempty"`
	Remediation     string    `json:"remediation,omitempty"`
	RemediationPlan string    `json:"remediation_plan,omitempty"`
	RiskScore       int       `json:"risk_score"`
	PoC             string    `json:"poc,omitempty"`
	Confidence      string    `json:"confidence,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	Impact          string    `json:"impact,omitempty"`
	Steps           string    `json:"steps,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
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

// WithDetail adds confidence, tags, impact, verification steps, and remediation plan.
func (f Finding) WithDetail(confidence string, tags []string, impact, steps, plan string) Finding {
	f.Confidence = confidence
	f.Tags = tags
	f.Impact = impact
	f.Steps = steps
	f.RemediationPlan = plan
	return f
}

// IsActionable returns true if the finding should affect actionable risk rating.
func (f Finding) IsActionable() bool {
	switch f.Confidence {
	case ConfidenceConfirmed, ConfidenceLikely:
		return true
	default:
		return false
	}
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
	Total            int            `json:"total"`
	Actionable       int            `json:"actionable"`
	ManualTests      int            `json:"manual_tests"`
	PlaybookItems    int            `json:"playbook_items"`
	BySeverity       map[string]int `json:"by_severity"`
	ByConfidence     map[string]int `json:"by_confidence"`
	ByCategory       map[string]int `json:"by_category"`
	MaxRisk          int            `json:"max_risk"`
	AvgRisk          float64        `json:"avg_risk"`
	ActionableMax    int            `json:"actionable_max_risk"`
	RiskRating       string         `json:"risk_rating"`
	ActionableRating string         `json:"actionable_rating"`
}

func Summarize(list []Finding) Summary {
	s := Summary{
		BySeverity:   map[string]int{},
		ByConfidence: map[string]int{},
		ByCategory:   map[string]int{},
	}
	var riskSum, actionableSum int
	for _, f := range list {
		s.Total++
		s.BySeverity[f.Severity]++
		conf := f.Confidence
		if conf == "" {
			conf = "unset"
		}
		s.ByConfidence[conf]++
		if f.Category != "" {
			s.ByCategory[f.Category]++
		}
		switch f.Confidence {
		case ConfidenceManual:
			s.ManualTests++
		case ConfidencePlaybook, ConfidenceInfo:
			s.PlaybookItems++
		}
		if f.RiskScore > s.MaxRisk {
			s.MaxRisk = f.RiskScore
		}
		riskSum += f.RiskScore

		if f.IsActionable() {
			s.Actionable++
			actionableSum += f.RiskScore
			if f.RiskScore > s.ActionableMax {
				s.ActionableMax = f.RiskScore
			}
		}
	}
	if s.Total > 0 {
		s.AvgRisk = float64(riskSum) / float64(s.Total)
	}
	s.RiskRating = ratingFromMax(s.MaxRisk)
	s.ActionableRating = ratingFromMax(s.ActionableMax)
	return s
}

func ratingFromMax(max int) string {
	switch {
	case max >= 9:
		return "CRITICAL"
	case max >= 7:
		return "HIGH"
	case max >= 4:
		return "MEDIUM"
	case max >= 2:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// TagsString joins tags for display.
func TagsString(tags []string) string {
	return strings.Join(tags, ", ")
}
