package findings

import "testing"

func TestSeverityScore(t *testing.T) {
	cases := map[string]int{
		"critical": 10,
		"high":     8,
		"medium":   5,
		"low":      2,
		"info":     1,
		"unknown":  1,
	}
	for sev, want := range cases {
		if got := SeverityScore(sev); got != want {
			t.Errorf("SeverityScore(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestRatingFromMax(t *testing.T) {
	cases := map[int]string{
		10: "CRITICAL",
		9:  "CRITICAL",
		8:  "HIGH",
		7:  "HIGH",
		5:  "MEDIUM",
		4:  "MEDIUM",
		2:  "LOW",
		1:  "INFORMATIONAL",
		0:  "INFORMATIONAL",
	}
	for max, want := range cases {
		if got := ratingFromMax(max); got != want {
			t.Errorf("ratingFromMax(%d) = %q, want %q", max, got, want)
		}
	}
}

func TestIsActionable(t *testing.T) {
	actionable := []string{ConfidenceConfirmed, ConfidenceLikely}
	notActionable := []string{ConfidenceManual, ConfidencePlaybook, ConfidenceInfo, ""}
	for _, c := range actionable {
		if !(Finding{Confidence: c}).IsActionable() {
			t.Errorf("confidence %q should be actionable", c)
		}
	}
	for _, c := range notActionable {
		if (Finding{Confidence: c}).IsActionable() {
			t.Errorf("confidence %q should not be actionable", c)
		}
	}
}

// TestSummarizeSeparatesActionableFromManual verifies the core reporting
// contract: a high-severity manual-test finding must NOT inflate the actionable
// rating, while a confirmed finding must. This is what keeps scoped reports
// honest, so it is worth locking down.
func TestSummarizeActionableVsManual(t *testing.T) {
	list := []Finding{
		New("A", "critical", "m", "cat", "confirmed crit", "d", "e").
			WithDetail(ConfidenceConfirmed, nil, "", "", ""),
		New("B", "critical", "m", "cat", "manual crit", "d", "e").
			WithDetail(ConfidenceManual, nil, "", "", ""),
		New("C", "low", "m", "cat", "info", "d", "e").
			WithDetail(ConfidenceInfo, nil, "", "", ""),
	}
	s := Summarize(list)

	if s.Total != 3 {
		t.Fatalf("Total = %d, want 3", s.Total)
	}
	if s.Actionable != 1 {
		t.Errorf("Actionable = %d, want 1 (only the confirmed finding)", s.Actionable)
	}
	if s.ManualTests != 1 {
		t.Errorf("ManualTests = %d, want 1", s.ManualTests)
	}
	if s.ActionableMax != 10 {
		t.Errorf("ActionableMax = %d, want 10", s.ActionableMax)
	}
	if s.ActionableRating != "CRITICAL" {
		t.Errorf("ActionableRating = %q, want CRITICAL", s.ActionableRating)
	}
	// Raw max still reflects the manual critical.
	if s.MaxRisk != 10 {
		t.Errorf("MaxRisk = %d, want 10", s.MaxRisk)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(nil)
	if s.Total != 0 || s.Actionable != 0 {
		t.Fatalf("empty summary should be zero, got %+v", s)
	}
	if s.ActionableRating != "INFORMATIONAL" {
		t.Errorf("empty ActionableRating = %q, want INFORMATIONAL", s.ActionableRating)
	}
}
