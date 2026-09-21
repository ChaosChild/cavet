package cli

import (
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/store"
)

func TestUndecided(t *testing.T) {
	cases := []struct {
		name string
		f    store.Finding
		want bool
	}{
		{"open untriaged", store.Finding{Status: "open"}, true},
		{"deferred", store.Finding{Status: "deferred"}, true},
		{"dismissed", store.Finding{Status: "dismissed",
			Verdict: &store.Verdict{Verdict: "dismissed"}}, false},
		{"confirmed", store.Finding{Status: "confirmed",
			Verdict: &store.Verdict{Verdict: "confirmed"}}, false},
		{"suppressed", store.Finding{Status: "suppressed"}, false},
	}
	for _, tc := range cases {
		f := tc.f
		if got := undecided(&f); got != tc.want {
			t.Errorf("%s: undecided = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDebtTableHidesDecided(t *testing.T) {
	rows := []store.Finding{
		{DisplayID: "aaa111", Severity: "high", RuleID: "CVE-1", Status: "open"},
		{DisplayID: "bbb222", Severity: "low", RuleID: "CVE-2", Status: "dismissed",
			Verdict: &store.Verdict{Verdict: "dismissed"}},
	}
	got := debtTable(rows, false)
	if strings.Contains(got, "bbb222") {
		t.Error("decided row leaked into default debt table")
	}
	if !strings.Contains(got, "aaa111") {
		t.Error("undecided row missing from default debt table")
	}
	all := debtTable(rows, true)
	if !strings.Contains(all, "bbb222") || !strings.Contains(all, "dismissed") {
		t.Error("--all must show decided rows with their verdict")
	}
}
