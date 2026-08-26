// Package output renders cavet's normative result blocks: markdown tables with
// an aggregate line and next-step hints, golden-tested against spec §4.1
// (cli-spec §9). The CLI speaks CLI: hints never reference skills or agents.
package output

import (
	"fmt"
	"sort"
	"strings"
)

// Counts carries pre-computed aggregates so no consumer round-trips to work
// out what it is facing (spec §4 principle 3).
type Counts struct {
	Confirmed                            int
	Critical, High, Medium, Low, Info    int
	Dismissed, Suppressed, Baseline      int
}

// FindingView is one confirmed row. Path and Line stay structured so the
// sort order (severity desc, path asc, line asc) is exact, not lexical.
type FindingView struct {
	ID   string
	Sev  string
	Rule string
	Path string
	Line int
	Desc string
}

type ScanView struct {
	Scope       string
	Scanners    []string
	Phase       string
	EngineShort string
	Counts      Counts
	Findings    []FindingView
	Hints       []string
}

const descLimit = 60

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// RenderResult renders the normative result block. Empty states are explicit
// strings, never silence (spec §4 principle 4).
func RenderResult(v ScanView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scan: %s · scanners: %s · phase: %s · engine: %s\n",
		v.Scope, strings.Join(v.Scanners, ","), v.Phase, v.EngineShort)
	b.WriteString(aggregate(v.Counts))
	b.WriteString("\n\n")
	if len(v.Findings) == 0 {
		b.WriteString("0 new findings\n")
	} else {
		b.WriteString(renderTable(v.Findings))
	}
	if len(v.Hints) > 0 {
		b.WriteString("\nnext:\n")
		for _, h := range v.Hints {
			fmt.Fprintf(&b, "  %s\n", h)
		}
	}
	return b.String()
}

func aggregate(c Counts) string {
	head := fmt.Sprintf("%d confirmed", c.Confirmed)
	if c.Confirmed > 0 {
		head += " (" + breakdown(c) + ")"
	}
	parts := []string{head,
		fmt.Sprintf("%d dismissed", c.Dismissed),
		fmt.Sprintf("%d new suppressions", c.Suppressed)}
	if c.Baseline > 0 {
		parts = append(parts, fmt.Sprintf("baseline %d", c.Baseline))
	}
	return strings.Join(parts, " · ")
}

func breakdown(c Counts) string {
	var parts []string
	for _, p := range []struct {
		n int
		s string
	}{
		{c.Critical, "critical"}, {c.High, "high"}, {c.Medium, "medium"},
		{c.Low, "low"}, {c.Info, "info"},
	} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.s))
		}
	}
	return strings.Join(parts, ", ")
}

func renderTable(fs []FindingView) string {
	sorted := append([]FindingView(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sevRank[sorted[i].Sev], sevRank[sorted[j].Sev]
		if ri != rj {
			return ri < rj
		}
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].Line < sorted[j].Line
	})

	headers := []string{"id", "sev", "rule", "location", "description"}
	rows := make([][]string, 0, len(sorted))
	for _, f := range sorted {
		rows = append(rows, []string{
			f.ID, f.Sev, f.Rule,
			fmt.Sprintf("%s:%d", f.Path, f.Line),
			truncate(f.Desc),
		})
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	var b strings.Builder
	writeRow := func(cells []string) {
		b.WriteString("|")
		for i, c := range cells {
			fmt.Fprintf(&b, " %s%s |", c, strings.Repeat(" ", widths[i]-len(c)))
		}
		b.WriteString("\n")
	}
	writeRow(headers)
	b.WriteString("|")
	for _, w := range widths {
		b.WriteString(strings.Repeat("-", w+2))
		b.WriteString("|")
	}
	b.WriteString("\n")
	for _, r := range rows {
		writeRow(r)
	}
	return b.String()
}

// truncate clips to descLimit runes including the ellipsis.
func truncate(s string) string {
	r := []rune(s)
	if len(r) <= descLimit {
		return s
	}
	return string(r[:descLimit-1]) + "…"
}
