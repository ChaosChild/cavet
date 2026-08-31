package lookup

import (
	"fmt"
	"strings"
)

// Render reduces rows to one compact markdown table carrying only what
// changes a triage decision (spec §5.3) — not the advisory prose. The url
// column carries the canonical source URL so verdicts cite identifier + URL.
func Render(rows []Row) string {
	if len(rows) == 0 {
		return "no results\n"
	}
	headers := []string{"id", "severity", "range", "fixed", "kev", "epss", "summary", "url"}
	cells := func(r Row) []string {
		return []string{r.ID, r.Severity, r.Range, r.Fixed, r.KEV, r.EPSS, r.Summary, r.URL}
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range cells(r) {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	var b strings.Builder
	write := func(cs []string) {
		b.WriteString("|")
		for i, c := range cs {
			fmt.Fprintf(&b, " %s%s |", c, strings.Repeat(" ", widths[i]-len(c)))
		}
		b.WriteString("\n")
	}
	write(headers)
	b.WriteString("|")
	for _, w := range widths {
		b.WriteString(strings.Repeat("-", w+2))
		b.WriteString("|")
	}
	b.WriteString("\n")
	for _, r := range rows {
		write(cells(r))
	}
	for _, r := range rows {
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "note: %s: %s\n", r.ID, n)
		}
	}
	return b.String()
}
