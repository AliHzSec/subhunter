package stats

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/AliHzSec/subhunter/internal/sources"
)

type Stats struct {
	results []sources.Result
}

func New() *Stats {
	return &Stats{}
}

func (s *Stats) Add(r sources.Result) {
	s.results = append(s.results, r)
}

func (s *Stats) Print(w io.Writer, totalUnique int, totalDuration float64) {
	// Sort by source name for consistent output
	sorted := make([]sources.Result, len(s.results))
	copy(sorted, s.results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Source < sorted[j].Source
	})

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "Source\tResults\tDuration\tSTATUS")
	fmt.Fprintln(tw, "────────────────────────────────────────────────────────────────────")

	var ok, skipped, failed int
	for _, r := range sorted {
		fmt.Fprintf(tw, "%s\t%d\t%.1fs\t%s\n",
			r.Source,
			len(r.Subdomains),
			r.Duration.Seconds(),
			r.Status,
		)
		switch r.Status {
		case sources.StatusOK:
			ok++
		case sources.StatusSkipped:
			skipped++
		case sources.StatusFailed:
			failed++
		}
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "----------------------------------------")
	fmt.Fprintf(w, "Total sources run:       %d\n", len(sorted))
	fmt.Fprintf(w, "Successful:              %d\n", ok)
	fmt.Fprintf(w, "Skipped:                 %d\n", skipped)
	fmt.Fprintf(w, "Failed:                  %d\n", failed)
	fmt.Fprintf(w, "Total unique subdomains: %d\n", totalUnique)
	fmt.Fprintf(w, "Total time:              %.1fs\n", totalDuration)
}
