package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/AliHzSec/subhunter/internal/sources"
)

// SplitWriter writes per-source output files named <source>.txt.
type SplitWriter struct {
	dir     string
	buffers map[string][]string // source -> list of subdomains
}

func NewSplitWriter(dir string) *SplitWriter {
	if dir == "" {
		dir = "."
	}
	return &SplitWriter{dir: dir, buffers: map[string][]string{}}
}

func (sw *SplitWriter) AddResult(r sources.Result) {
	if len(r.Subdomains) == 0 {
		return
	}
	sw.buffers[r.Source] = append(sw.buffers[r.Source], r.Subdomains...)
}

func (sw *SplitWriter) Flush() error {
	for source, subs := range sw.buffers {
		sort.Strings(subs)
		path := filepath.Join(sw.dir, source+".txt")
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		for _, s := range subs {
			fmt.Fprintln(f, s)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}
