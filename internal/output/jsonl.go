package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/AliHzSec/subhunter/internal/sources"
)

// SubdomainEntry tracks a discovered subdomain and which sources found it.
type SubdomainEntry struct {
	Host    string
	Input   string
	Sources []string
}

// Tracker deduplicates subdomains across sources and tracks origins.
type Tracker struct {
	entries map[string]*SubdomainEntry // key = host
}

func NewTracker() *Tracker {
	return &Tracker{entries: map[string]*SubdomainEntry{}}
}

func (t *Tracker) Add(host, input, source string) {
	if e, ok := t.entries[host]; ok {
		e.Sources = append(e.Sources, source)
	} else {
		t.entries[host] = &SubdomainEntry{Host: host, Input: input, Sources: []string{source}}
	}
}

func (t *Tracker) AddResult(r sources.Result, input string) {
	for _, sub := range r.Subdomains {
		t.Add(sub, input, r.Source)
	}
}

func (t *Tracker) UniqueHosts() []string {
	hosts := make([]string, 0, len(t.entries))
	for h := range t.entries {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func (t *Tracker) Entries() []*SubdomainEntry {
	hosts := t.UniqueHosts()
	out := make([]*SubdomainEntry, len(hosts))
	for i, h := range hosts {
		out[i] = t.entries[h]
	}
	return out
}

type jsonlLine struct {
	Host   string      `json:"host"`
	Input  string      `json:"input"`
	Source interface{} `json:"source"`
}

// WriteJSONL writes JSONL output to w. If a host was found by multiple sources,
// source is a JSON array; otherwise it's a string.
func WriteJSONL(w io.Writer, entries []*SubdomainEntry) error {
	for _, e := range entries {
		var src interface{}
		if len(e.Sources) == 1 {
			src = e.Sources[0]
		} else {
			src = e.Sources
		}
		line := jsonlLine{Host: e.Host, Input: e.Input, Source: src}
		data, err := json.Marshal(line)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s\n", data); err != nil {
			return err
		}
	}
	return nil
}
