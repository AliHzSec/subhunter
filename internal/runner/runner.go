package runner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/logger"
	"github.com/AliHzSec/subhunter/internal/output"
	"github.com/AliHzSec/subhunter/internal/sources"
	"github.com/AliHzSec/subhunter/internal/stats"
)

// Options holds all parsed CLI options.
type Options struct {
	Domains        []string
	DomainList     string
	UseAll         bool
	Sources        []string
	ExcludeSources []string
	ListSources    bool
	OutputFile     string
	OutputJSON     bool
	OutputDir      string
	OutputSplit    bool
	ConfigPath     string
	Proxy          string
	CapsolverToken string
	CapsolverProxy string
	Retry          int
	Concurrency    int
	Timeout        int
	NoColor        bool
	Silent         bool
	Debug          bool
	ShowStats      bool
	Version        bool
}

// Runner orchestrates subdomain enumeration.
type Runner struct {
	opts *Options
	cfg  *config.Config
}

func New(opts *Options) (*Runner, error) {
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Infof("Config not found at %s, creating default...", cfgPath)
			if writeErr := config.WriteDefault(cfgPath); writeErr != nil {
				logger.Warningf("Could not write default config: %v", writeErr)
			} else {
				logger.Infof("Default config written to %s — please fill in your credentials", cfgPath)
			}
			cfg = &config.Config{}
			cfg.Global.Retry = 3
			cfg.Global.Timeout = 120
			cfg.Global.Concurrency = 1
		} else {
			return nil, fmt.Errorf("loading config: %w", err)
		}
	}

	// CLI flags override config values
	if opts.Proxy != "" {
		cfg.Global.Proxy = opts.Proxy
	}
	if opts.CapsolverToken != "" {
		cfg.Capsolver.Token = opts.CapsolverToken
	}
	if opts.CapsolverProxy != "" {
		cfg.Capsolver.Proxy = opts.CapsolverProxy
	}
	if opts.Retry > 0 {
		cfg.Global.Retry = opts.Retry
	}
	if opts.Concurrency > 0 {
		cfg.Global.Concurrency = opts.Concurrency
	}
	if opts.Timeout > 0 {
		cfg.Global.Timeout = opts.Timeout
	}

	return &Runner{opts: opts, cfg: cfg}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	// Load domains
	domains, err := r.loadDomains()
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided")
	}

	// Resolve which sources to run
	activeSources, err := r.resolveSources()
	if err != nil {
		return err
	}

	// Set up output
	writer, err := output.NewWriter(r.opts.OutputFile)
	if err != nil {
		return fmt.Errorf("opening output file: %w", err)
	}
	defer writer.Close()

	var splitWriter *output.SplitWriter
	if r.opts.OutputSplit {
		splitWriter = output.NewSplitWriter(r.opts.OutputDir)
	}

	st := stats.New()
	tracker := output.NewTracker()
	globalStart := time.Now()

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		logger.Infof("Enumerating subdomains for %s", domain)
		results := r.runSources(ctx, domain, activeSources)

		for _, res := range results {
			st.Add(res)
			tracker.AddResult(res, domain)
			if splitWriter != nil {
				splitWriter.AddResult(res)
			}
		}

		// Deduplicate and output
		seen := map[string]bool{}
		for _, res := range results {
			for _, sub := range res.Subdomains {
				if !seen[sub] {
					seen[sub] = true
					if !r.opts.OutputJSON {
						writer.Write(sub)
					}
				}
			}
		}

		totalUnique := len(seen)
		elapsed := time.Since(globalStart)
		logger.Infof("Found %d subdomains for %s in %d seconds", totalUnique, domain, int(elapsed.Seconds()))

		if r.opts.ShowStats {
			logger.Infof("Printing source statistics for %s", domain)
			fmt.Fprintln(os.Stderr)
			st.Print(os.Stderr, totalUnique, elapsed.Seconds())
		}
	}

	// JSONL output
	if r.opts.OutputJSON {
		entries := tracker.Entries()
		var out *os.File
		if r.opts.OutputFile != "" {
			out, err = os.Create(r.opts.OutputFile)
			if err != nil {
				return err
			}
			defer out.Close()
		} else {
			out = os.Stdout
		}
		if err := output.WriteJSONL(out, entries); err != nil {
			return err
		}
	}

	// Split output files
	if splitWriter != nil {
		if err := splitWriter.Flush(); err != nil {
			logger.Errorf("writing split output: %v", err)
		}
	}

	return nil
}

func (r *Runner) runSources(ctx context.Context, domain string, srcs []sources.Source) []sources.Result {
	concurrency := r.cfg.Global.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	type work struct {
		src sources.Source
	}
	workCh := make(chan work, len(srcs))
	for _, s := range srcs {
		workCh <- work{src: s}
	}
	close(workCh)

	results := make([]sources.Result, 0, len(srcs))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				ok, reason := w.src.ConfigCheck(r.cfg)
				if !ok {
					logger.Warningf("Skipping source %s: %s", w.src.Name(), reason)
					res := sources.Result{
						Source: w.src.Name(),
						Status: sources.StatusSkipped,
					}
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
					continue
				}
				res := w.src.Run(ctx, domain, r.cfg)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results
}

func (r *Runner) resolveSources() ([]sources.Source, error) {
	all := sources.All()

	// -s: run only specified sources
	if len(r.opts.Sources) > 0 {
		var out []sources.Source
		for _, name := range r.opts.Sources {
			s := sources.ByName(strings.TrimSpace(name))
			if s == nil {
				return nil, fmt.Errorf("unknown source: %s", name)
			}
			out = append(out, s)
		}
		return out, nil
	}

	// Build exclusion set (only valid with -a or default)
	if len(r.opts.ExcludeSources) > 0 && !r.opts.UseAll {
		return nil, fmt.Errorf("-es/-exclude-sources is only valid when -a/-all is also passed")
	}

	excluded := map[string]bool{}
	for _, name := range r.opts.ExcludeSources {
		excluded[strings.TrimSpace(name)] = true
	}

	var out []sources.Source
	for _, s := range all {
		if !excluded[s.Name()] {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *Runner) loadDomains() ([]string, error) {
	var domains []string

	// From -d flag
	for _, d := range r.opts.Domains {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}

	// From -dl file
	if r.opts.DomainList != "" {
		f, err := os.Open(r.opts.DomainList)
		if err != nil {
			return nil, fmt.Errorf("opening domain list %s: %w", r.opts.DomainList, err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				domains = append(domains, line)
			}
		}
	}

	// From stdin if no domains given yet and stdin is piped
	if len(domains) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					domains = append(domains, line)
				}
			}
		}
	}

	return domains, nil
}

// ListSources prints all registered source names and exits.
func ListSources() {
	for _, name := range sources.Names() {
		fmt.Println(name)
	}
}
