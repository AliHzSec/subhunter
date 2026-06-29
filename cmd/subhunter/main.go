package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AliHzSec/subhunter/internal/logger"
	"github.com/AliHzSec/subhunter/internal/runner"
	"github.com/AliHzSec/subhunter/pkg/banner"
	"github.com/projectdiscovery/goflags"
)

const version = "1.0.0"

func main() {
	opts := &runner.Options{}

	// goflags uses its own StringSlice type; declare them here and convert below
	var (
		domains        goflags.StringSlice
		sources        goflags.StringSlice
		excludeSources goflags.StringSlice
	)

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Subhunter is a subdomain enumeration tool that aggregates results from multiple intelligence sources.")

	// INPUT
	flagSet.CreateGroup("INPUT", "Input",
		flagSet.StringSliceVarP(&domains, "domain", "d", nil, "domains to find subdomains for", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.DomainList, "domain-list", "dl", "", "file containing list of domains for subdomain discovery"),
	)

	// SOURCE
	flagSet.CreateGroup("SOURCE", "Source",
		flagSet.BoolVarP(&opts.UseAll, "all", "a", false, "use all sources for enumeration"),
		flagSet.StringSliceVarP(&sources, "sources", "s", nil, "specific sources to use for discovery (-s crtsh,sourcegraph)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&excludeSources, "exclude-sources", "es", nil, "sources to exclude from enumeration (-es securitytrails,shodan)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&opts.ListSources, "list-sources", "ls", false, "display all available sources"),
	)

	// OUTPUT
	flagSet.CreateGroup("OUTPUT", "Output",
		flagSet.StringVarP(&opts.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&opts.OutputJSON, "json", "oJ", false, "write output in JSONL(ines) format"),
		flagSet.StringVarP(&opts.OutputDir, "output-dir", "oD", "", "directory to write output"),
		flagSet.BoolVarP(&opts.OutputSplit, "output-sources", "oS", false, "split all sources in the output"),
	)

	// CONFIGURATION
	flagSet.CreateGroup("CONFIGURATION", "Configuration",
		flagSet.StringVar(&opts.ConfigPath, "config", "", "provider config file (default \"~/.config/subhunter/provider-config.yaml\")"),
		flagSet.StringVarP(&opts.Proxy, "proxy", "p", "", "http proxy to use with subhunter"),
		flagSet.StringVarP(&opts.CapsolverToken, "capsolver-token", "ct", "", "capsolver API token (overrides config)"),
		flagSet.StringVarP(&opts.CapsolverProxy, "capsolver-proxy", "cp", "", "proxy for capsolver requests (overrides config)"),
		flagSet.IntVarP(&opts.Retry, "retry", "r", 3, "number of retries"),
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 1, "number of concurrent sources"),
		flagSet.IntVar(&opts.Timeout, "timeout", 120, "seconds to wait before timing out"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "disable color in output"),
	)

	// DEBUG
	flagSet.CreateGroup("DEBUG", "Debug",
		flagSet.BoolVar(&opts.Silent, "silent", false, "show only subdomains in output"),
		flagSet.BoolVar(&opts.ShowStats, "stats", false, "report source statistics"),
		flagSet.BoolVar(&opts.Debug, "debug", false, "show full request/response debug info (proxy, tokens, status codes, headers)"),
		flagSet.BoolVar(&opts.Version, "version", false, "display the current version"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Convert goflags.StringSlice to []string
	opts.Domains = []string(domains)
	opts.Sources = []string(sources)
	opts.ExcludeSources = []string(excludeSources)

	// Apply global flags.
	// -debug and -silent are mutually exclusive in spirit; debug takes precedence
	// so full output is visible even if -silent was also passed.
	logger.Silent = opts.Silent
	logger.NoColor = opts.NoColor
	logger.DebugMode = opts.Debug

	if opts.Version {
		fmt.Printf("subhunter %s\n", version)
		return
	}

	if !opts.Silent {
		banner.Print()
	}

	if opts.ListSources {
		runner.ListSources()
		return
	}

	// Validate -es without -a
	if len(opts.ExcludeSources) > 0 && !opts.UseAll && len(opts.Sources) == 0 {
		logger.Fatal("-es/-exclude-sources is only valid when -a/-all is also passed")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	r, err := runner.New(opts)
	if err != nil {
		logger.Fatalf("Initialization error: %v", err)
	}

	if err := r.Run(ctx); err != nil {
		if ctx.Err() != nil {
			logger.Warning("Interrupted, shutting down...")
			os.Exit(1)
		}
		logger.Fatalf("%v", err)
	}
}
