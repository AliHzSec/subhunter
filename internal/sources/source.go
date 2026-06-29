package sources

import (
	"context"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
)

const (
	StatusOK      = "OK"
	StatusFailed  = "FAILED"
	StatusSkipped = "SKIPPED"
)

type Result struct {
	Source     string
	Subdomains []string
	Duration   time.Duration
	Status     string
	Err        error
}

type Source interface {
	Name() string
	// ConfigCheck reports whether the source is properly configured.
	// If not, it returns false with a human-readable reason describing what is missing.
	ConfigCheck(cfg *config.Config) (bool, string)
	Run(ctx context.Context, domain string, cfg *config.Config) Result
}
