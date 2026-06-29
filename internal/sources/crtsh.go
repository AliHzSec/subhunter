package sources

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/AliHzSec/subhunter/internal/config"
	"github.com/AliHzSec/subhunter/internal/logger"
	"github.com/jackc/pgx/v5"
)

type CrtshSource struct{}

func (s *CrtshSource) Name() string { return "crtsh" }

func (s *CrtshSource) ConfigCheck(_ *config.Config) (bool, string) { return true, "" }

func (s *CrtshSource) Run(ctx context.Context, domain string, cfg *config.Config) Result {
	start := time.Now()
	subdomains, err := s.fetch(ctx, domain, cfg)
	dur := time.Since(start)
	if err != nil {
		logger.Errorf("[crtsh] %v", err)
		return Result{Source: s.Name(), Status: StatusFailed, Err: err, Duration: dur}
	}
	return Result{Source: s.Name(), Subdomains: subdomains, Status: StatusOK, Duration: dur}
}

const crtshQuery = `
SELECT ci.NAME_VALUE
FROM certificate_and_identities ci
WHERE plainto_tsquery('certwatch', $1) @@ identities(ci.CERTIFICATE)
`

func (s *CrtshSource) fetch(ctx context.Context, domain string, cfg *config.Config) ([]string, error) {
	connStr := "host=crt.sh port=5432 user=guest dbname=certwatch sslmode=prefer"

	// crtsh needs no credentials — it queries the public crt.sh Postgres replica.
	logger.Debugf("[crtsh] no credentials required")
	logger.Debugf("[crtsh] connection string: %s", connStr)
	logger.Debugf("[crtsh] query: %s", crtshQuery)

	timeoutSecs := cfg.Global.Timeout
	if timeoutSecs <= 0 {
		timeoutSecs = 120
	}
	connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	// crt.sh sits behind PgBouncer in transaction-pooling mode. pgx's default
	// behaviour caches prepared statements per logical connection, but a pooler
	// can route successive queries to different backend sessions, so a cached
	// statement from session A is unknown to session B — producing SQLSTATE 26000
	// ("prepared statement does not exist"). Simple-protocol mode sends each
	// query as plain text with inline parameters and never touches the prepared-
	// statement cache, which is the correct mode for pooler-fronted connections.
	connCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parse connection config: %w", err)
	}
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(connCtx, connCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to crt.sh: %w", err)
	}
	defer conn.Close(ctx)

	logger.Successf("[crtsh] connected, querying for %s", domain)

	rows, err := conn.Query(connCtx, crtshQuery, domain)
	if err != nil {
		return nil, fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

	pattern := regexp.MustCompile(`(?i).*\.` + regexp.QuoteMeta(domain) + `$`)
	seen := map[string]bool{}
	var results []string
	rawCount := 0

	for rows.Next() {
		rawCount++
		var nameValue string
		if err := rows.Scan(&nameValue); err != nil {
			logger.Warningf("[crtsh] scan error on row %d: %v", rawCount, err)
			continue
		}
		// Strip spaces (crt.sh can include spaces in SAN values) and trailing
		// newlines — Go's regexp $ anchor requires exact end-of-text, unlike
		// Python's re which matches before a terminal \n.
		nameValue = strings.TrimRight(strings.ReplaceAll(nameValue, " ", ""), "\r\n")
		if pattern.MatchString(nameValue) {
			nameValue = strings.ReplaceAll(nameValue, "*.", "")
			nameValue = strings.ToLower(nameValue)
			if !seen[nameValue] {
				seen[nameValue] = true
				results = append(results, nameValue)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	logger.Debugf("[crtsh] raw rows from DB: %d, after filter/dedup: %d", rawCount, len(results))
	logger.Successf("[crtsh] found %d subdomains for %s", len(results), domain)
	return results, nil
}
