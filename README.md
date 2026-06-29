# Subhunter

Subhunter is a subdomain enumeration tool that aggregates results from multiple intelligence sources, similar in spirit to ProjectDiscovery's subfinder.

## Installation

```bash
go install github.com/AliHzSec/subhunter/cmd/subhunter@latest
```

Or build from source:

```bash
git clone https://github.com/AliHzSec/subhunter.git
cd subhunter
go build -o subhunter ./cmd/subhunter
```

## Usage

```
subhunter [flags]

Flags:
INPUT:
   -d,  -domain string[]           domains to find subdomains for
   -dl, -domain-list string        file containing list of domains for subdomain discovery

SOURCE:
   -a,  -all                       use all sources for enumeration
   -s,  -sources string[]          specific sources to use for discovery (-s crtsh,sourcegraph)
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es securitytrails,shodan)
   -ls, -list-sources              display all available sources

OUTPUT:
   -o,  -output string             file to write output to
   -oJ, -json                      write output in JSONL(ines) format
   -oD, -output-dir string         directory to write output
   -oS, -output-sources            split all sources in the output

CONFIGURATION:
   -config string                  flag config file (default "~/.config/subhunter/config.yaml")
   -p,  -proxy string              http proxy to use with subhunter
   -ct, -capsolver-token string    capsolver API token (overrides config)
   -cp, -capsolver-proxy string    proxy for capsolver requests (overrides config)
   -r,  -retry int                 number of retries (default 3)
   -c,  -concurrency int           number of concurrent sources (default 1)
   -timeout int                    seconds to wait before timing out (default 120)
   -nc, -no-color                  disable color in output

DEBUG:
   -silent                         show only subdomains in output
   -stats                          report source statistics
   -version                        display the current version
```

## Config File Setup

On first run, subhunter creates a default config at `~/.config/subhunter/config.yaml` (permissions `0600`):

```yaml
global:
  proxy: ""
  retry: 3
  timeout: 120
  concurrency: 1

capsolver:
  token: ""
  proxy: ""

sources:
  shodan:
    api_key: ""

  c99:
    api_key: ""

  securitytrails:
    email: ""
    password: ""

  sourcegraph:
    access_token: ""

  cloudsni:
    data_dir: "~/.cloud-sni-data"

  abuseipdb:
    session_cookie: ""
    use_capsolver: true
```

Fill in the credentials for the sources you want to use. Sources with empty credentials are automatically skipped with a `[WRN]` log line.

### Source Notes

| Source | Credentials Required | Notes |
|--------|---------------------|-------|
| `crtsh` | None | Queries crt.sh PostgreSQL database directly |
| `shodan` | `api_key` | Shodan DNS API |
| `c99` | `api_key` | c99.nl subdomain finder API |
| `securitytrails` | `email`, `password`, Capsolver token | Scrapes SecurityTrails web UI with CF bypass |
| `sourcegraph` | `access_token` | Requires `src` CLI: `go install github.com/sourcegraph/src-cli/cmd/src@latest` |
| `cloudsni` | None (needs `data_dir`) | Downloads SNI files from kaeferjaeger.gay and searches locally |
| `abuseipdb` | `session_cookie` | Scrapes AbuseIPDB WHOIS pages; optional CF bypass via Capsolver |

## Usage Examples

```bash
# Single domain (uses all configured sources by default)
subhunter -d example.com

# Multiple domains
subhunter -d example.com,sub.example.org

# Domain list from file
subhunter -dl domains.txt

# From stdin
echo "example.com" | subhunter

# Use only specific sources
subhunter -d example.com -s crtsh,shodan

# Use all sources, exclude some
subhunter -d example.com -a -es securitytrails,abuseipdb

# Write output to file (tee: also prints to stdout)
subhunter -d example.com -o results.txt

# JSONL output
subhunter -d example.com -oJ -o results.jsonl

# Split output by source
subhunter -d example.com -oS -oD ./output-dir/

# With proxy and Capsolver (for CloudFlare-protected sources)
subhunter -d example.com -p http://proxy:8080 -ct YOUR_CAPSOLVER_TOKEN

# Override Capsolver proxy independently
subhunter -d example.com -ct YOUR_TOKEN -cp http://capsolver-proxy:8080

# Show statistics table after enumeration
subhunter -d example.com -stats

# Silent mode (only subdomains, no logs)
subhunter -d example.com -silent

# List available sources
subhunter -ls

# Run 3 sources concurrently
subhunter -d example.com -c 3
```

## JSONL Output Format

When `-oJ` is used, each line is a JSON object:

```json
{"host":"dev.example.com","input":"example.com","source":"crtsh"}
{"host":"api.example.com","input":"example.com","source":["crtsh","shodan"]}
```

If a subdomain is found by multiple sources, `source` is an array.

## Stats Output

With `-stats`:

```
Source             Results     Duration   STATUS
────────────────────────────────────────────────────────────────────
abuseipdb           0             0.3s       SKIPPED
c99                 28            1.5s       OK
cloudsni            89            0.9s       OK
crtsh               312           4.8s       OK
securitytrails      67            8.2s       SKIPPED
shodan              45            2.1s       OK
sourcegraph         15            12.4s      OK

----------------------------------------
Total sources run:       7
Successful:              4
Skipped:                 2
Failed:                  0
Total unique subdomains: 32
Total time:              30.0s
```

## Timeout Semantics

`-timeout` applies **per individual HTTP request**, not per source total runtime. Sources like SecurityTrails that paginate through many pages can legitimately take several minutes total — only each individual HTTP request is bounded by the timeout.
