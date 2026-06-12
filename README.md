# Shodan-Go CLI

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/doc/install)
[![Build](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml)
[![Test](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml)
[![Lint](https://img.shields.io/badge/lint-golangci--lint-blue)](.golangci.yml)
[![Release](https://img.shields.io/github/v/release/mar0ls/shodan_go)](https://github.com/mar0ls/shodan_go/releases/latest)
[![Docs](https://img.shields.io/badge/docs-DOCUMENTATION.md-brightgreen)](docs/DOCUMENTATION.md)

A command-line interface for the Shodan API written in Go.

[Go 1.25+](https://go.dev/doc/install) • [Code Documentation](docs/DOCUMENTATION.md)

## Overview

`shodan_go` exposes the most common Shodan endpoints through a single binary:
account info, host lookup, paginated search, count, DNS records, hostname
resolution, reverse DNS and your public IP.

## Features

- Seven commands: `host`, `search`, `count`, `dns`, `resolve`, `reverse`, `myip`
- `context.Context` on every request; 30 s HTTP client timeout
- API key passed via `url.Values`, never via `fmt.Sprintf`
- API key stripped from error messages by `sanitizeErr`
- IP / domain path components encoded with `url.PathEscape`
- Search pagination (`--page`, `--all`) with retry and exponential backoff
- JSON export via `--out`, with path sanitization (no `..` traversal)
- Generated reference docs in [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)

## Requirements

- Go `1.25` or newer
- A Shodan API key
- Network access to `https://api.shodan.io`

## Installation

### Download pre-built binary

Grab the latest release from [GitHub Releases](https://github.com/mar0ls/shodan_go/releases/latest):

```bash
# Linux (amd64)
tar -xzf shodan-go-linux-amd64.tar.gz
./shodan-go --help

# macOS (Apple Silicon)
tar -xzf shodan-go-macos-arm64.tar.gz
./shodan-go --help

# Windows (amd64) — extract shodan-go-windows-amd64.zip
```

### Build from source

```bash
git clone https://github.com/mar0ls/shodan_go.git
cd shodan_go
go build -o shodan-go .
```

Or run from source without building:

```bash
go run .
```

## Security

| Concern | Mitigation |
|---------|------------|
| API key in URLs | Passed via `url.Values`, never via `fmt.Sprintf` |
| API key in error messages | `sanitizeErr` strips the key from `*url.Error` before logging |
| URL/path injection via IP parameter | `url.PathEscape` applied before embedding in URL path |
| Output file path traversal | `filepath.Clean` + dotdot traversal check (absolute paths like `/tmp/out.json` are allowed) |
| Long-running / hanging requests | Every HTTP request uses `context.Context` + 30 s client timeout |
| Secret in source code | `SHODAN_API_KEY` is read from environment only — never hardcoded |

> Do not commit your `SHODAN_API_KEY`. Add `.env` to `.gitignore` and load it from your shell or CI secret store.

## Configuration

Set your API key via environment variable:

```bash
export SHODAN_API_KEY="your_api_key"
```

The CLI exits with an error if `SHODAN_API_KEY` is not set.

## Usage

General form:

```bash
./shodan-go <command> [options]
```

### Commands

| Command | Description |
|---|---|
| `host <ip>` | Show detailed information for one host IP |
| `search [options] <query>` | Search hosts by Shodan query |
| `count <query>` | Count results **without consuming query credits** |
| `dns [--all-records] <domain>` | DNS records and subdomains for a domain |
| `resolve <hostname> [...]` | Resolve one or more hostnames to IP addresses |
| `reverse <ip> [...]` | Reverse DNS lookup for one or more IPs |
| `myip` | Show your public IP address as seen by Shodan |

### Search options

| Option | Description |
|---|---|
| `--page N` | Fetch only page `N` (default: `1`) |
| `--all` | Fetch all pages (consumes additional credits) |
| `--out <file>` | Save full JSON result to a file (relative or absolute path) |
| `-h`, `--help` | Show usage and exit |

### Examples

```bash
# Host lookup
./shodan-go host 8.8.8.8

# Search, first page
./shodan-go search "apache country:PL"

# Search, specific page
./shodan-go search --page 3 "nginx country:DE"

# Search all pages and export JSON (relative path)
./shodan-go search --all --out results.json "webcam country:PL"

# Search all pages and export to absolute path
./shodan-go search --all --out /tmp/results.json "webcam country:PL"

# Count results without using credits
./shodan-go count "apache country:PL"

# DNS records and subdomains
./shodan-go dns example.com

# DNS records and subdomains (without output cap)
./shodan-go dns --all-records example.com

# Resolve hostnames to IPs
./shodan-go resolve google.com cloudflare.com

# Reverse DNS lookup
./shodan-go reverse 8.8.8.8 1.1.1.1

# Your public IP
./shodan-go myip

# Show help
./shodan-go --help

# Resume a previously interrupted search from page 38
./shodan-go search --page 38 --all --out results.json "webcam country:PL"

# Extract all IPs from JSON export
jq -r '.. | .ip_str? // empty' results.json | sort -u
```

### Error handling

With `--all` the CLI applies these safeguards between pages:

- **Rate-limit delay** — 1-second pause between page requests.
- **Retry with backoff** — each failed page is retried up to 3 times (2 s, 4 s, 6 s).
- **Partial results preserved** — collected pages are printed and saved with `--out` even if a later page fails.
- **Resume hint** — on failure the CLI logs the page number; re-run with `--page N --all` to continue.

Example resume command:

```bash
./shodan-go search --page 38 --all --out results.json "webcam country:PL"
```

## Testing

Run the full test suite with the race detector:

```bash
go test -race ./...
```

Coverage report:

```bash
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go tool cover -html=coverage.out
```

Overall coverage is around 76 %. Uncovered lines are the deprecated alias
wrappers and `main()` (it needs a live API key).

## Lint and docs

```bash
golangci-lint run -c ./.golangci.yml
./scripts/generate_docs.py
```

## Scripting Recipes

Bash and PowerShell snippets for common automation tasks.

### 1) Nightly count report (no query credits consumed)

```bash
#!/usr/bin/env bash
set -euo pipefail

query='apache country:PL'
timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

total="$(./shodan-go count "$query" | awk '/Total results:/ {print $3}')"
printf '%s query=%q total=%s\n' "$timestamp" "$query" "$total" >> shodan-counts.log
```

### 2) Save full search snapshot to JSON and extract unique IPs

```bash
#!/usr/bin/env bash
set -euo pipefail

query='nginx country:DE'
outfile="search-$(date +%F).json"

./shodan-go search --all --out "$outfile" "$query"
jq -r '.. | .ip_str? // empty' "$outfile" | sort -u > ips.txt
echo "Saved JSON: $outfile"
echo "Unique IPs: $(wc -l < ips.txt)"
```

### 3) Bulk hostname resolution from a file

Input file (`hosts.txt`):

```text
google.com
cloudflare.com
example.org
```

Script:

```bash
#!/usr/bin/env bash
set -euo pipefail

mapfile -t hosts < <(grep -v '^\s*$' hosts.txt)
./shodan-go resolve "${hosts[@]}" | tee resolved.txt
```

### 4) Reverse DNS enrichment for a list of IPs

Input file (`ips.txt`):

```text
8.8.8.8
1.1.1.1
9.9.9.9
```

Script:

```bash
#!/usr/bin/env bash
set -euo pipefail

mapfile -t ips < <(grep -v '^\s*$' ips.txt)
./shodan-go reverse "${ips[@]}" | tee reverse.txt
```

### 5) DNS inventory to file

```bash
#!/usr/bin/env bash
set -euo pipefail

domain='google.com'

# Capped output (50 records) — readable in a terminal
./shodan-go dns "$domain" > "dns-${domain}.txt"

# Full output — use for further processing
./shodan-go dns --all-records "$domain" > "dns-${domain}-all.txt"
```

### 6) Retry wrapper for unstable API windows (503/timeout)

```bash
#!/usr/bin/env bash
set -euo pipefail

run_with_retry() {
	local max_attempts=5
	local attempt=1
	local delay=2

	while true; do
		if "$@"; then
			return 0
		fi
		if (( attempt >= max_attempts )); then
			echo "command failed after $attempt attempts: $*" >&2
			return 1
		fi
		echo "attempt $attempt failed, retrying in ${delay}s..." >&2
		sleep "$delay"
		attempt=$((attempt + 1))
		delay=$((delay * 2))
	done
}

run_with_retry ./shodan-go host 8.8.8.8
```

### 7) Smoke test in CI

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${SHODAN_API_KEY:?SHODAN_API_KEY is required}"

./shodan-go myip > /dev/null
./shodan-go count 'ssl cert.subject.cn:example.com' > /dev/null
echo "Shodan CLI checks: OK"
```

### 8) PowerShell equivalents (Windows)

```powershell
$ErrorActionPreference = "Stop"

# Requires SHODAN_API_KEY in environment
if (-not $env:SHODAN_API_KEY) {
    throw "SHODAN_API_KEY is required"
}

# Count report
$query = "apache country:PL"
$countLine = .\shodan-go.exe count $query | Select-String "Total results:"
"{0} query='{1}' {2}" -f (Get-Date).ToUniversalTime().ToString("o"), $query, $countLine >> shodan-counts.log

# DNS output (capped and full)
.\shodan-go.exe dns google.com | Out-File -Encoding utf8 dns-google.txt
.\shodan-go.exe dns --all-records google.com | Out-File -Encoding utf8 dns-google-all.txt
```

### 9) Makefile shortcuts for recurring tasks

Create `Makefile`:

```makefile
SHODAN ?= ./shodan-go
QUERY ?= apache country:PL
DOMAIN ?= example.com
OUT ?= results.json

.PHONY: shodan-count shodan-search shodan-dns shodan-dns-all shodan-myip

shodan-count:
	$(SHODAN) count "$(QUERY)"

shodan-search:
	$(SHODAN) search --all --out "$(OUT)" "$(QUERY)"

shodan-dns:
	$(SHODAN) dns "$(DOMAIN)"

shodan-dns-all:
	$(SHODAN) dns --all-records "$(DOMAIN)"

shodan-myip:
	$(SHODAN) myip
```

Usage examples:

```bash
make shodan-count QUERY='nginx country:DE'
make shodan-search QUERY='ssl:cloudflare' OUT=cloudflare.json
make shodan-dns DOMAIN=google.com
```

## Building and Distribution

Helper scripts under `scripts/` build local and cross-platform binaries.

### POSIX (Linux/macOS)

```bash
# Local build -> ./shodan-go
./scripts/build.sh

# Cross-build examples
./scripts/build.sh linux-amd64
./scripts/build.sh macos-arm64
./scripts/build.sh windows-amd64

# Custom output base name
./scripts/build.sh local my-cli
```

### PowerShell (Windows)

```powershell
# Local build -> .\shodan-go.exe
./scripts/build.ps1

# Cross-build examples
./scripts/build.ps1 -Target linux-amd64
./scripts/build.ps1 -Target windows-amd64

# Custom output base name
./scripts/build.ps1 -Target local -Out shodan-go.exe
```

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       ├── build.yml        # CI: build matrix (Linux/macOS/Windows) + cross-compile
│       └── test.yml         # CI: race tests, coverage upload, golangci-lint
├── api/
│   ├── shodan.go            # Client struct, Option pattern, sanitizeErr
│   ├── api.go               # GetAPIInfo
│   ├── host.go              # SearchHosts, GetHostByIP, CountHosts, host types
│   ├── dns.go               # GetDomain, ResolveHostnames, ReverseIPs, MyIP
│   ├── client_test.go       # httptest-based API tests
│   └── dns_test.go          # httptest-based DNS/count API tests
├── docs/                    # Auto-generated documentation
├── scripts/                 # Build and docs generation helpers
├── main.go                  # CLI entrypoint (all commands)
├── main_test.go             # Unit tests for CLI functions
├── .golangci.yml            # Lint/formatter configuration
└── go.mod
```

## Documentation

- [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) — generated reference for all exported symbols.

## Contributing

Issues and pull requests are welcome. Run `go test -race ./...` and
`golangci-lint run ./...` before opening a PR.
