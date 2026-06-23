# Shodan-Go CLI

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/doc/install)
[![Build](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml)
[![Test](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml)
[![Lint](https://img.shields.io/badge/lint-golangci--lint-blue)](.golangci.yml)
[![Release](https://img.shields.io/github/v/release/mar0ls/shodan_go)](https://github.com/mar0ls/shodan_go/releases/latest)

A command-line interface for the Shodan API, written in Go.

## Overview

`shodan_go` exposes the most common Shodan endpoints through a single binary:
host lookup, paginated search, count, DNS records, hostname resolution, reverse
DNS, and your public IP.

## Features

- Seven commands: `host`, `search`, `count`, `dns`, `resolve`, `reverse`, `myip`
- Search pagination (`--page`, `--all`) with retry and backoff
- Page and partial-result limits for automation: `--max-pages`, `--fail-on-partial`, `--fail-on-empty`
- Search output as `text`, `json`, `ndjson`, or `tsv`
- JSON export via `--out`, with path traversal protection
- API key read from the environment only, never hardcoded or logged

## Requirements

- Go 1.25 or newer (to build from source)
- A Shodan API key
- Network access to `https://api.shodan.io`

## Installation

### Pre-built binary

Grab the latest release from [GitHub Releases](https://github.com/mar0ls/shodan_go/releases/latest):

```bash
# Linux (amd64)
tar -xzf shodan-go-linux-amd64.tar.gz
./shodan-go --help

# macOS (Apple Silicon)
tar -xzf shodan-go-macos-arm64.tar.gz
./shodan-go --help

# Windows (amd64): extract shodan-go-windows-amd64.zip
```

### From source

```bash
git clone https://github.com/mar0ls/shodan_go.git
cd shodan_go
go build -o shodan-go .
```

Or run without building: `go run .`

## Configuration

Set your API key via environment variable. The CLI exits with an error if it is
not set.

```bash
export SHODAN_API_KEY="your_api_key"
```

## Usage

```bash
./shodan-go <command> [options]
```

### Commands

| Command | Description |
|---|---|
| `host <ip>` | Detailed information for one host IP |
| `host --input <file\|->` | Batch host lookup from file/stdin |
| `search [options] <query>` | Search hosts by Shodan query (100 results/page) |
| `count <query>` | Count results **without consuming query credits** |
| `dns [--all-records] <domain>` | DNS records and subdomains for a domain |
| `resolve [--input <file\|->] <hostname> [...]` | Resolve hostnames to IPs |
| `reverse [--input <file\|->] <ip> [...]` | Reverse DNS for IPs |
| `myip` | Show your public IP as seen by Shodan |

### Search options

| Option | Description |
|---|---|
| `--page N` | Fetch only page `N`. Default `1`. Ignored with `--all`. |
| `--all` | Fetch every page, from page `1` to the last. Consumes one query credit per extra page. |
| `--max-pages N` | Cap pages fetched in `--all` mode (page `1` counts). Requires `--all`. |
| `--format F` | Output format: `text`, `json`, `ndjson`, `tsv`. Default `text`. |
| `--no-header` | Suppress header/metadata lines. Affects `text`/`tsv` only. |
| `--fail-on-empty` | Exit non-zero when no matches are found. |
| `--fail-on-partial` | Exit non-zero when `--all` cannot fetch every page. Requires `--all`. |
| `--out <file>` | Write the full JSON snapshot to a file (relative or absolute path). Independent of `--format`. |

`-h` / `--help` prints usage for any command.

### Examples

```bash
# Host lookup, single IP and batch from file
./shodan-go host 8.8.8.8
./shodan-go host --input ips.txt

# Search: first page, a specific page, all pages
./shodan-go search "apache country:PL"
./shodan-go search --page 3 "nginx country:DE"
./shodan-go search --all --out results.json "webcam country:PL"

# Cap an --all search to the first 3 pages
./shodan-go search --all --max-pages 3 "apache country:PL"

# Machine-readable output
./shodan-go search --format json "apache country:PL"
./shodan-go search --format ndjson --no-header "nginx country:DE"

# CI: fail if not every page could be fetched
./shodan-go search --all --fail-on-partial "nginx country:DE"

# Count without using credits
./shodan-go count "apache country:PL"

# DNS records (capped at 50, or full with --all-records)
./shodan-go dns example.com
./shodan-go dns --all-records example.com

# Resolve and reverse DNS (positional or from stdin/file)
./shodan-go resolve google.com cloudflare.com
cat hosts.txt | ./shodan-go resolve --input -
./shodan-go reverse 8.8.8.8 1.1.1.1

# Public IP
./shodan-go myip
```

More automation snippets (count reports, NDJSON streaming, CI smoke tests,
PowerShell, Makefile) live in [docs/RECIPES.md](docs/RECIPES.md).

## Error handling and retries

In `--all` mode the CLI applies these safeguards between pages:

- **Rate-limit delay:** 1-second pause between page requests.
- **Retry with backoff:** each failed page is retried up to 3 times (2 s, 4 s, 6 s).
- **Partial results preserved:** pages fetched so far are still printed and saved to `--out` if a later page fails.
- **Resume hint:** on failure the CLI logs the failing page number; re-run with `--page N --all` to continue from there.

```bash
# Resume an interrupted search from page 38
./shodan-go search --page 38 --all --out results.json "webcam country:PL"
```

## Security

| Concern | Mitigation |
|---|---|
| API key in URLs | Passed via `url.Values`, never via `fmt.Sprintf` |
| API key in error messages | `sanitizeErr` strips the key from `*url.Error` before logging |
| URL/path injection via IP/domain | `url.PathEscape` applied before embedding in the URL path |
| Output file path traversal | `filepath.Clean` plus a `..` traversal check (absolute paths allowed) |
| Hanging requests | Every request uses `context.Context` and a 30 s client timeout |
| Secret in source code | `SHODAN_API_KEY` is read from the environment only |

## Development

```bash
# Build cross-platform binaries (see scripts/ for targets)
./scripts/build.sh                 # local build -> ./shodan-go
./scripts/build.sh linux-amd64     # cross-build
./scripts/build.ps1 -Target local  # PowerShell equivalent

# Test (with race detector) and coverage
go test -race ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Lint and regenerate docs
golangci-lint run -c ./.golangci.yml
./scripts/generate_docs.py
```

Coverage sits around 75-80%. The remaining uncovered lines are in `main()`,
which needs a live API key to exercise.

## Project structure

```text
.
├── .github/workflows/   # CI: build matrix + race tests, coverage, lint
├── api/                  # Shodan API client
│   ├── shodan.go         # Client, options, sanitizeErr
│   ├── api.go            # GetAPIInfo
│   ├── host.go           # SearchHosts, GetHostByIP, CountHosts, host types
│   ├── dns.go            # GetDomain, ResolveHostnames, ReverseIPs, MyIP
│   └── *_test.go         # httptest-based API tests
├── docs/                 # Generated reference + scripting recipes
├── scripts/              # Build and docs-generation helpers
├── main.go               # CLI entrypoint (all commands)
├── main_test.go          # CLI unit tests
└── go.mod
```

## Documentation

- [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md): generated reference for all exported symbols.
- [docs/RECIPES.md](docs/RECIPES.md): Bash and PowerShell automation snippets.

## Contributing

Issues and pull requests are welcome. Run `go test -race ./...` and
`golangci-lint run ./...` before opening a PR.
