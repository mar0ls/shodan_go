# Shodan-Go CLI

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/doc/install)
[![Build](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/build.yml)
[![Test](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml/badge.svg)](https://github.com/mar0ls/shodan_go/actions/workflows/test.yml)
[![Lint](https://img.shields.io/badge/lint-golangci--lint-blue)](.golangci.yml)
[![Docs](https://img.shields.io/badge/docs-DOCUMENTATION.md-brightgreen)](docs/DOCUMENTATION.md)

A lightweight command-line interface for querying the Shodan API in Go.

[Go 1.25+](https://go.dev/doc/install) • [Code Documentation](docs/DOCUMENTATION.md)

## Overview

`shodan_go` provides a small, script-friendly CLI for:
- checking account credits,
- looking up a single host,
- searching hosts with pagination,
- exporting full search results to JSON.

## Key Features

- Minimal CLI with two core commands: `host` and `search`
- Context-aware HTTP client with 30 s timeout and cancellation support
- API key encoded via `url.Values` — never interpolated raw into URLs
- API key stripped from error messages (`sanitizeErr` removes it from `*url.Error`)
- IP path encoded with `url.PathEscape` to prevent URL manipulation
- Search pagination support (`--page`, `--all`)
- JSON export with output-path sanitization (`--out`)
- Automatic retry with exponential backoff for paginated fetches
- Linting and formatter support via `golangci-lint`
- Auto-generated developer docs from source comments

## Requirements

- Go `1.25` or newer
- A Shodan API key
- Network access to `https://api.shodan.io`

## Installation

Clone and build locally:

```bash
git clone https://github.com/mar0ls/shodan_go.git
cd shodan_go
go build -o shodan-go .
```

Run directly in development mode:

```bash
go run .
```

## Security

The following security measures are built into the client and CLI:

| Concern | Mitigation |
|---------|------------|
| API key in URLs | Passed via `url.Values`, never via `fmt.Sprintf` |
| API key in error messages | `sanitizeErr` strips the key from `*url.Error` before logging |
| URL/path injection via IP parameter | `url.PathEscape` applied before embedding in URL path |
| Output file path traversal | `filepath.Clean` + dotdot traversal check (absolute paths like `/tmp/out.json` are allowed) |
| Long-running / hanging requests | Every HTTP request uses `context.Context` + 30 s client timeout |
| Secret in source code | `SHODAN_API_KEY` is read from environment only — never hardcoded |

> **Never commit your `SHODAN_API_KEY`.** Add `.env` to `.gitignore` and use your hosting platform's secret manager for production deployments.

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

# Show help
./shodan-go --help

# Resume a previously interrupted search from page 38
./shodan-go search --page 38 --all --out results.json "webcam country:PL"

# Example of listing all ips from results JSON
jq -r '.. | .ip_str? // empty' results.json | sort -u
```

### Error handling

When fetching multiple pages with `--all`, the CLI applies automatic safeguards:

- **Rate-limit delay** — 1-second pause between page requests to avoid API throttling.
- **Retry with backoff** — each failed page is retried up to 3 times with increasing delay (2 s, 4 s, 6 s).
- **Partial results preserved** — if a page fails after all retries, already collected results are kept and output normally (printed and/or saved with `--out`).
- **Resume hint** — on failure the CLI prints the page number so you can continue later with `--page N --all`.
``ex.: ./shodan-go search --page 38 --all --out results.json "webcam country:PL"``

## Testing

Run the full test suite (includes race-condition detection):

```bash
go test -race ./...
```

Generate a coverage report:

```bash
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out   # summary per function
go tool cover -html=coverage.out   # interactive HTML report
```

Current coverage: ~77% overall (`shodan/api` ~82%, `shodan` main package ~75%).
The zero-coverage items are all deprecated alias wrappers and the `main()` entry point
(which requires a live API key).

## Developer Tools

Format, lint, and generate docs:

```bash
# Lint + format checks (configured in .golangci.yml)
golangci-lint run -c ./.golangci.yml

# Generate docs from source comments
./scripts/generate_docs.py
```

## Building and Distribution

Use helper scripts for local/cross-platform builds. Both scripts resolve the
project root automatically, so you can run them from any working directory.

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
│   ├── host.go              # SearchHosts, GetHostByIP, host types
│   └── client_test.go       # httptest-based API tests
├── docs/                    # Auto-generated documentation
├── scripts/                 # Build and docs generation helpers
├── main.go                  # CLI entrypoint (host / search commands)
├── main_test.go             # Unit tests for CLI functions
├── .golangci.yml            # Lint/formatter configuration
└── go.mod
```

## Documentation

Detailed code-level docs are generated to:

- [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)


## Contributing

Issues and pull requests are welcome.
Please include a clear description and run lint before submitting changes.
