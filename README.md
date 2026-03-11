# Shodan-Go CLI

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/doc/install)
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
- Safe API client with timeout-based HTTP requests
- Search pagination support (`--page`, `--all`)
- JSON export with output-path sanitization (`--out`)
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
| `--out <file>` | Save full JSON result to file |

### Examples

```bash
# Host lookup
./shodan-go host 8.8.8.8

# Search, first page
./shodan-go search "apache country:PL"

# Search, specific page
./shodan-go search --page 3 "nginx country:DE"

# Search all pages and export JSON
./shodan-go search --all --out results.json "webcam country:PL"

# Example of listing all ips from results JSON
jq -r '.. | .ip_str? // empty' results.json | sort -u
```

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
./scripts/build.ps1 -Target local -Out my-cli.exe
```

## Project Structure

```text
.
├── api/                 # Shodan client, models, and API operations
├── docs/                # Generated documentation
├── scripts/             # Build and docs generation helpers
├── main.go              # CLI entrypoint
├── .golangci.yml        # Lint/formatter configuration
└── go.mod
```

## Documentation

Detailed code-level docs are generated to:

- [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)


## Contributing

Issues and pull requests are welcome.
Please include a clear description and run lint before submitting changes.
