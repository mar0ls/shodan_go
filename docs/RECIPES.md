# Scripting Recipes

Bash and PowerShell snippets for common automation tasks. All snippets assume
`shodan-go` is on your `PATH` (or adjust the path) and `SHODAN_API_KEY` is set.

## 1. Nightly count report (no query credits consumed)

```bash
#!/usr/bin/env bash
set -euo pipefail

query='apache country:PL'
timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

total="$(./shodan-go count "$query" | awk '/Total results:/ {print $3}')"
printf '%s query=%q total=%s\n' "$timestamp" "$query" "$total" >> shodan-counts.log
```

## 2. Save a search snapshot and extract unique IPs

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

Stream the same data as NDJSON instead of buffering JSON:

```bash
./shodan-go search --format ndjson --no-header 'apache country:US' \
  | jq -r '.ip_str' \
  | sort -u > ips.txt
```

## 3. Bulk hostname resolution from a file

`hosts.txt`:

```text
google.com
cloudflare.com
example.org
```

```bash
./shodan-go resolve --input hosts.txt | tee resolved.txt
```

## 4. Reverse DNS enrichment for a list of IPs

`ips.txt`:

```text
8.8.8.8
1.1.1.1
9.9.9.9
```

```bash
./shodan-go reverse --input ips.txt | tee reverse.txt
```

## 5. DNS inventory to file

```bash
domain='google.com'

# Capped output (50 records), readable in a terminal
./shodan-go dns "$domain" > "dns-${domain}.txt"

# Full output, for further processing
./shodan-go dns --all-records "$domain" > "dns-${domain}-all.txt"
```

## 6. Retry wrapper for unstable API windows (503/timeout)

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

## 7. Smoke test in CI

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${SHODAN_API_KEY:?SHODAN_API_KEY is required}"

./shodan-go myip > /dev/null
./shodan-go count 'ssl cert.subject.cn:example.com' > /dev/null
echo "Shodan CLI checks: OK"
```

## 8. PowerShell equivalents (Windows)

```powershell
$ErrorActionPreference = "Stop"

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

## 9. Makefile shortcuts

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

Usage:

```bash
make shodan-count QUERY='nginx country:DE'
make shodan-search QUERY='ssl:cloudflare' OUT=cloudflare.json
make shodan-dns DOMAIN=google.com
```
