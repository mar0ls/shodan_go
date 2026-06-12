# Shodan-Go — Code Documentation

## Table of contents

1. [Quick start](#quick-start)
2. [Command reference](#command-reference)
3. [API method contracts](#api-method-contracts)
4. [Operation → model mapping](#operation--model-mapping)
5. [Error handling & limits](#error-handling--limits)
6. [Package overview](#package-overview)
7. [CLI](#cli)
8. [API Client Core](#api-client-core)
9. [API Models](#api-models)
10. [API Operations](#api-operations)
11. [Compatibility Aliases](#compatibility-aliases)
12. [Other](#other)

---

## Quick start

```go
apiKey := os.Getenv("SHODAN_API_KEY")
client := shodan.NewClient(apiKey)

ctx := context.Background()

info, err := client.GetAPIInfo(ctx)
if err != nil {
    log.Fatal(err)
}

host, err := client.GetHostByIP(ctx, "8.8.8.8")
if err != nil {
    log.Fatal(err)
}
fmt.Println(host.IPString, host.Org)
```

---

## Command reference

| Command | Purpose |
|---------|---------|
| `host <ip>` | Fetch detailed host metadata for one IP address. |
| `search [--page N] <query>` | Run one paginated search request and print results. |
| `search --all <query>` | Iterate all pages for a query (consumes query credits). |
| `search --out <file> <query>` | Save full JSON output to a file with safe path checks. |
| `count <query>` | Return only the total number of matches (does not consume query credits). |
| `dns [--all-records] <domain>` | Fetch DNS records and subdomains for a domain. |
| `resolve <hostname> [...]` | Resolve one or more hostnames to IP addresses. |
| `reverse <ip> [...]` | Reverse-resolve one or more IPs to hostnames. |
| `myip` | Return your public IP as seen by Shodan. |

---

## API method contracts

| Method | Input | Output | Errors |
|--------|-------|--------|--------|
| `GetAPIInfo(ctx)` | ctx context.Context | *APIInfo | network error, non-200 API status, JSON decode error |
| `SearchHosts(ctx, query, page)` | ctx context.Context, query string, page >= 1 | *SearchResult | network error, non-200 API status, JSON decode error |
| `GetHostByIP(ctx, ip)` | ctx context.Context, IPv4/IPv6 as string | *Host | network error, non-200 API status, JSON decode error |
| `CountHosts(ctx, query, facets...)` | ctx context.Context, query string, optional facets | *CountResult | network error, non-200 API status, JSON decode error |
| `GetDomain(ctx, domain)` | ctx context.Context, domain string | *DomainInfo | network error, non-200 API status, JSON decode error |
| `ResolveHostnames(ctx, hostnames...)` | ctx context.Context, one or more hostnames | map[string]string | network error, non-200 API status, JSON decode error |
| `ReverseIPs(ctx, ips...)` | ctx context.Context, one or more IPs | map[string][]string | network error, non-200 API status, JSON decode error |
| `MyIP(ctx)` | ctx context.Context | string | network error, non-200 API status, JSON decode error |

---

## Operation → model mapping

| Operation | Main models involved |
|-----------|-----------------------|
| `GetAPIInfo()` | APIInfo |
| `SearchHosts()` | SearchResult, Host, FacetCount |
| `GetHostByIP()` | Host, HostLocation, HostHTTP, Meta |
| `CountHosts()` | CountResult, FacetCount |
| `GetDomain()` | DomainInfo, DNSRecord |
| `ResolveHostnames()` | map[string]string |
| `ReverseIPs()` | map[string][]string |
| `MyIP()` | string |

---

## Error handling & limits

- All API calls return an error for network failures and non-200 Shodan responses.
- All errors include operation context: `GetAPIInfo: decode response: ...`.
- Network errors are sanitized — the API key is **never** included in error messages.
- Search pagination uses 100 results per page; `--all` consumes additional query credits.
- CLI exits early when `SHODAN_API_KEY` is missing.
- `--out` path is sanitized: absolute paths and relative paths are allowed, but upward traversal (`..`) is rejected.

### Security notes

| Concern | Mitigation |
|---------|------------|
| API key in URLs | Encoded via `url.Values`, never raw in `fmt.Sprintf` |
| API key in error logs | Stripped by `sanitizeErr` via `*url.Error` unwrap |
| IP path injection | Input encoded with `url.PathEscape` before use in URL |
| Output path traversal | `filepath.Clean` + dotdot traversal check (absolute paths allowed) |
| Context / timeout | Every HTTP call uses `context.Context` + 30 s client timeout |

- Example (`SHODAN_API_KEY` missing): `SHODAN_API_KEY environment variable not set`.
- Example (API non-200): `GetHostByIP 8.8.8.8: shodan API error: 404 Not Found`.

---

## Package overview

### `main`

Command main is a CLI for querying Shodan host, search, and DNS endpoints.

### `shodan`

Package shodan provides a small client for the Shodan API.

---

## CLI

| Symbol | Source | Description |
|--------|--------|-------------|
| `searchOptions` | `main.go` | searchOptions stores parsed flags and query text for the search command. |
| `searchOutput` | `main.go` | searchOutput is the JSON snapshot written to --out. |
| `parseSearchArgs()` | `main.go` | parseSearchArgs accepts flags in any order, then treats remaining tokens as query text. |
| `validateOutPath()` | `main.go` | validateOutPath returns an error if the path contains ".." traversal components. |
| `formatLine()` | `main.go` | formatLine builds one readable console row for search results. |
| `fetchPageWithRetry()` | `main.go` | fetchPageWithRetry fetches a single search page, retrying up to maxRetries times on failure. |
| `runHost()` | `main.go` | runHost fetches and prints details for a single IP. |
| `runSearch()` | `main.go` | runSearch executes a paginated host search and optionally exports JSON. |
| `runCount()` | `main.go` | runCount prints the number of results for a query without consuming query credits. |
| `runDNS()` | `main.go` | runDNS prints DNS records and subdomains for a domain. |
| `runResolve()` | `main.go` | runResolve resolves hostnames to IP addresses. |
| `runReverse()` | `main.go` | runReverse performs reverse DNS lookup for IP addresses. |
| `runMyIP()` | `main.go` | runMyIP prints the caller's public IP address. |
| `main()` | `main.go` | main dispatches CLI commands. |

### `searchOptions`

searchOptions stores parsed flags and query text for the search command.

### `searchOutput`

searchOutput is the JSON snapshot written to --out.

### `parseSearchArgs()`

parseSearchArgs accepts flags in any order, then treats remaining tokens as query text.

### `validateOutPath()`

validateOutPath returns an error if the path contains ".." traversal components.
Both absolute paths (e.g. /tmp/results.json) and relative paths are accepted;
only upward traversal above the current directory is rejected.

### `formatLine()`

formatLine builds one readable console row for search results.

### `fetchPageWithRetry()`

fetchPageWithRetry fetches a single search page, retrying up to maxRetries times on failure.
baseDelay is multiplied by the attempt number between retries; pass 0 to skip sleeping (tests).

### `runHost()`

runHost fetches and prints details for a single IP.

### `runSearch()`

runSearch executes a paginated host search and optionally exports JSON.
pagePause is the delay between page fetches in --all mode (pass 0 in tests).
retryBase is the base delay for fetchPageWithRetry (pass 0 in tests).

### `runCount()`

runCount prints the number of results for a query without consuming query credits.

### `runDNS()`

runDNS prints DNS records and subdomains for a domain.
Accepts optional --all-records flag to show all records instead of the default cap.

### `runResolve()`

runResolve resolves hostnames to IP addresses.

### `runReverse()`

runReverse performs reverse DNS lookup for IP addresses.

### `runMyIP()`

runMyIP prints the caller's public IP address.

### `main()`

main dispatches CLI commands.

---

## API Client Core

| Symbol | Source | Description |
|--------|--------|-------------|
| `Option` | `api/shodan.go` | Option configures a Client. |
| `WithBaseURL()` | `api/shodan.go` | WithBaseURL overrides the default API base URL. Primarily used in tests. |
| `Client` | `api/shodan.go` | Client holds API key and shared HTTP client config. |
| `NewClient()` | `api/shodan.go` | NewClient returns a Client with a 30 s HTTP timeout. |

### `Option`

Option configures a Client.

### `WithBaseURL()`

WithBaseURL overrides the default API base URL. Primarily used in tests.

### `Client`

Client holds API key and shared HTTP client config.

### `NewClient()`

NewClient returns a Client with a 30 s HTTP timeout.

---

## API Models

| Symbol | Source | Description |
|--------|--------|-------------|
| `APIInfo` | `api/api.go` | APIInfo contains account credits and plan capabilities. |
| `DomainInfo` | `api/dns.go` | DomainInfo contains DNS records and subdomains for a domain. |
| `DNSRecord` | `api/dns.go` | DNSRecord is a single DNS entry returned by the domain lookup endpoint. |
| `HostLocation` | `api/host.go` | HostLocation describes geographic metadata for a host. |
| `HostHTTP` | `api/host.go` | HostHTTP is a small subset of HTTP metadata returned by Shodan. |
| `Meta` | `api/host.go` | Meta stores scan metadata embedded under _shodan. |
| `Host` | `api/host.go` | Host represents one service banner/record returned by search and lookup APIs. |
| `FacetCount` | `api/host.go` | FacetCount represents one bucket in aggregated facet results. |
| `SearchResult` | `api/host.go` | SearchResult is the paginated response returned by host search. |
| `CountResult` | `api/host.go` | CountResult holds the total number of results for a search query. |

### `APIInfo`

APIInfo contains account credits and plan capabilities.

### `DomainInfo`

DomainInfo contains DNS records and subdomains for a domain.

### `DNSRecord`

DNSRecord is a single DNS entry returned by the domain lookup endpoint.

### `HostLocation`

HostLocation describes geographic metadata for a host.

### `HostHTTP`

HostHTTP is a small subset of HTTP metadata returned by Shodan.

### `Meta`

Meta stores scan metadata embedded under _shodan.

### `Host`

Host represents one service banner/record returned by search and lookup APIs.

### `FacetCount`

FacetCount represents one bucket in aggregated facet results.

### `SearchResult`

SearchResult is the paginated response returned by host search.

### `CountResult`

CountResult holds the total number of results for a search query.

---

## API Operations

| Symbol | Source | Description |
|--------|--------|-------------|
| `GetAPIInfo()` | `api/api.go` | GetAPIInfo returns account limits and subscription-related fields. |
| `GetDomain()` | `api/dns.go` | GetDomain looks up subdomains and DNS records for a domain. |
| `ResolveHostnames()` | `api/dns.go` | ResolveHostnames resolves one or more hostnames to IP addresses. |
| `ReverseIPs()` | `api/dns.go` | ReverseIPs performs reverse DNS lookup for one or more IP addresses. |
| `MyIP()` | `api/dns.go` | MyIP returns the public IP address of the caller as seen by Shodan. |
| `SearchHosts()` | `api/host.go` | SearchHosts runs /shodan/host/search with query and page number. |
| `GetHostByIP()` | `api/host.go` | GetHostByIP fetches detailed host information for a specific IP. |
| `CountHosts()` | `api/host.go` | CountHosts returns the number of results for a query without consuming query credits. |

### `GetAPIInfo()`

GetAPIInfo returns account limits and subscription-related fields.

### `GetDomain()`

GetDomain looks up subdomains and DNS records for a domain.
Requires a paid Shodan API plan; free keys return 403.

### `ResolveHostnames()`

ResolveHostnames resolves one or more hostnames to IP addresses.
Returns a map of hostname → IP string.

### `ReverseIPs()`

ReverseIPs performs reverse DNS lookup for one or more IP addresses.
Returns a map of IP → list of hostnames.

### `MyIP()`

MyIP returns the public IP address of the caller as seen by Shodan.

### `SearchHosts()`

SearchHosts runs /shodan/host/search with query and page number.

### `GetHostByIP()`

GetHostByIP fetches detailed host information for a specific IP.

### `CountHosts()`

CountHosts returns the number of results for a query without consuming query credits.
Optionally accepts facet names (e.g. "country", "org") to include aggregations.

---

## Compatibility Aliases

| Symbol | Source | Description |
|--------|--------|-------------|
| `APIInfo()` | `api/api.go` | APIInfo is a compatibility alias for GetAPIInfo. |
| `HostSearch()` | `api/host.go` | HostSearch is a compatibility alias for SearchHosts. |
| `HostLookup()` | `api/host.go` | HostLookup is a compatibility alias for GetHostByIP. |
| `New()` | `api/shodan.go` | New is kept as a short alias for NewClient. |

### `APIInfo()`

APIInfo is a compatibility alias for GetAPIInfo.

Deprecated: Use GetAPIInfo instead.

### `HostSearch()`

HostSearch is a compatibility alias for SearchHosts.

Deprecated: Use SearchHosts instead.

### `HostLookup()`

HostLookup is a compatibility alias for GetHostByIP.

Deprecated: Use GetHostByIP instead.

### `New()`

New is kept as a short alias for NewClient.

Deprecated: Use NewClient instead.

---

## Other

| Symbol | Source | Description |
|--------|--------|-------------|
| `init()` | `main.go` | init builds the CLI usage text using the current binary name. |
| `joinFacets()` | `api/host.go` | joinFacets formats a slice of facet names for the API (comma-separated, each prefixed with count). |
| `sanitizeErr()` | `api/shodan.go` | sanitizeErr strips the URL (which may contain the API key) from net/http URL errors. |

### `init()`

init builds the CLI usage text using the current binary name.

### `joinFacets()`

joinFacets formats a slice of facet names for the API (comma-separated, each prefixed with count).

### `sanitizeErr()`

sanitizeErr strips the URL (which may contain the API key) from net/http URL errors.

---

