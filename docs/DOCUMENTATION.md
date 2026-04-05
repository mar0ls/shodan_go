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

---

## API method contracts

| Method | Input | Output | Errors |
|--------|-------|--------|--------|
| `GetAPIInfo(ctx)` | ctx context.Context | *APIInfo | network error, non-200 API status, JSON decode error |
| `SearchHosts(ctx, query, page)` | ctx context.Context, query string, page >= 1 | *SearchResult | network error, non-200 API status, JSON decode error |
| `GetHostByIP(ctx, ip)` | ctx context.Context, IPv4/IPv6 as string | *Host | network error, non-200 API status, JSON decode error |

---

## Operation → model mapping

| Operation | Main models involved |
|-----------|-----------------------|
| `GetAPIInfo()` | APIInfo |
| `SearchHosts()` | SearchResult, Host, FacetCount |
| `GetHostByIP()` | Host, HostLocation, HostHTTP, Meta |

---

## Error handling & limits

- All API calls return an error for network failures and non-200 Shodan responses.
- All errors include operation context: `GetAPIInfo: decode response: ...`.
- Network errors are sanitized — the API key is **never** included in error messages.
- Search pagination uses 100 results per page; `--all` consumes additional query credits.
- CLI exits early when `SHODAN_API_KEY` is missing.
- `--out` path is sanitized: only relative paths inside the current directory are accepted.

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

Command main is a small CLI for querying Shodan host and search endpoints.

### `shodan`

Package shodan provides a small client for the Shodan API.

---

## CLI

| Symbol | Source | Description |
|--------|--------|-------------|
| `searchOptions` | `main.go` | searchOptions stores parsed flags and query text for the search command. |
| `searchOutput` | `main.go` | searchOutput is what we save to --out as a full JSON snapshot. |
| `parseSearchArgs()` | `main.go` | parseSearchArgs accepts flags in any order, then treats remaining tokens as query text. |
| `formatLine()` | `main.go` | formatLine builds one readable console row for search results. |
| `fetchPageWithRetry()` | `main.go` | fetchPageWithRetry fetches a single search page, retrying up to maxRetries times on failure. |
| `runHost()` | `main.go` | runHost fetches and prints details for a single IP. |
| `runSearch()` | `main.go` | runSearch executes a paginated host search and optionally exports JSON. |
| `main()` | `main.go` | main dispatches CLI commands. |

### `searchOptions`

searchOptions stores parsed flags and query text for the search command.

### `searchOutput`

searchOutput is what we save to --out as a full JSON snapshot.

### `parseSearchArgs()`

parseSearchArgs accepts flags in any order, then treats remaining tokens as query text.

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

### `main()`

main dispatches CLI commands.

---

## API Client Core

| Symbol | Source | Description |
|--------|--------|-------------|
| `Option` | `api/shodan.go` | Option configures a Client. |
| `WithBaseURL()` | `api/shodan.go` | WithBaseURL overrides the default API base URL. Primarily used in tests. |
| `Client` | `api/shodan.go` | Client holds API key and shared HTTP client config. |
| `NewClient()` | `api/shodan.go` | NewClient creates a Shodan client with a sane default timeout. |

### `Option`

Option configures a Client.

### `WithBaseURL()`

WithBaseURL overrides the default API base URL. Primarily used in tests.

### `Client`

Client holds API key and shared HTTP client config.

### `NewClient()`

NewClient creates a Shodan client with a sane default timeout.

---

## API Models

| Symbol | Source | Description |
|--------|--------|-------------|
| `APIInfo` | `api/api.go` | APIInfo contains account credits and plan capabilities. |
| `HostLocation` | `api/host.go` | HostLocation describes geographic metadata for a host. |
| `HostHTTP` | `api/host.go` | HostHTTP is a small subset of HTTP metadata returned by Shodan. |
| `Meta` | `api/host.go` | Meta stores scan metadata embedded under _shodan. |
| `Host` | `api/host.go` | Host represents one service banner/record returned by search and lookup APIs. |
| `FacetCount` | `api/host.go` | FacetCount represents one bucket in aggregated facet results. |
| `SearchResult` | `api/host.go` | SearchResult is the paginated response returned by host search. |

### `APIInfo`

APIInfo contains account credits and plan capabilities.

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

---

## API Operations

| Symbol | Source | Description |
|--------|--------|-------------|
| `GetAPIInfo()` | `api/api.go` | GetAPIInfo returns account limits and subscription-related fields. |
| `SearchHosts()` | `api/host.go` | SearchHosts runs /shodan/host/search with query and page number. |
| `GetHostByIP()` | `api/host.go` | GetHostByIP fetches detailed host information for a specific IP. |

### `GetAPIInfo()`

GetAPIInfo returns account limits and subscription-related fields.

### `SearchHosts()`

SearchHosts runs /shodan/host/search with query and page number.

### `GetHostByIP()`

GetHostByIP fetches detailed host information for a specific IP.

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
| `init()` | `main.go` | _No description provided._ |
| `validateOutPath()` | `main.go` | validateOutPath returns an error if the path contains ".." traversal components. |
| `TestGetAPIInfo()` | `api/client_test.go` | _No description provided._ |
| `TestGetAPIInfo_KeyNotInError()` | `api/client_test.go` | _No description provided._ |
| `TestSearchHosts()` | `api/client_test.go` | _No description provided._ |
| `TestSearchHosts_PageNormalization()` | `api/client_test.go` | _No description provided._ |
| `TestGetHostByIP()` | `api/client_test.go` | _No description provided._ |
| `sanitizeErr()` | `api/shodan.go` | sanitizeErr strips the URL (which may contain the API key) from net/http URL errors. |

### `init()`

_No comment provided._

### `validateOutPath()`

validateOutPath returns an error if the path contains ".." traversal components.
Both absolute paths (e.g. /tmp/results.json) and relative paths are accepted;
only upward traversal above the current directory is rejected.

### `TestGetAPIInfo()`

_No comment provided._

### `TestGetAPIInfo_KeyNotInError()`

_No comment provided._

### `TestSearchHosts()`

_No comment provided._

### `TestSearchHosts_PageNormalization()`

_No comment provided._

### `TestGetHostByIP()`

_No comment provided._

### `sanitizeErr()`

sanitizeErr strips the URL (which may contain the API key) from net/http URL errors.

---

