// Command main is a small CLI for querying Shodan host and search endpoints.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	shodan "shodan/api"
)

const (
	maxRetries     = 3               // maximum number of retry attempts per page fetch
	retryBaseDelay = 2 * time.Second // base wait between retries; multiplied by attempt number
	resultsPerPage = 100             // Shodan returns at most 100 results per page
	pagePauseDelay = 1 * time.Second // delay between pages in --all mode to avoid rate limiting
)

var usage string

func init() {
	bin := filepath.Base(os.Args[0])
	usage = fmt.Sprintf(`Usage:
	%s host <ip>                                  — details for a specific host
	%s search [options] <query>                   — host search (100 results/page)

Search options:
	-page/--page N      fetch a specific page (default: 1)
	-all/--all           fetch all pages (warning: consumes credits)
	-out/--out <file>    save JSON output to a file (relative or absolute path)

General flags:
	-h, --help           show this help message

Examples:
  %s search "webcam country:PL"
  %s search --page 3 "apache country:PL"
  %s search --all --out /tmp/wyniki.json "apache country:PL"`, bin, bin, bin, bin, bin)
}

// searchOptions stores parsed flags and query text for the search command.
type searchOptions struct {
	Page  int
	All   bool
	Out   string
	Query string
}

// searchOutput is what we save to --out as a full JSON snapshot.
type searchOutput struct {
	Query      string        `json:"query"`
	Total      int           `json:"total"`
	TotalPages int           `json:"total_pages"`
	Page       int           `json:"page"`
	AllPages   bool          `json:"all_pages"`
	Count      int           `json:"count"`
	Matches    []shodan.Host `json:"matches"`
}

// parseSearchArgs accepts flags in any order, then treats remaining tokens as query text.
func parseSearchArgs(args []string) (searchOptions, error) {
	opts := searchOptions{Page: 1}
	queryParts := make([]string, 0)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--all" || arg == "-all":
			opts.All = true

		case arg == "--page" || arg == "-page":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing value for --page")
			}
			pageValue, err := strconv.Atoi(args[i+1])
			if err != nil || pageValue < 1 {
				return opts, fmt.Errorf("--page must be a number >= 1")
			}
			opts.Page = pageValue
			i++

		case strings.HasPrefix(arg, "--page=") || strings.HasPrefix(arg, "-page="):
			pageValue, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(arg, "--page="), "-page="))
			if err != nil || pageValue < 1 {
				return opts, fmt.Errorf("--page must be a number >= 1")
			}
			opts.Page = pageValue

		case arg == "--out" || arg == "-out":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing value for --out")
			}
			opts.Out = args[i+1]
			i++

		case strings.HasPrefix(arg, "--out=") || strings.HasPrefix(arg, "-out="):
			opts.Out = strings.TrimPrefix(strings.TrimPrefix(arg, "--out="), "-out=")

		case strings.HasPrefix(arg, "--") || (strings.HasPrefix(arg, "-") && len(arg) > 1):
			return opts, fmt.Errorf("unknown flag: %s", arg)

		default:
			queryParts = append(queryParts, arg)
		}
	}

	opts.Query = strings.TrimSpace(strings.Join(queryParts, " "))
	if opts.Query == "" {
		return opts, fmt.Errorf("missing query, e.g. %s search \"apache country:PL\"", filepath.Base(os.Args[0]))
	}

	return opts, nil
}

// validateOutPath returns an error if the path contains ".." traversal components.
// Both absolute paths (e.g. /tmp/results.json) and relative paths are accepted;
// only upward traversal above the current directory is rejected.
func validateOutPath(path string) error {
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("--out path must not traverse above the current directory")
	}
	return nil
}

// formatLine builds one readable console row for search results.
func formatLine(host shodan.Host) string {
	extra := host.Org
	if host.Product != "" {
		extra += " | " + host.Product
		if host.Version != "" {
			extra += " " + host.Version
		}
	}
	if host.HTTP != nil && host.HTTP.Title != nil && *host.HTTP.Title != "" {
		extra += " | " + *host.HTTP.Title
	}
	return fmt.Sprintf("%-18s port %-6d %s", host.IPString, host.Port, extra)
}

// fetchPageWithRetry fetches a single search page, retrying up to maxRetries times on failure.
// baseDelay is multiplied by the attempt number between retries; pass 0 to skip sleeping (tests).
func fetchPageWithRetry(ctx context.Context, s *shodan.Client, query string, page int, baseDelay time.Duration) (*shodan.SearchResult, error) {
	var (
		r   *shodan.SearchResult
		err error
	)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		r, err = s.SearchHosts(ctx, query, page)
		if err == nil {
			return r, nil
		}
		log.Printf("page %d attempt %d failed: %v", page, attempt, err) //nolint:gosec // G706: error originates from Shodan API, not user input
		if attempt < maxRetries && baseDelay > 0 {
			wait := time.Duration(attempt) * baseDelay
			log.Printf("retrying in %v...", wait)
			time.Sleep(wait)
		}
	}
	return nil, fmt.Errorf("page %d: all %d attempts failed: %w", page, maxRetries, err)
}

// runHost fetches and prints details for a single IP.
func runHost(ctx context.Context, s *shodan.Client, args []string, w io.Writer) error {
	ip := strings.Join(args, " ")
	host, err := s.GetHostByIP(ctx, ip)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "IP:      %s\n", host.IPString)
	_, _ = fmt.Fprintf(w, "Org:     %s\n", host.Org)
	_, _ = fmt.Fprintf(w, "ISP:     %s\n", host.ISP)
	_, _ = fmt.Fprintf(w, "Country: %s\n", host.Location.CountryName)
	if host.OS != nil && *host.OS != "" {
		_, _ = fmt.Fprintf(w, "OS:      %s\n", *host.OS)
	}
	if len(host.Hostnames) > 0 {
		_, _ = fmt.Fprintf(w, "Hosts:   %s\n", strings.Join(host.Hostnames, ", "))
	}
	_, _ = fmt.Fprintf(w, "Ports:   %v\n", host.Ports)
	return nil
}

// runSearch executes a paginated host search and optionally exports JSON.
// pagePause is the delay between page fetches in --all mode (pass 0 in tests).
// retryBase is the base delay for fetchPageWithRetry (pass 0 in tests).
func runSearch(ctx context.Context, s *shodan.Client, args []string, w io.Writer, pagePause, retryBase time.Duration) error {
	opts, err := parseSearchArgs(args)
	if err != nil {
		return err
	}

	startPage := opts.Page
	if opts.All {
		startPage = 1
	}

	// First request tells us total results/pages.
	first, err := s.SearchHosts(ctx, opts.Query, startPage)
	if err != nil {
		return err
	}
	totalPages := int(math.Ceil(float64(first.Total) / float64(resultsPerPage)))
	_, _ = fmt.Fprintf(w, "Found results: %d  |  Pages: %d\n\n", first.Total, totalPages)

	matches := first.Matches

	if opts.All && totalPages > 1 {
		_, _ = fmt.Fprintf(w, "Fetching all %d pages (will consume %d credits)...\n", totalPages, totalPages-1)
		for p := startPage + 1; p <= totalPages; p++ {
			_, _ = fmt.Fprintf(w, "  page %d/%d\n", p, totalPages)
			if pagePause > 0 {
				time.Sleep(pagePause)
			}

			r, fetchErr := fetchPageWithRetry(ctx, s, opts.Query, p, retryBase)
			if fetchErr != nil {
				log.Printf("error while fetching page %d: %v", p, fetchErr)                               //nolint:gosec // G706: error from Shodan API, not user input
				log.Printf("continuing with %d results collected so far (pages 1-%d)", len(matches), p-1) //nolint:gosec // G706: integer values, safe
				log.Printf("tip: re-run with --page %d --all to resume later", p)                         //nolint:gosec // G706: integer values, safe
				break
			}
			matches = append(matches, r.Matches...)
		}
		_, _ = fmt.Fprintln(w)
	}

	if !opts.All {
		_, _ = fmt.Fprintf(w, "Selected page: %d\n\n", opts.Page)
	}

	if opts.Out != "" {
		if err := validateOutPath(opts.Out); err != nil {
			return err
		}
		payload := searchOutput{
			Query:      opts.Query,
			Total:      first.Total,
			TotalPages: totalPages,
			Page:       startPage,
			AllPages:   opts.All,
			Count:      len(matches),
			Matches:    matches,
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal output: %w", err)
		}
		outputPath := filepath.Clean(opts.Out)
		//nolint:gosec // G304: path validated by validateOutPath above; user explicitly provides this path.
		if err := os.WriteFile(outputPath, data, 0o600); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		_, _ = fmt.Fprintf(w, "Saved full JSON (%d records) to: %s\n\n", len(matches), outputPath)
	}

	for _, host := range matches {
		_, _ = fmt.Fprintln(w, formatLine(host))
	}
	return nil
}

// main dispatches CLI commands.
func main() {
	// Handle -h/--help before any other processing so it always works.
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" {
			fmt.Println(usage)
			return
		}
	}

	if len(os.Args) < 3 {
		log.Fatalln(usage)
	}
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		log.Fatalln("SHODAN_API_KEY environment variable not set")
	}

	ctx := context.Background()
	s := shodan.NewClient(apiKey)

	info, err := s.GetAPIInfo(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Query Credits: %d\nScan Credits:  %d\n\n", info.QueryCredits, info.ScanCredits)

	switch os.Args[1] {
	case "host":
		if err := runHost(ctx, s, os.Args[2:], os.Stdout); err != nil {
			log.Fatalln(err)
		}
	case "search":
		if err := runSearch(ctx, s, os.Args[2:], os.Stdout, pagePauseDelay, retryBaseDelay); err != nil {
			log.Fatalln(err)
		}
	default:
		log.Fatalln(usage)
	}
}
