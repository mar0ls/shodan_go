// Command main is a small CLI for querying Shodan host and search endpoints.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	shodan "shodan/api"
)

const usage = `Usage:
	main host <ip>                                  — details for a specific host
	main search [options] <query>                   — host search (100 results/page)

Search options:
	-page/--page N      fetch a specific page (default: 1)
	-all/--all           fetch all pages (warning: consumes credits)
	-out/--out <file>    save full JSON output to a file

Examples:
  main search "webcam country:PL"
  main search --page 3 "apache country:PL"
  main search --all --out wyniki.txt "apache country:PL"`

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
		return opts, fmt.Errorf("missing query, e.g. main search \"apache country:PL\"")
	}

	return opts, nil
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

// main dispatches CLI commands and prints host or search results.
func main() {
	if len(os.Args) < 3 {
		log.Fatalln(usage)
	}
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		log.Fatalln("SHODAN_API_KEY environment variable not set")
	}
	s := shodan.NewClient(apiKey)
	info, err := s.GetAPIInfo()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Query Credits: %d\nScan Credits:  %d\n\n", info.QueryCredits, info.ScanCredits)

	cmd := os.Args[1]

	switch cmd {
	case "host":
		// Host mode: show richer details for a single IP.
		arg := strings.Join(os.Args[2:], " ")
		host, err := s.GetHostByIP(arg)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("IP:      %s\n", host.IPString)
		fmt.Printf("Org:     %s\n", host.Org)
		fmt.Printf("ISP:     %s\n", host.ISP)
		fmt.Printf("Country: %s\n", host.Location.CountryName)
		if host.OS != nil && *host.OS != "" {
			fmt.Printf("OS:      %s\n", *host.OS)
		}
		if len(host.Hostnames) > 0 {
			fmt.Printf("Hosts:   %s\n", strings.Join(host.Hostnames, ", "))
		}
		fmt.Printf("Ports:   %v\n", host.Ports)

	case "search":
		// Search mode: list hosts and optionally export full raw JSON.
		opts, err := parseSearchArgs(os.Args[2:])
		if err != nil {
			log.Fatalln(err)
		}

		startPage := opts.Page
		if opts.All {
			startPage = 1
		}

		// First request tells us total results/pages.
		first, err := s.SearchHosts(opts.Query, startPage)
		if err != nil {
			log.Fatalln(err)
		}
		totalPages := int(math.Ceil(float64(first.Total) / 100.0))
		fmt.Printf("Found results: %d  |  Pages: %d\n\n", first.Total, totalPages)

		// Start with the requested page; append more only when --all is used.
		matches := first.Matches

		if opts.All && totalPages > 1 {
			fmt.Printf("Fetching all %d pages (will consume %d credits)...\n", totalPages, totalPages-1)
			for p := startPage + 1; p <= totalPages; p++ {
				fmt.Printf("  page %d/%d\n", p, totalPages)
				r, err := s.SearchHosts(opts.Query, p)
				if err != nil {
					fmt.Fprintln(os.Stderr, "error while fetching additional search results")
					os.Exit(1)
				}
				matches = append(matches, r.Matches...)
			}
			fmt.Println()
		}

		if !opts.All {
			fmt.Printf("Selected page: %d\n\n", opts.Page)
		}

		if opts.Out != "" {
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
				log.Fatalln(err)
			}
			outputPath := filepath.Clean(opts.Out)
			if outputPath == "." || outputPath == ".." || filepath.IsAbs(outputPath) || strings.HasPrefix(outputPath, ".."+string(filepath.Separator)) {
				log.Fatalln("--out must be a relative file path within the current directory")
			}
			//nolint:gosec // outputPath is sanitized via filepath.Clean and relative-path checks above.
			if err := os.WriteFile(outputPath, data, 0o600); err != nil {
				log.Fatalln(err)
			}
			fmt.Printf("Saved full JSON (%d records) to: %s\n\n", len(matches), outputPath)
		}

		for _, host := range matches {
			line := formatLine(host)
			fmt.Println(line)
		}

	default:
		log.Fatalln(usage)
	}
}
