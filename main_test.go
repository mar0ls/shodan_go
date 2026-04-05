package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shodan "shodan/api"
)

// ─── parseSearchArgs ────────────────────────────────────────────────────────

func TestParseSearchArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    searchOptions
		wantErr bool
	}{
		{
			name: "simple query",
			args: []string{"apache"},
			want: searchOptions{Page: 1, Query: "apache"},
		},
		{
			name: "multi-word query",
			args: []string{"apache", "country:PL"},
			want: searchOptions{Page: 1, Query: "apache country:PL"},
		},
		{
			name: "--page flag",
			args: []string{"--page", "3", "nginx"},
			want: searchOptions{Page: 3, Query: "nginx"},
		},
		{
			name: "-page flag",
			args: []string{"-page", "2", "nginx"},
			want: searchOptions{Page: 2, Query: "nginx"},
		},
		{
			name: "--page=N form",
			args: []string{"--page=5", "nginx"},
			want: searchOptions{Page: 5, Query: "nginx"},
		},
		{
			name: "--all flag",
			args: []string{"--all", "nginx"},
			want: searchOptions{Page: 1, All: true, Query: "nginx"},
		},
		{
			name: "-all flag",
			args: []string{"-all", "nginx"},
			want: searchOptions{Page: 1, All: true, Query: "nginx"},
		},
		{
			name: "--out flag",
			args: []string{"--out", "results.json", "nginx"},
			want: searchOptions{Page: 1, Out: "results.json", Query: "nginx"},
		},
		{
			name: "--out=file form",
			args: []string{"--out=data.json", "nginx"},
			want: searchOptions{Page: 1, Out: "data.json", Query: "nginx"},
		},
		{
			name: "flags combined",
			args: []string{"--all", "--out", "r.json", "--page", "2", "nginx"},
			want: searchOptions{Page: 2, All: true, Out: "r.json", Query: "nginx"},
		},
		{
			name: "query before flags",
			args: []string{"nginx", "--page", "7"},
			want: searchOptions{Page: 7, Query: "nginx"},
		},
		{
			name:    "missing query",
			args:    []string{"--page", "2"},
			wantErr: true,
		},
		{
			name:    "empty args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "--page missing value",
			args:    []string{"--page"},
			wantErr: true,
		},
		{
			name:    "--page zero",
			args:    []string{"--page", "0", "nginx"},
			wantErr: true,
		},
		{
			name:    "--page negative",
			args:    []string{"--page", "-1", "nginx"},
			wantErr: true,
		},
		{
			name:    "--out missing value",
			args:    []string{"--out"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"--notaflag", "nginx"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSearchArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSearchArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Page != tt.want.Page {
				t.Errorf("Page = %d, want %d", got.Page, tt.want.Page)
			}
			if got.All != tt.want.All {
				t.Errorf("All = %v, want %v", got.All, tt.want.All)
			}
			if got.Out != tt.want.Out {
				t.Errorf("Out = %q, want %q", got.Out, tt.want.Out)
			}
			if got.Query != tt.want.Query {
				t.Errorf("Query = %q, want %q", got.Query, tt.want.Query)
			}
		})
	}
}

// ─── formatLine ─────────────────────────────────────────────────────────────

func TestFormatLine(t *testing.T) {
	title := "My Site"
	tests := []struct {
		name string
		host shodan.Host
		want []string
	}{
		{
			name: "ip + port + org",
			host: shodan.Host{IPString: "1.2.3.4", Port: 80, Org: "Acme"},
			want: []string{"1.2.3.4", "80", "Acme"},
		},
		{
			name: "with product",
			host: shodan.Host{IPString: "5.6.7.8", Port: 443, Org: "Corp", Product: "Apache"},
			want: []string{"5.6.7.8", "443", "Corp", "Apache"},
		},
		{
			name: "product + version",
			host: shodan.Host{IPString: "9.0.0.1", Port: 22, Product: "OpenSSH", Version: "8.0"},
			want: []string{"OpenSSH", "8.0"},
		},
		{
			name: "with http title",
			host: shodan.Host{
				IPString: "10.0.0.1",
				Port:     80,
				HTTP:     &shodan.HostHTTP{Title: &title},
			},
			want: []string{"My Site"},
		},
		{
			name: "empty product skipped",
			host: shodan.Host{IPString: "1.1.1.1", Port: 53, Org: "CF"},
			want: []string{"1.1.1.1", "53", "CF"},
		},
		{
			name: "nil http skipped",
			host: shodan.Host{IPString: "2.2.2.2", Port: 80, HTTP: nil},
			want: []string{"2.2.2.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatLine(tt.host)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("formatLine() = %q, missing %q", got, want)
				}
			}
		})
	}
}

// ─── validateOutPath ─────────────────────────────────────────────────────────

func TestValidateOutPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "relative file", path: "results.json", wantErr: false},
		{name: "relative subdir", path: "out/results.json", wantErr: false},
		{name: "absolute path", path: "/tmp/results.json", wantErr: false},
		{name: "dotdot traversal", path: "../results.json", wantErr: true},
		{name: "complex dotdot", path: "a/../../results.json", wantErr: true},
		{name: "just dotdot", path: "..", wantErr: true},
		{name: "current dir is ok", path: ".", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOutPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// newTestClient creates a Client pointing at an httptest server.
// The server is closed automatically when the test ends.
func newTestClient(t *testing.T, handler http.HandlerFunc) *shodan.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
}

// ─── fetchPageWithRetry ──────────────────────────────────────────────────────

func TestFetchPageWithRetry(t *testing.T) {
	t.Run("success on first attempt", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"1.2.3.4","port":80}],"total":1}`)
		})
		r, err := fetchPageWithRetry(context.Background(), c, "nginx", 1, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.Matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(r.Matches))
		}
	})

	t.Run("success on second attempt after transient failure", func(t *testing.T) {
		calls := 0
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		_, err := fetchPageWithRetry(context.Background(), c, "nginx", 1, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 2 {
			t.Errorf("expected 2 server calls, got %d", calls)
		}
	})

	t.Run("all retries exhausted returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		_, err := fetchPageWithRetry(context.Background(), c, "nginx", 2, 0)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("all %d attempts failed", maxRetries)) {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

// ─── runHost ─────────────────────────────────────────────────────────────────

func TestRunHost(t *testing.T) {
	osStr := "Linux"
	tests := []struct {
		name       string
		body       string
		statusCode int
		wantOut    []string
		wantErr    bool
	}{
		{
			name:       "minimal host",
			statusCode: http.StatusOK,
			body:       `{"ip_str":"8.8.8.8","org":"Google","isp":"Google LLC","location":{"country_name":"United States"},"ports":[53,443]}`,
			wantOut:    []string{"IP:", "8.8.8.8", "Org:", "Google", "Country:", "United States", "Ports:"},
		},
		{
			name:       "host with OS and hostnames",
			statusCode: http.StatusOK,
			body:       fmt.Sprintf(`{"ip_str":"1.1.1.1","org":"CF","isp":"CF Inc","os":%q,"hostnames":["one.one.one.one"],"location":{"country_name":"AU"},"ports":[80]}`, osStr),
			wantOut:    []string{"OS:", "Linux", "Hosts:", "one.one.one.one"},
		},
		{
			name:       "api error propagated",
			statusCode: http.StatusNotFound,
			body:       `{"error":"No info available"}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, tt.body)
			})
			var buf bytes.Buffer
			err := runHost(context.Background(), c, []string{"8.8.8.8"}, &buf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runHost() error = %v, wantErr %v", err, tt.wantErr)
			}
			out := buf.String()
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("runHost() output missing %q\nfull output:\n%s", want, out)
				}
			}
		})
	}
}

// ─── runSearch ───────────────────────────────────────────────────────────────

func TestRunSearch(t *testing.T) {
	t.Run("single page results printed to writer", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"1.2.3.4","port":80,"org":"Acme"}],"total":1}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "1.2.3.4") {
			t.Errorf("expected IP in output, got:\n%s", out)
		}
		if !strings.Contains(out, "Found results: 1") {
			t.Errorf("expected result count in output, got:\n%s", out)
		}
	})

	t.Run("--page flag sends correct page to API", func(t *testing.T) {
		var gotPage string
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotPage = r.URL.Query().Get("page")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		var buf bytes.Buffer
		_ = runSearch(context.Background(), c, []string{"--page", "3", "nginx"}, &buf, 0, 0)
		if gotPage != "3" {
			t.Errorf("expected API page=3, got %q", gotPage)
		}
	})

	t.Run("--all fetches multiple pages", func(t *testing.T) {
		calls := 0
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusOK)
			// 101 total ⇒ 2 pages
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"1.2.3.4","port":80}],"total":101}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--all", "nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls < 2 {
			t.Errorf("expected ≥2 API calls for --all with 2 pages, got %d", calls)
		}
	})

	t.Run("--out writes JSON to absolute path", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"2.2.2.2","port":443}],"total":1}`)
		})
		outFile := filepath.Join(t.TempDir(), "results.json")
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--out", outFile, "nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data, readErr := os.ReadFile(outFile) //nolint:gosec // G304: test uses a temp dir path from t.TempDir(), safe in tests
		if readErr != nil {
			t.Fatalf("output file not created: %v", readErr)
		}
		var out searchOutput
		if jsonErr := json.Unmarshal(data, &out); jsonErr != nil {
			t.Fatalf("invalid JSON in output file: %v", jsonErr)
		}
		if out.Count != 1 {
			t.Errorf("expected Count=1, got %d", out.Count)
		}
		if len(out.Matches) > 0 && out.Matches[0].IPString != "2.2.2.2" {
			t.Errorf("unexpected IP in output: %s", out.Matches[0].IPString)
		}
	})

	t.Run("--out with dotdot path rejected", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--out", "../evil.json", "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error for dotdot --out path, got nil")
		}
	})

	t.Run("API error propagated to caller", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error from API, got nil")
		}
	})

	t.Run("invalid flag returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--badFlag", "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error for unknown flag, got nil")
		}
	})
}
