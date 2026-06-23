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
	"reflect"
	"strings"
	"testing"
	"time"

	shodan "shodan/api"
)

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
			want: searchOptions{Page: 1, Format: searchFormatText, Query: "apache"},
		},
		{
			name: "multi-word query",
			args: []string{"apache", "country:PL"},
			want: searchOptions{Page: 1, Format: searchFormatText, Query: "apache country:PL"},
		},
		{
			name: "--page flag",
			args: []string{"--page", "3", "nginx"},
			want: searchOptions{Page: 3, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "-page flag",
			args: []string{"-page", "2", "nginx"},
			want: searchOptions{Page: 2, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--page=N form",
			args: []string{"--page=5", "nginx"},
			want: searchOptions{Page: 5, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--all flag",
			args: []string{"--all", "nginx"},
			want: searchOptions{Page: 1, All: true, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--max-pages flag",
			args: []string{"--all", "--max-pages", "2", "nginx"},
			want: searchOptions{Page: 1, All: true, MaxPages: 2, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--max-pages=value form",
			args: []string{"--all", "--max-pages=3", "nginx"},
			want: searchOptions{Page: 1, All: true, MaxPages: 3, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "-all flag",
			args: []string{"-all", "nginx"},
			want: searchOptions{Page: 1, All: true, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--out flag",
			args: []string{"--out", "results.json", "nginx"},
			want: searchOptions{Page: 1, Out: "results.json", Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--out=file form",
			args: []string{"--out=data.json", "nginx"},
			want: searchOptions{Page: 1, Out: "data.json", Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "flags combined",
			args: []string{"--all", "--out", "r.json", "--page", "2", "nginx"},
			want: searchOptions{Page: 2, All: true, Out: "r.json", Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "query before flags",
			args: []string{"nginx", "--page", "7"},
			want: searchOptions{Page: 7, Format: searchFormatText, Query: "nginx"},
		},
		{
			name: "--format flag",
			args: []string{"--format", "json", "nginx"},
			want: searchOptions{Page: 1, Format: searchFormatJSON, Query: "nginx"},
		},
		{
			name: "--format=value form",
			args: []string{"--format=ndjson", "nginx"},
			want: searchOptions{Page: 1, Format: searchFormatNDJSON, Query: "nginx"},
		},
		{
			name: "--no-header flag",
			args: []string{"--no-header", "nginx"},
			want: searchOptions{Page: 1, Format: searchFormatText, NoHeader: true, Query: "nginx"},
		},
		{
			name: "--fail-on-empty flag",
			args: []string{"--fail-on-empty", "nginx"},
			want: searchOptions{Page: 1, Format: searchFormatText, FailOnEmpty: true, Query: "nginx"},
		},
		{
			name: "--fail-on-partial flag",
			args: []string{"--all", "--fail-on-partial", "nginx"},
			want: searchOptions{Page: 1, All: true, Format: searchFormatText, FailOnPartial: true, Query: "nginx"},
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
			name:    "--format missing value",
			args:    []string{"--format"},
			wantErr: true,
		},
		{
			name:    "--max-pages missing value",
			args:    []string{"--all", "--max-pages"},
			wantErr: true,
		},
		{
			name:    "--max-pages zero",
			args:    []string{"--all", "--max-pages", "0", "nginx"},
			wantErr: true,
		},
		{
			name:    "invalid --format value",
			args:    []string{"--format", "xml", "nginx"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"--notaflag", "nginx"},
			wantErr: true,
		},
		{
			name:    "--page=non-numeric",
			args:    []string{"--page=abc", "nginx"},
			wantErr: true,
		},
		{
			name:    "--max-pages=non-numeric",
			args:    []string{"--all", "--max-pages=abc", "nginx"},
			wantErr: true,
		},
		{
			name:    "--format=invalid value",
			args:    []string{"--format=xml", "nginx"},
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
			if got.MaxPages != tt.want.MaxPages {
				t.Errorf("MaxPages = %d, want %d", got.MaxPages, tt.want.MaxPages)
			}
			if got.Out != tt.want.Out {
				t.Errorf("Out = %q, want %q", got.Out, tt.want.Out)
			}
			if got.Format != tt.want.Format {
				t.Errorf("Format = %q, want %q", got.Format, tt.want.Format)
			}
			if got.NoHeader != tt.want.NoHeader {
				t.Errorf("NoHeader = %v, want %v", got.NoHeader, tt.want.NoHeader)
			}
			if got.FailOnEmpty != tt.want.FailOnEmpty {
				t.Errorf("FailOnEmpty = %v, want %v", got.FailOnEmpty, tt.want.FailOnEmpty)
			}
			if got.FailOnPartial != tt.want.FailOnPartial {
				t.Errorf("FailOnPartial = %v, want %v", got.FailOnPartial, tt.want.FailOnPartial)
			}
			if got.Query != tt.want.Query {
				t.Errorf("Query = %q, want %q", got.Query, tt.want.Query)
			}
		})
	}
}

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

func TestParseInputFlagArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantPos   []string
		wantInput string
		wantErr   bool
	}{
		{
			name:    "positional only",
			args:    []string{"8.8.8.8"},
			wantPos: []string{"8.8.8.8"},
		},
		{
			name:      "--input flag",
			args:      []string{"--input", "ips.txt"},
			wantInput: "ips.txt",
		},
		{
			name:      "--input=value form",
			args:      []string{"--input=ips.txt"},
			wantInput: "ips.txt",
		},
		{
			name:      "positional + --input",
			args:      []string{"google.com", "--input", "hosts.txt"},
			wantPos:   []string{"google.com"},
			wantInput: "hosts.txt",
		},
		{
			name:    "missing --input value",
			args:    []string{"--input"},
			wantErr: true,
		},
		{
			name:    "multiple --input flags",
			args:    []string{"--input", "a.txt", "--input", "b.txt"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"--bad"},
			wantErr: true,
		},
		{
			name:    "empty --input value (space form)",
			args:    []string{"--input", ""},
			wantErr: true,
		},
		{
			name:    "empty --input= value",
			args:    []string{"--input="},
			wantErr: true,
		},
		{
			name:    "duplicate --input= forms",
			args:    []string{"--input=a.txt", "--input=b.txt"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos, gotInput, err := parseInputFlagArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseInputFlagArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(gotPos) != len(tt.wantPos) {
				t.Errorf("positional = %v, want %v", gotPos, tt.wantPos)
			} else {
				for i := range gotPos {
					if gotPos[i] != tt.wantPos[i] {
						t.Errorf("positional = %v, want %v", gotPos, tt.wantPos)
						break
					}
				}
			}
			if gotInput != tt.wantInput {
				t.Errorf("input = %q, want %q", gotInput, tt.wantInput)
			}
		})
	}
}

func TestReadInputValues(t *testing.T) {
	t.Run("reads file, skips blanks/comments, and dedupes", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "values.txt")
		content := "# comment\n\n8.8.8.8\n1.1.1.1\n8.8.8.8\n"
		if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}
		got, err := readInputValues(filePath, strings.NewReader(""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"8.8.8.8", "1.1.1.1"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("values = %v, want %v", got, want)
		}
	})

	t.Run("reads from stdin when path is dash", func(t *testing.T) {
		stdin := strings.NewReader("google.com\ncloudflare.com\n#comment\ngoogle.com\n")
		got, err := readInputValues("-", stdin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"google.com", "cloudflare.com"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("values = %v, want %v", got, want)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := readInputValues(filepath.Join(t.TempDir(), "does-not-exist.txt"), strings.NewReader(""))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})
}

func TestDedupeValues(t *testing.T) {
	got := dedupeValues([]string{"a", " a ", "", "  ", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeValues() = %v, want %v", got, want)
	}
}

func TestFormatTSVLine(t *testing.T) {
	title := "Home\tPage\nLine"
	host := shodan.Host{
		IPString: "1.2.3.4",
		Port:     443,
		Org:      "Acme",
		Product:  "nginx",
		Version:  "1.25",
		HTTP:     &shodan.HostHTTP{Title: &title},
	}
	got := formatTSVLine(host)
	fields := strings.Split(got, "\t")
	if len(fields) != 6 {
		t.Fatalf("expected 6 tab-separated fields, got %d: %q", len(fields), got)
	}
	if fields[5] != "Home Page Line" {
		t.Errorf("title not sanitized, got %q", fields[5])
	}
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("output still contains newline characters: %q", got)
	}
}

// newTestClient creates a Client pointing at an httptest server.
// The server is closed automatically when the test ends.
func newTestClient(t *testing.T, handler http.HandlerFunc) *shodan.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
}

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

	t.Run("sleeps between retries when baseDelay is positive", func(t *testing.T) {
		calls := 0
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		if _, err := fetchPageWithRetry(context.Background(), c, "nginx", 1, time.Millisecond); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 2 {
			t.Errorf("expected 2 server calls, got %d", calls)
		}
	})
}

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

	t.Run("missing ip returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runHost(context.Background(), c, []string{}, &buf)
		if err == nil {
			t.Fatal("expected error for missing IP, got nil")
		}
	})

	t.Run("extra ip arguments return error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runHost(context.Background(), c, []string{"8.8.8.8", "1.1.1.1"}, &buf)
		if err == nil {
			t.Fatal("expected error for too many IP args, got nil")
		}
	})

	t.Run("--input file processes multiple unique IPs", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "ips.txt")
		content := "8.8.8.8\n1.1.1.1\n8.8.8.8\n"
		if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}

		calls := 0
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			switch {
			case strings.Contains(r.URL.Path, "/shodan/host/8.8.8.8"):
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"ip_str":"8.8.8.8","org":"Google","isp":"Google LLC","location":{"country_name":"United States"},"ports":[53,443]}`)
			case strings.Contains(r.URL.Path, "/shodan/host/1.1.1.1"):
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"ip_str":"1.1.1.1","org":"Cloudflare","isp":"Cloudflare Inc","location":{"country_name":"Australia"},"ports":[53]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, `{"error":"not found"}`)
			}
		})

		var buf bytes.Buffer
		err := runHost(context.Background(), c, []string{"--input", inputPath}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected 2 unique API calls, got %d", calls)
		}
		out := buf.String()
		if !strings.Contains(out, "8.8.8.8") || !strings.Contains(out, "1.1.1.1") {
			t.Fatalf("expected both IPs in output, got:\n%s", out)
		}
	})

	t.Run("mixing --input with positional ip returns error", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "ips.txt")
		if err := os.WriteFile(inputPath, []byte("8.8.8.8\n"), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runHost(context.Background(), c, []string{"--input", inputPath, "1.1.1.1"}, &buf)
		if err == nil {
			t.Fatal("expected error when mixing --input and positional IP")
		}
	})

	t.Run("unknown flag returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		if err := runHost(context.Background(), c, []string{"--bogus"}, &buf); err == nil {
			t.Fatal("expected error for unknown flag, got nil")
		}
	})

	t.Run("missing --input file returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		missing := filepath.Join(t.TempDir(), "nope.txt")
		if err := runHost(context.Background(), c, []string{"--input", missing}, &buf); err == nil {
			t.Fatal("expected error for missing input file, got nil")
		}
	})

	t.Run("empty --input file returns error", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "empty.txt")
		if err := os.WriteFile(inputPath, []byte("\n# only a comment\n"), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		if err := runHost(context.Background(), c, []string{"--input", inputPath}, &buf); err == nil {
			t.Fatal("expected error for empty input file, got nil")
		}
	})

	t.Run("falls back to country_code when country_name is empty", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"ip_str":"8.8.8.8","org":"Google","isp":"Google LLC","location":{"country_code":"US"},"ports":[53]}`)
		})
		var buf bytes.Buffer
		if err := runHost(context.Background(), c, []string{"8.8.8.8"}, &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), "Country: US") {
			t.Errorf("expected country code fallback in output, got:\n%s", buf.String())
		}
	})
}

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

	t.Run("--max-pages limits --all fetches and marks payload partial", func(t *testing.T) {
		calls := 0
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusOK)
			// 301 total => 4 pages, but we will cap at 2.
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"8.8.8.8","port":53}],"total":301}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--all", "--max-pages", "2", "--format", "json", "dns"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected exactly 2 API calls, got %d", calls)
		}

		var payload searchOutput
		if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
			t.Fatalf("expected valid json payload, got: %v", err)
		}
		if payload.TotalPages != 4 {
			t.Fatalf("expected total_pages=4, got %d", payload.TotalPages)
		}
		if payload.FetchedPages != 2 {
			t.Fatalf("expected fetched_pages=2, got %d", payload.FetchedPages)
		}
		if !payload.Partial {
			t.Fatal("expected payload to be marked as partial")
		}
	})

	t.Run("--fail-on-partial returns error when capped by --max-pages", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"9.9.9.9","port":53}],"total":201}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--all", "--max-pages", "1", "--fail-on-partial", "dns"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error for partial results with --fail-on-partial, got nil")
		}
		if !strings.Contains(err.Error(), "partial results") {
			t.Fatalf("expected partial-results error, got: %v", err)
		}
	})

	t.Run("--max-pages without --all returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--max-pages", "2", "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error when --max-pages used without --all, got nil")
		}
	})

	t.Run("--fail-on-partial without --all returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--fail-on-partial", "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error when --fail-on-partial used without --all, got nil")
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

	t.Run("--format json prints payload JSON to stdout", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"3.3.3.3","port":8080,"org":"Acme"}],"total":1}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--format", "json", "nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, "Found results:") {
			t.Fatalf("json output should not include text headers, got:\n%s", out)
		}

		var payload searchOutput
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("expected valid json payload, got error: %v", err)
		}
		if payload.Count != 1 {
			t.Fatalf("expected payload count 1, got %d", payload.Count)
		}
		if len(payload.Matches) != 1 || payload.Matches[0].IPString != "3.3.3.3" {
			t.Fatalf("unexpected matches payload: %+v", payload.Matches)
		}
	})

	t.Run("--format ndjson prints one host per line", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"4.4.4.4","port":80},{"ip_str":"5.5.5.5","port":443}],"total":2}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--format", "ndjson", "nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 ndjson lines, got %d", len(lines))
		}
		var h shodan.Host
		if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
			t.Fatalf("first line is not valid host json: %v", err)
		}
		if h.IPString != "4.4.4.4" {
			t.Fatalf("unexpected first host: %+v", h)
		}
	})

	t.Run("--format tsv prints header and rows", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"6.6.6.6","port":8443,"org":"OrgA","product":"Nginx","version":"1.24"}],"total":1}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--format", "tsv", "nginx"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := strings.TrimSpace(buf.String())
		lines := strings.Split(out, "\n")
		if len(lines) != 2 {
			t.Fatalf("expected header + 1 row, got %d lines", len(lines))
		}
		if lines[0] != "ip_str\tport\torg\tproduct\tversion\thttp_title" {
			t.Fatalf("unexpected tsv header: %q", lines[0])
		}
		if !strings.Contains(lines[1], "6.6.6.6\t8443\tOrgA\tNginx\t1.24") {
			t.Fatalf("unexpected tsv row: %q", lines[1])
		}
	})

	t.Run("--format tsv with --no-header suppresses header", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"7.7.7.7","port":53}],"total":1}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--format", "tsv", "--no-header", "dns"}, &buf, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := strings.TrimSpace(buf.String())
		if strings.Contains(out, "ip_str\tport\torg\tproduct\tversion\thttp_title") {
			t.Fatalf("expected no tsv header, got:\n%s", out)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 1 {
			t.Fatalf("expected exactly one data row, got %d lines", len(lines))
		}
	})

	t.Run("--fail-on-empty returns error when no matches", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[],"total":0}`)
		})
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--fail-on-empty", "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error for empty results with --fail-on-empty, got nil")
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

	t.Run("--all marks results partial when a later page keeps failing", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("page") == "1" {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"1.2.3.4","port":80}],"total":101}`)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		var buf bytes.Buffer
		// non-zero pagePause exercises the inter-page sleep path; retryBase 0 keeps it fast.
		err := runSearch(context.Background(), c, []string{"--all", "--format", "json", "nginx"}, &buf, time.Millisecond, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var payload searchOutput
		if jsonErr := json.Unmarshal(buf.Bytes(), &payload); jsonErr != nil {
			t.Fatalf("expected valid json payload, got: %v", jsonErr)
		}
		if !payload.Partial {
			t.Fatal("expected payload to be marked partial after page failure")
		}
		if payload.FetchedPages != 1 || payload.Count != 1 {
			t.Fatalf("expected page-1 results preserved, got fetched=%d count=%d", payload.FetchedPages, payload.Count)
		}
	})

	t.Run("--out write failure returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"matches":[{"ip_str":"2.2.2.2","port":443}],"total":1}`)
		})
		// Directory component does not exist, so os.WriteFile fails while the path passes validation.
		badPath := filepath.Join(t.TempDir(), "missing-dir", "out.json")
		var buf bytes.Buffer
		err := runSearch(context.Background(), c, []string{"--out", badPath, "nginx"}, &buf, 0, 0)
		if err == nil {
			t.Fatal("expected error when output file cannot be written, got nil")
		}
	})
}

func TestRunCount(t *testing.T) {
	t.Run("prints total", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"total":1337,"facets":{}}`)
		})
		var buf bytes.Buffer
		err := runCount(context.Background(), c, []string{"nginx"}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), "1337") {
			t.Errorf("expected 1337 in output, got: %s", buf.String())
		}
	})

	t.Run("missing query returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runCount(context.Background(), c, []string{}, &buf)
		if err == nil {
			t.Fatal("expected error for missing query, got nil")
		}
	})

	t.Run("api error propagated", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		var buf bytes.Buffer
		err := runCount(context.Background(), c, []string{"nginx"}, &buf)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestRunDNS(t *testing.T) {
	t.Run("prints domain info", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"domain":"example.com","subdomains":["www","mail"],"data":[{"subdomain":"www","type":"A","value":"1.2.3.4","last_seen":"2024-01-01"}],"tags":[],"more":false}`)
		})
		var buf bytes.Buffer
		err := runDNS(context.Background(), c, []string{"example.com"}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "example.com") {
			t.Errorf("expected domain in output, got: %s", out)
		}
		if !strings.Contains(out, "www") {
			t.Errorf("expected subdomain in output, got: %s", out)
		}
	})

	t.Run("missing domain returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runDNS(context.Background(), c, []string{}, &buf)
		if err == nil {
			t.Fatal("expected error for missing domain, got nil")
		}
	})

	t.Run("extra domain arguments return error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runDNS(context.Background(), c, []string{"example.com", "extra.example.com"}, &buf)
		if err == nil {
			t.Fatal("expected error for too many domain args, got nil")
		}
	})

	t.Run("api error propagated", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		var buf bytes.Buffer
		if err := runDNS(context.Background(), c, []string{"example.com"}, &buf); err == nil {
			t.Fatal("expected error from API, got nil")
		}
	})

	t.Run("prints tags and caps records, with --all-records showing all", func(t *testing.T) {
		// Build 60 records (> the 50 cap), including an apex (empty subdomain)
		// and one very long subdomain that must be truncated in the FQDN column.
		var records []string
		records = append(records, `{"subdomain":"","type":"A","value":"1.1.1.1"}`)
		records = append(records, fmt.Sprintf(`{"subdomain":%q,"type":"A","value":"2.2.2.2"}`, strings.Repeat("a", 60)))
		for i := 0; i < 58; i++ {
			records = append(records, fmt.Sprintf(`{"subdomain":"h%d","type":"A","value":"3.3.3.3"}`, i))
		}
		body := fmt.Sprintf(`{"domain":"example.com","tags":["spf","dmarc"],"subdomains":["www"],"data":[%s]}`, strings.Join(records, ","))

		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, body)
		})

		var capped bytes.Buffer
		if err := runDNS(context.Background(), c, []string{"example.com"}, &capped); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := capped.String()
		if !strings.Contains(out, "Tags:") || !strings.Contains(out, "spf") {
			t.Errorf("expected tags in output, got:\n%s", out)
		}
		if !strings.Contains(out, "@.example.com") {
			t.Errorf("expected apex record rendered as @, got:\n%s", out)
		}
		if !strings.Contains(out, "...") {
			t.Errorf("expected a truncated long FQDN, got:\n%s", out)
		}
		if !strings.Contains(out, "more records") {
			t.Errorf("expected truncation notice for capped records, got:\n%s", out)
		}

		var full bytes.Buffer
		if err := runDNS(context.Background(), c, []string{"--all-records", "example.com"}, &full); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(full.String(), "more records") {
			t.Errorf("--all-records should not truncate, got:\n%s", full.String())
		}
	})
}

func TestRunResolve(t *testing.T) {
	t.Run("prints hostname to ip", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"google.com":"142.250.74.46"}`)
		})
		var buf bytes.Buffer
		err := runResolve(context.Background(), c, []string{"google.com"}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "google.com") || !strings.Contains(out, "142.250.74.46") {
			t.Errorf("unexpected output: %s", out)
		}
	})

	t.Run("missing args returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runResolve(context.Background(), c, []string{}, &buf)
		if err == nil {
			t.Fatal("expected error for missing args, got nil")
		}
	})

	t.Run("--input file merges with positional hosts and dedupes", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "hosts.txt")
		content := "google.com\ncloudflare.com\ngoogle.com\n"
		if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}

		var gotHostnames string
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotHostnames = r.URL.Query().Get("hostnames")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"example.com":"93.184.216.34","google.com":"142.250.74.46","cloudflare.com":"1.1.1.1"}`)
		})

		var buf bytes.Buffer
		err := runResolve(context.Background(), c, []string{"example.com", "--input", inputPath}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if gotHostnames != "example.com,google.com,cloudflare.com" {
			t.Fatalf("unexpected hostnames query: %q", gotHostnames)
		}
		out := buf.String()
		if !strings.Contains(out, "example.com") || !strings.Contains(out, "google.com") || !strings.Contains(out, "cloudflare.com") {
			t.Fatalf("missing expected hosts in output:\n%s", out)
		}
	})

	t.Run("empty --input without positional hosts returns error", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "empty-hosts.txt")
		if err := os.WriteFile(inputPath, []byte("\n# nothing\n"), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runResolve(context.Background(), c, []string{"--input", inputPath}, &buf)
		if err == nil {
			t.Fatal("expected error for empty --input with no positional hosts")
		}
	})

	t.Run("unknown flag returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		if err := runResolve(context.Background(), c, []string{"--bogus"}, &buf); err == nil {
			t.Fatal("expected error for unknown flag, got nil")
		}
	})

	t.Run("missing --input file returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		missing := filepath.Join(t.TempDir(), "nope.txt")
		if err := runResolve(context.Background(), c, []string{"--input", missing}, &buf); err == nil {
			t.Fatal("expected error for missing input file, got nil")
		}
	})

	t.Run("api error propagated", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		var buf bytes.Buffer
		if err := runResolve(context.Background(), c, []string{"google.com"}, &buf); err == nil {
			t.Fatal("expected error from API, got nil")
		}
	})

	t.Run("unresolved hostname shows not-found marker", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{}`)
		})
		var buf bytes.Buffer
		if err := runResolve(context.Background(), c, []string{"nope.invalid"}, &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), "(not found)") {
			t.Errorf("expected not-found marker, got:\n%s", buf.String())
		}
	})
}

func TestRunReverse(t *testing.T) {
	t.Run("prints ip to hostnames", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"8.8.8.8":["dns.google"]}`)
		})
		var buf bytes.Buffer
		err := runReverse(context.Background(), c, []string{"8.8.8.8"}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "8.8.8.8") || !strings.Contains(out, "dns.google") {
			t.Errorf("unexpected output: %s", out)
		}
	})

	t.Run("no PTR record shown gracefully", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{}`)
		})
		var buf bytes.Buffer
		err := runReverse(context.Background(), c, []string{"1.2.3.4"}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), "no PTR record") {
			t.Errorf("expected 'no PTR record' in output, got: %s", buf.String())
		}
	})

	t.Run("missing args returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		err := runReverse(context.Background(), c, []string{}, &buf)
		if err == nil {
			t.Fatal("expected error for missing args, got nil")
		}
	})

	t.Run("--input file merges with positional ips and dedupes", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "ips.txt")
		content := "1.1.1.1\n8.8.8.8\n1.1.1.1\n"
		if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to create input file: %v", err)
		}

		var gotIPs string
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotIPs = r.URL.Query().Get("ips")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"9.9.9.9":["dns9.quad9.net"],"1.1.1.1":["one.one.one.one"],"8.8.8.8":["dns.google"]}`)
		})
		var buf bytes.Buffer
		err := runReverse(context.Background(), c, []string{"9.9.9.9", "--input", inputPath}, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotIPs != "9.9.9.9,1.1.1.1,8.8.8.8" {
			t.Fatalf("unexpected ips query: %q", gotIPs)
		}
		out := buf.String()
		if !strings.Contains(out, "9.9.9.9") || !strings.Contains(out, "1.1.1.1") || !strings.Contains(out, "8.8.8.8") {
			t.Fatalf("missing expected ips in output:\n%s", out)
		}
	})

	t.Run("unknown flag returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		if err := runReverse(context.Background(), c, []string{"--bogus"}, &buf); err == nil {
			t.Fatal("expected error for unknown flag, got nil")
		}
	})

	t.Run("missing --input file returns error", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		var buf bytes.Buffer
		missing := filepath.Join(t.TempDir(), "nope.txt")
		if err := runReverse(context.Background(), c, []string{"--input", missing}, &buf); err == nil {
			t.Fatal("expected error for missing input file, got nil")
		}
	})

	t.Run("api error propagated", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		var buf bytes.Buffer
		if err := runReverse(context.Background(), c, []string{"8.8.8.8"}, &buf); err == nil {
			t.Fatal("expected error from API, got nil")
		}
	})
}

func TestRunMyIP(t *testing.T) {
	t.Run("prints public ip", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `"203.0.113.42"`)
		})
		var buf bytes.Buffer
		err := runMyIP(context.Background(), c, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), "203.0.113.42") {
			t.Errorf("expected IP in output, got: %s", buf.String())
		}
	})

	t.Run("api error propagated", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		var buf bytes.Buffer
		err := runMyIP(context.Background(), c, &buf)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
