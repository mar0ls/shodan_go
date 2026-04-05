package shodan_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	shodan "shodan/api"
)

func TestGetAPIInfo(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		body        any
		rawBody     string
		wantErr     bool
		wantCredits int
	}{
		{
			name:        "success",
			statusCode:  http.StatusOK,
			body:        shodan.APIInfo{QueryCredits: 42, ScanCredits: 10},
			wantCredits: 42,
		},
		{
			name:       "api error 403",
			statusCode: http.StatusForbidden,
			body:       map[string]string{"error": "Access denied"},
			wantErr:    true,
		},
		{
			name:       "invalid json response",
			statusCode: http.StatusOK,
			rawBody:    "not-json",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api-info" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.URL.Query().Get("key") == "" {
					t.Error("missing key query param")
				}
				w.WriteHeader(tt.statusCode)
				if tt.rawBody != "" {
					_, _ = w.Write([]byte(tt.rawBody))
					return
				}
				_ = json.NewEncoder(w).Encode(tt.body)
			}))
			defer ts.Close()

			c := shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
			info, err := c.GetAPIInfo(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetAPIInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && info.QueryCredits != tt.wantCredits {
				t.Errorf("QueryCredits = %d, want %d", info.QueryCredits, tt.wantCredits)
			}
		})
	}
}

func TestGetAPIInfo_KeyNotInError(t *testing.T) {
	c := shodan.NewClient("super-secret-key", shodan.WithBaseURL("http://127.0.0.1:1"))
	_, err := c.GetAPIInfo(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "super-secret-key") {
		t.Errorf("API key leaked in error message: %v", err)
	}
}

func TestSearchHosts(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantCount  int
		wantTotal  int
	}{
		{
			name:       "success single match",
			statusCode: http.StatusOK,
			body:       `{"matches":[{"ip_str":"1.2.3.4","port":80}],"total":1}`,
			wantCount:  1,
			wantTotal:  1,
		},
		{
			name:       "success empty matches",
			statusCode: http.StatusOK,
			body:       `{"matches":[],"total":0}`,
			wantCount:  0,
			wantTotal:  0,
		},
		{
			name:       "api error 401",
			statusCode: http.StatusUnauthorized,
			body:       `{"error":"Invalid API key"}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/shodan/host/search") {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.URL.Query().Get("key") == "" {
					t.Error("missing key query param")
				}
				if r.URL.Query().Get("query") == "" {
					t.Error("missing query param")
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer ts.Close()

			c := shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
			result, err := c.SearchHosts(context.Background(), "nginx", 1)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SearchHosts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(result.Matches) != tt.wantCount {
					t.Errorf("len(Matches) = %d, want %d", len(result.Matches), tt.wantCount)
				}
				if result.Total != tt.wantTotal {
					t.Errorf("Total = %d, want %d", result.Total, tt.wantTotal)
				}
			}
		})
	}
}

func TestSearchHosts_PageNormalization(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page != "1" {
			t.Errorf("expected page=1 for page<=0 input, got %q", page)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"matches":[],"total":0}`))
	}))
	defer ts.Close()

	c := shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
	_, err := c.SearchHosts(context.Background(), "query", 0)
	if err != nil {
		t.Fatalf("SearchHosts() unexpected error: %v", err)
	}
}

func TestGetHostByIP(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		statusCode int
		body       string
		wantErr    bool
		wantIP     string
	}{
		{
			name:       "success",
			ip:         "1.2.3.4",
			statusCode: http.StatusOK,
			body:       `{"ip_str":"1.2.3.4","org":"ExampleCorp","ports":[80,443]}`,
			wantIP:     "1.2.3.4",
		},
		{
			name:       "not found",
			ip:         "0.0.0.0",
			statusCode: http.StatusNotFound,
			body:       `{"error":"No information available for that IP."}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("key") == "" {
					t.Error("missing key query param")
				}
				if !strings.Contains(r.URL.Path, tt.ip) {
					t.Errorf("IP %q not found in path %q", tt.ip, r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer ts.Close()

			c := shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
			host, err := c.GetHostByIP(context.Background(), tt.ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetHostByIP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
			if !tt.wantErr && host.IPString != tt.wantIP {
				t.Errorf("IPString = %q, want %q", host.IPString, tt.wantIP)
			}
		})
	}
}
