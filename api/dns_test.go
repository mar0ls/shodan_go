package shodan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	shodan "shodan/api"
)

func newTestClientDNS(t *testing.T, handler http.HandlerFunc) *shodan.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return shodan.NewClient("test-key", shodan.WithBaseURL(ts.URL))
}

func TestGetDomain(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantDomain string
		wantSubs   int
		wantErr    bool
	}{
		{
			name:       "success",
			statusCode: http.StatusOK,
			body:       `{"domain":"example.com","subdomains":["www","mail"],"data":[{"subdomain":"www","type":"A","value":"1.2.3.4","last_seen":"2024-01-01"}],"tags":[],"more":false}`,
			wantDomain: "example.com",
			wantSubs:   2,
		},
		{
			name:       "api error",
			statusCode: http.StatusForbidden,
			body:       `{"error":"Forbidden"}`,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, tt.body)
			})
			info, err := c.GetDomain(context.Background(), "example.com")
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if info.Domain != tt.wantDomain {
				t.Errorf("Domain = %q, want %q", info.Domain, tt.wantDomain)
			}
			if len(info.Subdomains) != tt.wantSubs {
				t.Errorf("Subdomains len = %d, want %d", len(info.Subdomains), tt.wantSubs)
			}
		})
	}
}

func TestResolveHostnames(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("hostnames") == "" {
				t.Error("missing hostnames param")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"google.com":"142.250.74.46","cloudflare.com":"104.16.132.229"}`)
		})
		result, err := c.ResolveHostnames(context.Background(), "google.com", "cloudflare.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["google.com"] == "" {
			t.Error("expected IP for google.com")
		}
	})

	t.Run("api error", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		_, err := c.ResolveHostnames(context.Background(), "google.com")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestReverseIPs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("ips") == "" {
				t.Error("missing ips param")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"8.8.8.8":["dns.google"]}`)
		})
		result, err := c.ReverseIPs(context.Background(), "8.8.8.8")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result["8.8.8.8"]) == 0 {
			t.Error("expected hostnames for 8.8.8.8")
		}
	})

	t.Run("api error", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err := c.ReverseIPs(context.Background(), "8.8.8.8")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestMyIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `"203.0.113.42"`)
		})
		ip, err := c.MyIP(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ip != "203.0.113.42" {
			t.Errorf("MyIP() = %q, want %q", ip, "203.0.113.42")
		}
	})

	t.Run("api error", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		_, err := c.MyIP(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestCountHosts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"total":42,"facets":{}}`)
		})
		result, err := c.CountHosts(context.Background(), "nginx")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Total != 42 {
			t.Errorf("Total = %d, want 42", result.Total)
		}
	})

	t.Run("api error", func(t *testing.T) {
		c := newTestClientDNS(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := c.CountHosts(context.Background(), "nginx")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
