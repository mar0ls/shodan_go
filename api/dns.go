package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DomainInfo contains DNS records and subdomains for a domain.
type DomainInfo struct {
	Domain     string      `json:"domain"`
	Tags       []string    `json:"tags"`
	Data       []DNSRecord `json:"data"`
	Subdomains []string    `json:"subdomains"`
	More       bool        `json:"more"`
}

// DNSRecord is a single DNS entry returned by the domain lookup endpoint.
type DNSRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	LastSeen  string `json:"last_seen"`
}

// GetDomain looks up subdomains and DNS records for a domain.
// Requires a paid Shodan API plan; free keys return 403.
func (s *Client) GetDomain(ctx context.Context, domain string) (*DomainInfo, error) {
	v := url.Values{"key": {s.apiKey}}
	rawURL := s.baseURL + "/dns/domain/" + url.PathEscape(domain) + "?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("GetDomain %s: build request: %w", domain, err)
	}
	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetDomain %s: %w", domain, sanitizeErr(err))
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetDomain %s: shodan API error: %s", domain, res.Status)
	}

	var ret DomainInfo
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, fmt.Errorf("GetDomain %s: decode response: %w", domain, err)
	}
	return &ret, nil
}

// ResolveHostnames resolves one or more hostnames to IP addresses.
// Returns a map of hostname → IP string.
func (s *Client) ResolveHostnames(ctx context.Context, hostnames ...string) (map[string]string, error) {
	v := url.Values{}
	v.Set("key", s.apiKey)
	v.Set("hostnames", strings.Join(hostnames, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/dns/resolve?"+v.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("ResolveHostnames: build request: %w", err)
	}
	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ResolveHostnames: %w", sanitizeErr(err))
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ResolveHostnames: shodan API error: %s", res.Status)
	}

	var ret map[string]string
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, fmt.Errorf("ResolveHostnames: decode response: %w", err)
	}
	return ret, nil
}

// ReverseIPs performs reverse DNS lookup for one or more IP addresses.
// Returns a map of IP → list of hostnames.
func (s *Client) ReverseIPs(ctx context.Context, ips ...string) (map[string][]string, error) {
	v := url.Values{}
	v.Set("key", s.apiKey)
	v.Set("ips", strings.Join(ips, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/dns/reverse?"+v.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("ReverseIPs: build request: %w", err)
	}
	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ReverseIPs: %w", sanitizeErr(err))
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ReverseIPs: shodan API error: %s", res.Status)
	}

	var ret map[string][]string
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, fmt.Errorf("ReverseIPs: decode response: %w", err)
	}
	return ret, nil
}

// MyIP returns the public IP address of the caller as seen by Shodan.
func (s *Client) MyIP(ctx context.Context) (string, error) {
	v := url.Values{"key": {s.apiKey}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/tools/myip?"+v.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("MyIP: build request: %w", err)
	}
	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("MyIP: %w", sanitizeErr(err))
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MyIP: shodan API error: %s", res.Status)
	}

	var ip string
	if err := json.NewDecoder(res.Body).Decode(&ip); err != nil {
		return "", fmt.Errorf("MyIP: decode response: %w", err)
	}
	return ip, nil
}
