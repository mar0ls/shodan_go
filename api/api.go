// Package shodan provides a small client for the Shodan API.
package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// APIInfo contains account credits and plan capabilities.
type APIInfo struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Telnet       bool   `json:"telnet"`
	Plan         string `json:"plan"`
	HTTPS        bool   `json:"https"`
	Unlocked     bool   `json:"unlocked"`
}

// GetAPIInfo returns account limits and subscription-related fields.
func (s *Client) GetAPIInfo(ctx context.Context) (*APIInfo, error) {
	v := url.Values{"key": {s.apiKey}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/api-info?"+v.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("GetAPIInfo: build request: %w", err)
	}
	//nolint:gosec // G704: base URL is set at construction time from application config, not from request input.
	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetAPIInfo: %w", sanitizeErr(err))
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetAPIInfo: shodan API error: %s", res.Status)
	}

	var ret APIInfo
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, fmt.Errorf("GetAPIInfo: decode response: %w", err)
	}
	return &ret, nil
}

// APIInfo is a compatibility alias for GetAPIInfo.
//
// Deprecated: Use GetAPIInfo instead.
func (s *Client) APIInfo(ctx context.Context) (*APIInfo, error) {
	return s.GetAPIInfo(ctx)
}
