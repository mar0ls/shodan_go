// Package shodan provides a small client for the Shodan API.
package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
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
func (s *Client) GetAPIInfo() (*APIInfo, error) {
	res, err := s.httpClient.Get(fmt.Sprintf("%s/api-info?key=%s", BaseURL, s.apiKey))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error: %s", res.Status)
	}

	var ret APIInfo
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

// APIInfo is a compatibility alias for GetAPIInfo.
func (s *Client) APIInfo() (*APIInfo, error) {
	return s.GetAPIInfo()
}
