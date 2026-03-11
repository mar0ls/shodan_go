package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// HostLocation describes geographic metadata for a host.
type HostLocation struct {
	City         *string `json:"city"`
	RegionCode   *string `json:"region_code"`
	AreaCode     *int    `json:"area_code"`
	Longitude    float64 `json:"longitude"`
	CountryCode3 *string `json:"country_code3"`
	CountryName  string  `json:"country_name"`
	PostalCode   *string `json:"postal_code"`
	DMACode      *int    `json:"dma_code"`
	CountryCode  string  `json:"country_code"`
	Latitude     float64 `json:"latitude"`
}

// HostHTTP is a small subset of HTTP metadata returned by Shodan.
type HostHTTP struct {
	Title      *string        `json:"title"`
	Server     *string        `json:"server"`
	Host       string         `json:"host"`
	HTML       *string        `json:"html"`
	HTMLHash   *int64         `json:"html_hash"`
	Location   string         `json:"location"`
	Redirects  []interface{}  `json:"redirects"`
	Components map[string]any `json:"components"`
}

// Meta stores scan metadata embedded under _shodan.
type Meta struct {
	ID      string `json:"id"`
	Module  string `json:"module"`
	Crawler string `json:"crawler"`
	Ptr     bool   `json:"ptr"`
}

// Host represents one service banner/record returned by search and lookup APIs.
type Host struct {
	IPString  string          `json:"ip_str"`
	IP        int64           `json:"ip"`
	Org       string          `json:"org"`
	ISP       string          `json:"isp"`
	ASN       string          `json:"asn"`
	OS        *string         `json:"os"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	Transport string          `json:"transport"`
	Hash      int64           `json:"hash"`
	CPE       []string        `json:"cpe"`
	Timestamp string          `json:"timestamp"`
	Hostnames []string        `json:"hostnames"`
	Domains   []string        `json:"domains"`
	Location  HostLocation    `json:"location"`
	HTTP      *HostHTTP       `json:"http"`
	Shodan    *Meta           `json:"_shodan"`
	Data      json.RawMessage `json:"data"`  // string in search, array in host lookup
	Port      int             `json:"port"`  // single port in search results
	Ports     []int           `json:"ports"` // all open ports in host lookup
}

// FacetCount represents one bucket in aggregated facet results.
type FacetCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// SearchResult is the paginated response returned by host search.
type SearchResult struct {
	Matches []Host                  `json:"matches"`
	Total   int                     `json:"total"`
	Facets  map[string][]FacetCount `json:"facets"`
}

// SearchHosts runs /shodan/host/search with query and page number.
func (s *Client) SearchHosts(query string, page int) (*SearchResult, error) {
	if page < 1 {
		page = 1
	}
	v := url.Values{}
	v.Set("key", s.apiKey)
	v.Set("query", query)
	v.Set("page", fmt.Sprintf("%d", page))
	res, err := s.httpClient.Get(
		fmt.Sprintf("%s/shodan/host/search?%s", BaseURL, v.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error: %s", res.Status)
	}

	var ret SearchResult
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}

	return &ret, nil
}

// GetHostByIP fetches detailed host information for a specific IP.
func (s *Client) GetHostByIP(ip string) (*Host, error) {
	res, err := s.httpClient.Get(
		fmt.Sprintf("%s/shodan/host/%s?key=%s", BaseURL, ip, s.apiKey),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error: %s", res.Status)
	}

	var ret Host
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}

	return &ret, nil
}

// HostSearch is a compatibility alias for SearchHosts.
func (s *Client) HostSearch(q string, page int) (*SearchResult, error) {
	return s.SearchHosts(q, page)
}

// HostLookup is a compatibility alias for GetHostByIP.
func (s *Client) HostLookup(ip string) (*Host, error) {
	return s.GetHostByIP(ip)
}
