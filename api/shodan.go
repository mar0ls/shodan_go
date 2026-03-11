package shodan

import (
	"net/http"
	"time"
)

// BaseURL is the default Shodan API endpoint.
const BaseURL = "https://api.shodan.io"

// Client holds API key and shared HTTP client config.
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a Shodan client with a sane default timeout.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// New is kept as a short alias for compatibility.
func New(apiKey string) *Client {
	return NewClient(apiKey)
}
