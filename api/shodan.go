package shodan

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// BaseURL is the default Shodan API endpoint.
const BaseURL = "https://api.shodan.io"

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the default API base URL. Primarily used in tests.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) { c.baseURL = baseURL }
}

// Client holds API key and shared HTTP client config.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Shodan client with a sane default timeout.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: BaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// New is kept as a short alias for NewClient.
//
// Deprecated: Use NewClient instead.
func New(apiKey string) *Client {
	return NewClient(apiKey)
}

// sanitizeErr strips the URL (which may contain the API key) from net/http URL errors.
func sanitizeErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
