// Package client provides a WebDAV HTTP client for davlint conformance tests.
package client

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Client is a WebDAV HTTP client bound to a single server and principal.
type Client struct {
	baseURL  *url.URL
	username string
	password string
	http     *http.Client
}

// New creates a Client for the given base URL and credentials.
func New(baseURL, username, password string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	return &Client{
		baseURL:  u,
		username: username,
		password: password,
		http:     &http.Client{Timeout: timeout},
	}, nil
}

// BaseURL returns the server base URL string.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

// resolve returns an absolute URL for the given path relative to the base URL.
func (c *Client) resolve(path string) string {
	ref, err := url.Parse(path)
	if err != nil {
		// Path values in davlint come from static test code; a parse failure is a programming error.
		panic(fmt.Sprintf("davlint: resolve: bad path %q: %v", path, err))
	}
	return c.baseURL.ResolveReference(ref).String()
}
