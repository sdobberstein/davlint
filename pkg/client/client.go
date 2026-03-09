// Package client provides a WebDAV HTTP client for davlint conformance tests.
package client

import (
	"context"
	"fmt"
	"io"
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

// Username returns the authenticated principal's username.
func (c *Client) Username() string {
	return c.username
}

// GetNoRedirect sends a GET request without following redirects.
// It returns the redirect response (301/302) rather than the final destination.
func (c *Client) GetNoRedirect(ctx context.Context, path string) (*Response, error) {
	noFollow := &http.Client{
		Timeout: c.http.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.resolve(path), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request GET %s: %w", path, err)
	}
	req.SetBasicAuth(c.username, c.password)
	resp, err := noFollow.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET (no-redirect) %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // deferred close; read error checked below
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
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
