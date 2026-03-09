package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// Response wraps an HTTP response with its body pre-read and the connection closed.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// do executes a raw HTTP request and returns the response with body fully read.
func (c *Client) do(ctx context.Context, method, path string, header http.Header, body []byte) (*Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, path, err)
	}
	for k, vv := range header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // deferred close; read error checked below

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
	}, nil
}

// Options sends an OPTIONS request.
func (c *Client) Options(ctx context.Context, path string) (*Response, error) {
	return c.do(ctx, http.MethodOptions, path, nil, nil)
}

// Get sends a GET request.
func (c *Client) Get(ctx context.Context, path string) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, nil, nil)
}

// GetWithAccept sends a GET request with the given Accept header value.
func (c *Client) GetWithAccept(ctx context.Context, path, accept string) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, http.Header{"Accept": {accept}}, nil)
}

// Put sends a PUT request with the given Content-Type and body.
func (c *Client) Put(ctx context.Context, path, contentType string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {contentType}}
	return c.do(ctx, http.MethodPut, path, h, body)
}

// Delete sends a DELETE request. ifMatch may be "" or an ETag value.
func (c *Client) Delete(ctx context.Context, path, ifMatch string) (*Response, error) {
	var h http.Header
	if ifMatch != "" {
		h = http.Header{"If-Match": {ifMatch}}
	}
	return c.do(ctx, http.MethodDelete, path, h, nil)
}

// Mkcol sends a MKCOL request. body may be nil for simple MKCOL (RFC 4918),
// or an XML body for extended MKCOL (RFC 5689).
func (c *Client) Mkcol(ctx context.Context, path string, body []byte) (*Response, error) {
	var h http.Header
	if body != nil {
		h = http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	}
	return c.do(ctx, "MKCOL", path, h, body)
}

// Copy sends a COPY request.
func (c *Client) Copy(ctx context.Context, src, dst string, overwrite bool) (*Response, error) {
	ow := "F"
	if overwrite {
		ow = "T"
	}
	h := http.Header{
		"Destination": {c.resolve(dst)},
		"Overwrite":   {ow},
	}
	return c.do(ctx, "COPY", src, h, nil)
}

// Move sends a MOVE request.
func (c *Client) Move(ctx context.Context, src, dst string, overwrite bool) (*Response, error) {
	ow := "F"
	if overwrite {
		ow = "T"
	}
	h := http.Header{
		"Destination": {c.resolve(dst)},
		"Overwrite":   {ow},
	}
	return c.do(ctx, "MOVE", src, h, nil)
}

// Propfind sends a PROPFIND request. depth is "0", "1", or "infinity".
func (c *Client) Propfind(ctx context.Context, path, depth string, body []byte) (*Response, error) {
	h := http.Header{
		"Depth":        {depth},
		"Content-Type": {"application/xml; charset=utf-8"},
	}
	return c.do(ctx, "PROPFIND", path, h, body)
}

// Proppatch sends a PROPPATCH request.
func (c *Client) Proppatch(ctx context.Context, path string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	return c.do(ctx, "PROPPATCH", path, h, body)
}

// Report sends a REPORT request.
func (c *Client) Report(ctx context.Context, path string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	return c.do(ctx, "REPORT", path, h, body)
}

// Lock sends a LOCK request.
func (c *Client) Lock(ctx context.Context, path string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	return c.do(ctx, "LOCK", path, h, body)
}

// Unlock sends an UNLOCK request with the given lock token URI.
func (c *Client) Unlock(ctx context.Context, path, lockToken string) (*Response, error) {
	h := http.Header{"Lock-Token": {"<" + lockToken + ">"}}
	return c.do(ctx, "UNLOCK", path, h, nil)
}

// ACL sends an ACL request.
func (c *Client) ACL(ctx context.Context, path string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	return c.do(ctx, "ACL", path, h, body)
}
