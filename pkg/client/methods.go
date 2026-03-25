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

// doNoAuth executes a raw HTTP request without credentials and returns the response with body fully read.
func (c *Client) doNoAuth(ctx context.Context, method, path string, header http.Header, body []byte) (*Response, error) {
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
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // deferred close; read error checked below
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: respBody}, nil
}

// PropfindNoAuth sends a PROPFIND request without credentials.
// Use this to test that the server requires authentication (RFC 6764 §7 MUST).
func (c *Client) PropfindNoAuth(ctx context.Context, path, depth string, body []byte) (*Response, error) {
	h := http.Header{
		"Depth":        {depth},
		"Content-Type": {"application/xml; charset=utf-8"},
	}
	return c.doNoAuth(ctx, "PROPFIND", path, h, body)
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

// MkcolRaw sends a MKCOL request with an explicit Content-Type header.
// Use this to test server behaviour when Content-Type is incorrect (RFC 5689 §3 R-01).
func (c *Client) MkcolRaw(ctx context.Context, path, contentType string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {contentType}}
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

// ReportWithDepth sends a REPORT request with an explicit Depth header.
// RFC 6352 §8.6 and §8.7 require Depth: 1 for addressbook-query and addressbook-multiget.
func (c *Client) ReportWithDepth(ctx context.Context, path, depth string, body []byte) (*Response, error) {
	h := http.Header{
		"Content-Type": {"application/xml; charset=utf-8"},
		"Depth":        {depth},
	}
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

// PutConditional sends a PUT request with Content-Type and additional conditional
// headers (e.g. If-Match, If-None-Match, If-Unmodified-Since). cond is merged
// with the Content-Type header; callers must not set Content-Type in cond.
func (c *Client) PutConditional(ctx context.Context, path, contentType string, cond http.Header, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {contentType}}
	for k, vv := range cond {
		h[k] = vv
	}
	return c.do(ctx, http.MethodPut, path, h, body)
}

// GetConditional sends a GET request with conditional headers
// (e.g. If-None-Match, If-Modified-Since).
func (c *Client) GetConditional(ctx context.Context, path string, cond http.Header) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, cond, nil)
}

// GetNoAuth sends a GET request without credentials.
// Use this to test that the server requires authentication (RFC 6352 §13 MUST).
func (c *Client) GetNoAuth(ctx context.Context, path string) (*Response, error) {
	return c.doNoAuth(ctx, http.MethodGet, path, nil, nil)
}

// PutNoAuth sends a PUT request without credentials.
// Use this to test that the server requires authentication (RFC 6352 §13 MUST).
func (c *Client) PutNoAuth(ctx context.Context, path, contentType string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {contentType}}
	return c.doNoAuth(ctx, http.MethodPut, path, h, body)
}

// ReportNoAuth sends a REPORT request without credentials.
// Use this to test that the server requires authentication (RFC 6352 §13 MUST).
func (c *Client) ReportNoAuth(ctx context.Context, path string, body []byte) (*Response, error) {
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	return c.doNoAuth(ctx, "REPORT", path, h, body)
}

// CopyNoOverwrite sends a COPY request without an Overwrite header.
// Per RFC 4918 §10.6, the default when the header is absent is "T".
func (c *Client) CopyNoOverwrite(ctx context.Context, src, dst string) (*Response, error) {
	h := http.Header{"Destination": {c.resolve(dst)}}
	return c.do(ctx, "COPY", src, h, nil)
}

// MoveNoOverwrite sends a MOVE request without an Overwrite header.
// Per RFC 4918 §10.6, the default when the header is absent is "T".
func (c *Client) MoveNoOverwrite(ctx context.Context, src, dst string) (*Response, error) {
	h := http.Header{"Destination": {c.resolve(dst)}}
	return c.do(ctx, "MOVE", src, h, nil)
}

// CopyNoDestination sends a COPY request without a Destination header.
// Per RFC 4918 §9.8, Destination is required; absence should result in 400.
func (c *Client) CopyNoDestination(ctx context.Context, src string) (*Response, error) {
	return c.do(ctx, "COPY", src, nil, nil)
}

// MoveNoDestination sends a MOVE request without a Destination header.
// Per RFC 4918 §9.9, Destination is required; absence should result in 400.
func (c *Client) MoveNoDestination(ctx context.Context, src string) (*Response, error) {
	return c.do(ctx, "MOVE", src, nil, nil)
}

// PropfindWithIf sends a PROPFIND request with an If state-token header.
// token is wrapped as required by RFC 4918 §10.4: If: (<token>).
// Use this to test that a server honours DAV:sync-token values as state tokens
// per RFC 6578 §5.
func (c *Client) PropfindWithIf(ctx context.Context, path, depth, token string, body []byte) (*Response, error) {
	h := http.Header{
		"Depth":        {depth},
		"Content-Type": {"application/xml; charset=utf-8"},
		"If":           {"(<" + token + ">)"},
	}
	return c.do(ctx, "PROPFIND", path, h, body)
}
