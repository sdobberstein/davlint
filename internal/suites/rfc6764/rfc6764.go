// Package rfc6764 registers CardDAV service discovery conformance tests (RFC 6764).
//
// Discovery flow under test:
//  1. GET /.well-known/carddav (no auth) → 301/302/307/308 redirect to context path
//  2. OPTIONS {contextPath} → DAV compliance header: 1, 2, access-control, addressbook
//  3. PROPFIND {contextPath} (authenticated) → 207 with DAV:current-user-principal
//  4. PROPFIND {principalURL} → 207 with carddav:addressbook-home-set
//
// No URL structure is assumed beyond what the server itself advertises.
package rfc6764

import (
	"context"
	"fmt"
	"strings"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/suite"
)

func init() {
	suite.Register(suite.Test{
		ID:          "rfc6764.well-known-redirect",
		Suite:       "rfc6764",
		Description: "GET /.well-known/carddav returns 301/302/307/308 with a Location header",
		Severity:    suite.Must,
		Fn:          testWellKnownRedirect,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.dav-header",
		Suite:       "rfc6764",
		Description: "OPTIONS on the context path returns DAV compliance classes: 1, 2, access-control, addressbook",
		Severity:    suite.Must,
		Fn:          testDAVHeader,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.current-user-principal",
		Suite:       "rfc6764",
		Description: "PROPFIND on the context path returns DAV:current-user-principal for the authenticated user",
		Severity:    suite.Must,
		Fn:          testCurrentUserPrincipal,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.addressbook-home-set",
		Suite:       "rfc6764",
		Description: "PROPFIND on the principal URL returns carddav:addressbook-home-set",
		Severity:    suite.Must,
		Fn:          testAddressBookHomeSet,
	})
}

func testWellKnownRedirect(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.GetNoRedirect(ctx, "/.well-known/carddav")
	if err != nil {
		return err
	}
	if resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 && resp.StatusCode != 308 {
		return fmt.Errorf("well-known redirect: got status %d, want 301/302/307/308", resp.StatusCode)
	}
	if resp.Header.Get("Location") == "" {
		return fmt.Errorf("well-known redirect: missing Location header")
	}
	return nil
}

func testDAVHeader(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.Options(ctx, sess.ContextPath)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	dav := resp.Header.Get("DAV")
	for _, token := range []string{"1", "2", "access-control", "addressbook"} {
		if !strings.Contains(dav, token) {
			return fmt.Errorf("DAV header %q missing required token %q", dav, token)
		}
	}
	return nil
}

func testCurrentUserPrincipal(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	body := client.PropfindProps([][2]string{
		{client.NSdav, "current-user-principal"},
	})
	resp, err := c.Propfind(ctx, sess.ContextPath, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	// Verify the href contains the authenticated username — the only safe
	// assumption without imposing a specific URL structure.
	return assert.PropHrefContains(ms, sess.ContextPath, client.NSdav, "current-user-principal", c.Username())
}

func testAddressBookHomeSet(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()

	// Step 1: discover the principal URL from the context path.
	principalURL, err := currentUserPrincipalURL(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}

	// Step 2: PROPFIND the principal URL for the addressbook-home-set.
	body := client.PropfindProps([][2]string{
		{"urn:ietf:params:xml:ns:carddav", "addressbook-home-set"},
	})
	resp, err := c.Propfind(ctx, principalURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	return assert.PropHrefContains(ms, principalURL, "urn:ietf:params:xml:ns:carddav", "addressbook-home-set", c.Username())
}

// currentUserPrincipalURL issues a depth-0 PROPFIND on contextPath and returns
// the DAV:href value of the DAV:current-user-principal property.
func currentUserPrincipalURL(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	body := client.PropfindProps([][2]string{
		{client.NSdav, "current-user-principal"},
	})
	resp, err := c.Propfind(ctx, contextPath, "0", body)
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	href, err := assert.PropHrefValue(ms, contextPath, client.NSdav, "current-user-principal")
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	return href, nil
}
