// Package rfc6764 registers CardDAV service discovery conformance tests (RFC 6764).
//
// Discovery flow under test:
//  1. GET /.well-known/carddav (no auth) → 301/303/307 redirect to context path
//  2. OPTIONS {contextPath} → DAV compliance header: 1, 2, access-control
//  3. PROPFIND {contextPath} (authenticated) → 207 with DAV:current-user-principal
//  4. PROPFIND {contextPath} (unauthenticated) → 401
//  5. PROPFIND {principalURL} → 207 with carddav:addressbook-home-set
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
	"github.com/sdobberstein/davlint/pkg/webdav"
)

// wellKnownRedirectCodes are the redirect status codes explicitly listed in RFC 6764 §5.
var wellKnownRedirectCodes = map[int]bool{301: true, 303: true, 307: true}

func init() {
	suite.Register(suite.Test{
		ID:          "rfc6764.well-known-redirect",
		Suite:       "rfc6764",
		Description: "GET /.well-known/carddav returns 301/303/307 with a Location header (RFC 6764 §5 MUST)",
		Severity:    suite.Must,
		Fn:          testWellKnownRedirect,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.well-known-no-direct-serve",
		Suite:       "rfc6764",
		Description: "GET /.well-known/carddav MUST NOT return 2xx; server must redirect, not serve (RFC 6764 §5 MUST NOT)",
		Severity:    suite.Must,
		Fn:          testWellKnownNoDirectServe,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.well-known-cache-control",
		Suite:       "rfc6764",
		Description: "Redirect from /.well-known/carddav SHOULD include a Cache-Control header (RFC 6764 §5 SHOULD)",
		Severity:    suite.Should,
		Fn:          testWellKnownCacheControl,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.well-known-auth-redirect",
		Suite:       "rfc6764",
		Description: "If server requires auth on /.well-known/carddav (401), authenticated request still redirects (RFC 6764 §5 MAY)",
		Severity:    suite.May,
		Fn:          testWellKnownAuthRedirect,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.dav-header",
		Suite:       "rfc6764",
		Description: "OPTIONS on the context path returns DAV compliance classes: 1, 2, access-control (RFC 4918)",
		Severity:    suite.Must,
		Fn:          testDAVHeader,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.current-user-principal",
		Suite:       "rfc6764",
		Description: "Authenticated PROPFIND on the context path returns DAV:current-user-principal (RFC 6764 §6)",
		Severity:    suite.Must,
		Fn:          testCurrentUserPrincipal,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.current-user-principal-requires-auth",
		Suite:       "rfc6764",
		Description: "Unauthenticated PROPFIND for DAV:current-user-principal MUST return 401 (RFC 6764 §7 MUST)",
		Severity:    suite.Must,
		Fn:          testCurrentUserPrincipalRequiresAuth,
	})
	suite.Register(suite.Test{
		ID:          "rfc6764.addressbook-home-set",
		Suite:       "rfc6764",
		Description: "PROPFIND on the principal URL returns carddav:addressbook-home-set (RFC 6764 §6)",
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
	if !wellKnownRedirectCodes[resp.StatusCode] {
		return fmt.Errorf("well-known redirect: got status %d, want 301/303/307", resp.StatusCode)
	}
	if resp.Header.Get("Location") == "" {
		return fmt.Errorf("well-known redirect: missing Location header")
	}
	return nil
}

func testWellKnownNoDirectServe(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.GetNoRedirect(ctx, "/.well-known/carddav")
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Errorf("well-known: server returned %d; MUST NOT serve actual service at /.well-known/carddav — must redirect (RFC 6764 §5)", resp.StatusCode)
	}
	return nil
}

func testWellKnownCacheControl(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.GetNoRedirect(ctx, "/.well-known/carddav")
	if err != nil {
		return err
	}
	return assert.HeaderPresent(resp, "Cache-Control")
}

// testWellKnownAuthRedirect covers the RFC 6764 §5 MAY case: a server MAY require
// authentication before issuing the redirect. If it does (401), an authenticated
// request must still produce a valid redirect.
func testWellKnownAuthRedirect(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	unauthResp, err := c.GetNoRedirectNoAuth(ctx, "/.well-known/carddav")
	if err != nil {
		return err
	}
	// Server redirects without auth — MAY condition not exercised, pass.
	if wellKnownRedirectCodes[unauthResp.StatusCode] {
		return nil
	}
	if unauthResp.StatusCode != 401 {
		return fmt.Errorf("well-known auth-redirect: unexpected status %d (want redirect or 401)", unauthResp.StatusCode)
	}
	// Server requires auth; authenticated request must redirect.
	authResp, err := c.GetNoRedirect(ctx, "/.well-known/carddav")
	if err != nil {
		return err
	}
	if !wellKnownRedirectCodes[authResp.StatusCode] {
		return fmt.Errorf("well-known auth-redirect: authenticated request returned %d, want 301/303/307", authResp.StatusCode)
	}
	if authResp.Header.Get("Location") == "" {
		return fmt.Errorf("well-known auth-redirect: authenticated redirect missing Location header")
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
	for _, token := range []string{"1", "2", "access-control"} {
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
	return assert.PropExists(ms, sess.ContextPath, client.NSdav, "current-user-principal")
}

func testCurrentUserPrincipalRequiresAuth(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	body := client.PropfindProps([][2]string{
		{client.NSdav, "current-user-principal"},
	})
	resp, err := c.PropfindNoAuth(ctx, sess.ContextPath, "0", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 401 {
		return fmt.Errorf("unauthenticated PROPFIND for current-user-principal: got status %d, want 401 (RFC 6764 §7 MUST)", resp.StatusCode)
	}
	return nil
}

func testAddressBookHomeSet(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()

	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}

	body := client.PropfindProps([][2]string{
		{client.NScarddav, "addressbook-home-set"},
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
	return assert.PropExists(ms, principalURL, client.NScarddav, "addressbook-home-set")
}
