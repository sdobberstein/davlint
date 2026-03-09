// Package rfc4918 registers WebDAV core conformance tests (RFC 4918).
//
// Tests cover the HTTP methods required for a CardDAV server: OPTIONS, MKCOL,
// PUT, GET, DELETE, PROPFIND (depths 0, 1, and infinity-rejection), PROPPATCH,
// COPY, and MOVE. All resource URLs are discovered dynamically — no server-
// specific paths are assumed.
//
// Each test that creates server state registers a cleanup via sess.AddCleanup
// so the server is left in a clean state regardless of test outcome.
package rfc4918

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	suite.Register(suite.Test{
		ID:          "rfc4918.options",
		Suite:       "rfc4918",
		Description: "OPTIONS on a WebDAV collection returns DAV header and all required methods in Allow",
		Severity:    suite.Must,
		Fn:          testOptions,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.mkcol",
		Suite:       "rfc4918",
		Description: "MKCOL on an unmapped URL creates a collection and returns 201",
		Severity:    suite.Must,
		Fn:          testMkcol,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.mkcol-duplicate",
		Suite:       "rfc4918",
		Description: "MKCOL on an already-mapped URL returns 405 or 409",
		Severity:    suite.Must,
		Fn:          testMkcolDuplicate,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.put-contact",
		Suite:       "rfc4918",
		Description: "PUT a vCard to a new URL returns 201 Created",
		Severity:    suite.Must,
		Fn:          testPutContact,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.get-contact",
		Suite:       "rfc4918",
		Description: "GET on a vCard resource returns 200 with Content-Type text/vcard",
		Severity:    suite.Must,
		Fn:          testGetContact,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.etag-on-get",
		Suite:       "rfc4918",
		Description: "GET on a vCard resource returns a non-empty ETag header",
		Severity:    suite.Must,
		Fn:          testETagOnGet,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.propfind-depth0",
		Suite:       "rfc4918",
		Description: "PROPFIND depth 0 on a vCard resource returns 207 with getetag, getcontenttype, getcontentlength",
		Severity:    suite.Must,
		Fn:          testPropfindDepth0,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.propfind-depth1",
		Suite:       "rfc4918",
		Description: "PROPFIND depth 1 on a collection returns 207 including child resources",
		Severity:    suite.Must,
		Fn:          testPropfindDepth1,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.propfind-allprop",
		Suite:       "rfc4918",
		Description: "PROPFIND allprop on a vCard resource returns 207 with standard live properties",
		Severity:    suite.Must,
		Fn:          testPropfindAllprop,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.propfind-depth-infinity-forbidden",
		Suite:       "rfc4918",
		Description: "PROPFIND with Depth: infinity on a collection returns 403",
		Severity:    suite.Must,
		Fn:          testPropfindInfinityForbidden,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.proppatch-set",
		Suite:       "rfc4918",
		Description: "PROPPATCH set stores a dead property; subsequent PROPFIND returns it in a 200 propstat",
		Severity:    suite.Must,
		Fn:          testProppatchSet,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.delete",
		Suite:       "rfc4918",
		Description: "DELETE with a matching If-Match ETag returns 204; subsequent GET returns 404",
		Severity:    suite.Must,
		Fn:          testDelete,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.delete-etag-mismatch",
		Suite:       "rfc4918",
		Description: "DELETE with a mismatched If-Match ETag returns 412 Precondition Failed",
		Severity:    suite.Must,
		Fn:          testDeleteETagMismatch,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.copy",
		Suite:       "rfc4918",
		Description: "COPY creates a new resource at the destination; source still exists",
		Severity:    suite.Must,
		Fn:          testCopy,
	})
	suite.Register(suite.Test{
		ID:          "rfc4918.move",
		Suite:       "rfc4918",
		Description: "MOVE relocates a resource; source returns 404, destination returns 200",
		Severity:    suite.Must,
		Fn:          testMove,
	})
}

// discoverHomeSet returns the addressbook-home-set URL for the primary client,
// following the RFC 6764 → RFC 6352 discovery chain.
func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

// makeTestCollection creates a uniquely-named collection under homeSet and
// returns the collection URL and a cleanup func that deletes it.
func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here; named returns would conflict with := assignments
	colURL := fmt.Sprintf("%sdavlint-rfc4918-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	resp, err := c.Mkcol(ctx, colURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("MKCOL %s: %w", colURL, err)
	}
	if resp.StatusCode != 201 {
		return "", nil, fmt.Errorf("MKCOL %s: got %d, want 201", colURL, resp.StatusCode)
	}
	cleanup := func(ctx context.Context) {
		_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
	}
	return colURL, cleanup, nil
}

// putTestContact PUTs fixtures.AliceV4 to colURL+"test.vcf" and returns the contact URL.
func putTestContact(ctx context.Context, c *client.Client, colURL string) (string, error) {
	contactURL := colURL + "test.vcf"
	resp, err := c.Put(ctx, contactURL, "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return "", fmt.Errorf("PUT %s: %w", contactURL, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return "", fmt.Errorf("PUT %s: got %d, want 201 or 204", contactURL, resp.StatusCode)
	}
	return contactURL, nil
}

// proppatchSetXML returns a PROPPATCH body that sets a single property.
func proppatchSetXML(ns, local, value string) []byte {
	return []byte(fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>`+
			`<D:propertyupdate xmlns:D="DAV:" xmlns:X=%q>`+
			`<D:set><D:prop><X:%s>%s</X:%s></D:prop></D:set>`+
			`</D:propertyupdate>`,
		ns, local, value, local,
	))
}

// --- Test functions ---

func testOptions(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	resp, err := c.Options(ctx, colURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// DAV compliance header must be present.
	for _, token := range []string{"1", "2", "access-control", "addressbook"} {
		if err := assert.HeaderContains(resp, "DAV", token); err != nil {
			return err
		}
	}
	// Allow header must list the core WebDAV methods.
	allow := resp.Header.Get("Allow")
	for _, method := range []string{"OPTIONS", "GET", "PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"} {
		if !strings.Contains(allow, method) {
			return fmt.Errorf("allow header %q missing required method %q", allow, method)
		}
	}
	return nil
}

func testMkcol(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)
	_ = colURL
	return nil
}

func testMkcolDuplicate(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	resp, err := c.Mkcol(ctx, colURL, nil)
	if err != nil {
		return err
	}
	// RFC 4918 §9.3.1: "405 (Method Not Allowed) - MKCOL can only be executed
	// on an unmapped URL." Some servers return 409 instead.
	if resp.StatusCode != 405 && resp.StatusCode != 409 {
		return fmt.Errorf("duplicate MKCOL: got %d, want 405 or 409", resp.StatusCode)
	}
	return nil
}

func testPutContact(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	resp, err := c.Put(ctx, colURL+"test.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT new resource: got %d, want 201", resp.StatusCode)
	}
	return nil
}

func testGetContact(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.HeaderContains(resp, "Content-Type", "text/vcard")
}

func testETagOnGet(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.HeaderPresent(resp, "ETag")
}

func testPropfindDepth0(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	body := client.PropfindProps([][2]string{
		{client.NSdav, "getetag"},
		{client.NSdav, "getcontenttype"},
		{client.NSdav, "getcontentlength"},
		{client.NSdav, "resourcetype"},
	})
	resp, err := c.Propfind(ctx, contactURL, "0", body)
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
	for _, prop := range []string{"getetag", "getcontenttype", "getcontentlength"} {
		if err := assert.PropExists(ms, contactURL, client.NSdav, prop); err != nil {
			return err
		}
	}
	return nil
}

func testPropfindDepth1(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	if _, err := putTestContact(ctx, c, colURL); err != nil {
		return err
	}

	resp, err := c.Propfind(ctx, colURL, "1", client.PropfindAllprop())
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
	// Must include the collection itself plus at least one child.
	if len(ms.Responses) < 2 {
		return fmt.Errorf("PROPFIND depth 1: got %d responses, want at least 2 (collection + child)", len(ms.Responses))
	}
	return nil
}

func testPropfindAllprop(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	resp, err := c.Propfind(ctx, contactURL, "0", client.PropfindAllprop())
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
	for _, prop := range []string{"getetag", "getcontenttype", "getcontentlength", "getlastmodified"} {
		if err := assert.PropExists(ms, contactURL, client.NSdav, prop); err != nil {
			return err
		}
	}
	return nil
}

func testPropfindInfinityForbidden(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	resp, err := c.Propfind(ctx, colURL, "infinity", client.PropfindAllprop())
	if err != nil {
		return err
	}
	// RFC 4918 §9.1: "A server MUST return a 403 (Forbidden) status code
	// if a Depth: infinity request is not supported."
	return assert.StatusCode(resp, 403)
}

func testProppatchSet(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	const (
		deadNS    = "http://davlint.invalid/ns/"
		deadLocal = "test-prop"
		deadValue = "davlint-test-value"
	)

	patchBody := proppatchSetXML(deadNS, deadLocal, deadValue)
	resp, err := c.Proppatch(ctx, contactURL, patchBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return fmt.Errorf("PROPPATCH: %w", err)
	}

	// Now verify the property is returned by PROPFIND.
	pfBody := client.PropfindProps([][2]string{{deadNS, deadLocal}})
	resp, err = c.Propfind(ctx, contactURL, "0", pfBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return fmt.Errorf("PROPFIND after PROPPATCH: %w", err)
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	return assert.PropExists(ms, contactURL, deadNS, deadLocal)
}

func testDelete(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	// GET to retrieve the current ETag.
	getResp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(getResp, 200); err != nil {
		return err
	}
	etag := getResp.Header.Get("ETag")
	if etag == "" {
		return fmt.Errorf("GET did not return an ETag header")
	}

	// DELETE with matching If-Match.
	delResp, err := c.Delete(ctx, contactURL, etag)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(delResp, 204); err != nil {
		return err
	}

	// Subsequent GET must return 404.
	getResp2, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	return assert.StatusCode(getResp2, 404)
}

func testDeleteETagMismatch(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	contactURL, err := putTestContact(ctx, c, colURL)
	if err != nil {
		return err
	}

	// DELETE with a deliberately wrong ETag.
	resp, err := c.Delete(ctx, contactURL, `"davlint-stale-etag"`)
	if err != nil {
		return err
	}
	// RFC 4918 §10.4.2: If-Match failure → 412 Precondition Failed.
	return assert.StatusCode(resp, 412)
}

func testCopy(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	srcURL := colURL + "copy-src.vcf"
	dstURL := colURL + "copy-dst.vcf"

	putResp, err := c.Put(ctx, srcURL, "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT src: got %d, want 201 or 204", putResp.StatusCode)
	}

	copyResp, err := c.Copy(ctx, srcURL, dstURL, false)
	if err != nil {
		return err
	}
	// RFC 4918 §9.8: 201 Created when destination did not exist.
	if copyResp.StatusCode != 201 {
		return fmt.Errorf("COPY: got %d, want 201", copyResp.StatusCode)
	}

	// Both source and destination must now exist.
	srcGet, err := c.Get(ctx, srcURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(srcGet, 200); err != nil {
		return fmt.Errorf("GET src after COPY: %w", err)
	}
	dstGet, err := c.Get(ctx, dstURL)
	if err != nil {
		return err
	}
	return assert.StatusCode(dstGet, 200)
}

func testMove(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	srcURL := colURL + "move-src.vcf"
	dstURL := colURL + "move-dst.vcf"

	putResp, err := c.Put(ctx, srcURL, "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT src: got %d, want 201 or 204", putResp.StatusCode)
	}

	moveResp, err := c.Move(ctx, srcURL, dstURL, false)
	if err != nil {
		return err
	}
	// RFC 4918 §9.9: 201 Created when destination did not exist.
	if moveResp.StatusCode != 201 {
		return fmt.Errorf("MOVE: got %d, want 201", moveResp.StatusCode)
	}

	// Source must be gone.
	srcGet, err := c.Get(ctx, srcURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(srcGet, 404); err != nil {
		return fmt.Errorf("GET src after MOVE: %w", err)
	}

	// Destination must exist.
	dstGet, err := c.Get(ctx, dstURL)
	if err != nil {
		return err
	}
	return assert.StatusCode(dstGet, 200)
}
