// Package rfc5689 registers conformance tests for RFC 5689 — Extended MKCOL for WebDAV.
//
// RFC 5689 extends the plain MKCOL method (RFC 4918 §9.3) to accept a request
// body that specifies the new collection's resource type and initial properties.
// It is the standard way to create typed collections (CalDAV calendars, CardDAV
// address books) without protocol-specific creation methods.
//
// Tests activate via --suite rfc5689 or automatically via --discover when the
// server advertises "extended-mkcol" in its DAV header.
package rfc5689

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	suite.Register(suite.Test{
		ID:          "rfc5689.options-advertises-extended-mkcol",
		Suite:       "rfc5689",
		Description: `OPTIONS response includes "extended-mkcol" in the DAV header`,
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3.1"}},
		Fn:          testOptionsAdvertisesExtendedMkcol,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-addressbook-creates",
		Suite:       "rfc5689",
		Description: "Extended MKCOL with DAV:collection + CARDDAV:addressbook returns 201 and collection reports both resource types",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3"}},
		Fn:          testMkcolAddressbookCreates,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-with-displayname",
		Suite:       "rfc5689",
		Description: "Extended MKCOL sets DAV:displayname in the same request; PROPFIND confirms the property was stored",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3"}},
		Fn:          testMkcolWithDisplayname,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-bad-content-type",
		Suite:       "rfc5689",
		Description: "Extended MKCOL with a body but wrong Content-Type (text/plain) is rejected with 4xx",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3"}},
		Fn:          testMkcolBadContentType,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-missing-collection-type",
		Suite:       "rfc5689",
		Description: "Extended MKCOL with a resource type that omits DAV:collection is rejected with 4xx",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3"}},
		Fn:          testMkcolMissingCollectionType,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-unsupported-resourcetype",
		Suite:       "rfc5689",
		Description: "Extended MKCOL requesting an unknown resource type returns 403 with DAV:valid-resourcetype precondition",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3.3"}},
		Fn:          testMkcolUnsupportedResourcetype,
	})
	suite.Register(suite.Test{
		ID:          "rfc5689.mkcol-property-failure-atomic",
		Suite:       "rfc5689",
		Description: "Extended MKCOL that fails to set a property rolls back the entire request atomically",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 5689", Section: "§3"}},
		Fn:          testMkcolPropertyFailureAtomic,
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

// makeAddressbookCollection creates a uniquely-named address book collection
// under homeSet via extended MKCOL and returns the collection URL and a cleanup
// func that deletes it (best-effort).
func makeAddressbookCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	body := client.MkcolExtended(
		[][2]string{{client.NSdav, "collection"}, {client.NScarddav, "addressbook"}},
		nil,
	)
	resp, err := c.Mkcol(ctx, colURL, body)
	if err != nil {
		return "", nil, fmt.Errorf("extended MKCOL %s: %w", colURL, err)
	}
	if resp.StatusCode != 201 {
		return "", nil, fmt.Errorf("extended MKCOL %s: got %d, want 201", colURL, resp.StatusCode)
	}
	cleanup := func(ctx context.Context) {
		_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
	}
	return colURL, cleanup, nil
}

// --- Tests ---

// testOptionsAdvertisesExtendedMkcol verifies RFC 5689 §3.1 (R-09): a server
// that supports extended MKCOL MUST include "extended-mkcol" as a field in the
// DAV response header of an OPTIONS request.
func testOptionsAdvertisesExtendedMkcol(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.Options(ctx, sess.ContextPath)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.HeaderContains(resp, "DAV", "extended-mkcol")
}

// testMkcolAddressbookCreates verifies RFC 5689 §3 (R-01, R-02, R-03, R-07)
// and §4 (R-12): an extended MKCOL with DAV:collection and CARDDAV:addressbook
// resource types MUST return 201 and the resulting collection MUST report both
// types in DAV:resourcetype.
func testMkcolAddressbookCreates(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeAddressbookCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	body := client.PropfindProps([][2]string{
		{client.NSdav, "resourcetype"},
	})
	resp, err := c.Propfind(ctx, colURL, "0", body)
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
	if err := assert.ResourceTypeContains(ms, colURL, client.NSdav, "collection"); err != nil {
		return err
	}
	return assert.ResourceTypeContains(ms, colURL, client.NScarddav, "addressbook")
}

// testMkcolWithDisplayname verifies RFC 5689 §3 (R-04, R-07): an extended MKCOL
// that includes a DAV:set instruction for DAV:displayname SHOULD store the
// property and return it on PROPFIND.
func testMkcolWithDisplayname(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	body := client.MkcolExtended(
		[][2]string{{client.NSdav, "collection"}, {client.NScarddav, "addressbook"}},
		[][3]string{{client.NSdav, "displayname", "davlint-test"}},
	)
	resp, err := c.Mkcol(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("extended MKCOL with displayname: got %d, want 201", resp.StatusCode)
	}
	sess.AddCleanup(func(ctx context.Context) {
		_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
	})

	pfBody := client.PropfindProps([][2]string{
		{client.NSdav, "displayname"},
	})
	pfResp, err := c.Propfind(ctx, colURL, "0", pfBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(pfResp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(pfResp.Body)
	if err != nil {
		return err
	}
	return assert.PropTextContains(ms, colURL, client.NSdav, "displayname", "davlint-test")
}

// testMkcolBadContentType verifies RFC 5689 §3 (R-01): when the MKCOL request
// includes a body, the Content-Type header MUST be set appropriately for the
// XML content. Sending a well-formed XML body with Content-Type: text/plain
// MUST be rejected with a 4xx error.
func testMkcolBadContentType(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	body := client.MkcolExtended(
		[][2]string{{client.NSdav, "collection"}, {client.NScarddav, "addressbook"}},
		nil,
	)
	resp, err := c.MkcolRaw(ctx, colURL, "text/plain", body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return nil
	}
	// Non-compliant server accepted the request — register cleanup and fail.
	if resp.StatusCode == 201 {
		sess.AddCleanup(func(ctx context.Context) {
			_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
		})
	}
	return fmt.Errorf("extended MKCOL with Content-Type: text/plain: got %d, want 4xx; server MUST reject incorrect Content-Type (RFC 5689 §3 R-01)", resp.StatusCode)
}

// testMkcolMissingCollectionType verifies RFC 5689 §3 (R-03): the DAV:resourcetype
// element MUST include DAV:collection. A body that specifies only CARDDAV:addressbook
// without DAV:collection MUST be rejected with a 4xx error.
func testMkcolMissingCollectionType(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	// Body has only CARDDAV:addressbook — no DAV:collection.
	body := client.MkcolExtended(
		[][2]string{{client.NScarddav, "addressbook"}},
		nil,
	)
	resp, err := c.Mkcol(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return nil
	}
	if resp.StatusCode == 201 {
		sess.AddCleanup(func(ctx context.Context) {
			_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
		})
	}
	return fmt.Errorf("extended MKCOL without DAV:collection in resourcetype: got %d, want 4xx; server MUST reject (RFC 5689 §3 R-03)", resp.StatusCode)
}

// testMkcolUnsupportedResourcetype verifies RFC 5689 §3.3 (R-10): when a client
// requests an unsupported resource type, the server MUST return 403 Forbidden
// with a DAV:valid-resourcetype precondition element in the response body.
func testMkcolUnsupportedResourcetype(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	// Request an unknown resource type alongside DAV:collection.
	body := client.MkcolExtended(
		[][2]string{{client.NSdav, "collection"}, {client.NSdav, "bogus-davlint-type"}},
		nil,
	)
	resp, err := c.Mkcol(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 {
		sess.AddCleanup(func(ctx context.Context) {
			_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
		})
		return fmt.Errorf("extended MKCOL with unknown resource type was accepted (got 201); server MUST return 403 with DAV:valid-resourcetype (RFC 5689 §3.3 R-10)")
	}
	if resp.StatusCode != 403 {
		return fmt.Errorf("extended MKCOL with unknown resource type: got %d, want 403 (RFC 5689 §3.3 R-10)", resp.StatusCode)
	}
	return assert.BodyContainsElement(resp.Body, client.NSdav, "valid-resourcetype")
}

// testMkcolPropertyFailureAtomic verifies RFC 5689 §3 (R-05, R-06): if any
// property instruction in an extended MKCOL fails, the entire request MUST fail
// atomically — the collection MUST NOT be created. This test uses DAV:getetag
// (a server-managed protected property) as the instruction expected to fail.
func testMkcolPropertyFailureAtomic(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL := fmt.Sprintf("%sdavlint-rfc5689-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
	// Attempt to set DAV:getetag, which is a server-managed protected property.
	body := client.MkcolExtended(
		[][2]string{{client.NSdav, "collection"}, {client.NScarddav, "addressbook"}},
		[][3]string{{client.NSdav, "getetag", "fake-etag"}},
	)
	resp, err := c.Mkcol(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 {
		// Server silently accepted the protected property (or ignored it) — no
		// atomicity claim to verify. Clean up and pass.
		sess.AddCleanup(func(ctx context.Context) {
			_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup
		})
		return nil
	}
	// Server rejected the request — verify the collection was NOT created.
	pfBody := client.PropfindProps([][2]string{{client.NSdav, "resourcetype"}})
	pfResp, err := c.Propfind(ctx, colURL, "0", pfBody)
	if err != nil {
		return err
	}
	if pfResp.StatusCode != 404 {
		return fmt.Errorf("extended MKCOL property failure: MKCOL returned %d but collection still exists (PROPFIND returned %d); atomicity violated (RFC 5689 §3 R-05, R-06)", resp.StatusCode, pfResp.StatusCode)
	}
	return nil
}
