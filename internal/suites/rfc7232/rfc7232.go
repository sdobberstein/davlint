// Package rfc7232 registers conformance tests for RFC 7232 — HTTP/1.1: Conditional Requests.
//
// RFC 7232 defines the conditional request headers (If-Match, If-None-Match,
// If-Modified-Since, If-Unmodified-Since) and validator semantics (ETags,
// Last-Modified). In CardDAV/CalDAV, these are critical for safe concurrent
// writes: RFC 6352 §5.3.4 and RFC 4791 §5.3.4 both require servers to honour
// If-None-Match: * on resource creation and If-Match: <etag> on updates to
// prevent lost edits.
//
// Tests activate via --suite rfc7232 or implicitly via the webdav, carddav,
// or caldav protocol bundles. There is no DAV token for conditional request
// support, so --discover does not auto-activate this suite.
package rfc7232

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

// httpDatePast is an HTTP-date guaranteed to be before any test resource was created.
const httpDatePast = "Thu, 01 Jan 1970 00:00:00 GMT"

// httpDateFuture is an HTTP-date guaranteed to be after any test resource was created.
const httpDateFuture = "Mon, 01 Jan 2100 00:00:00 GMT"

// aliceModifiedV4 is AliceV4 with a different FN, same UID — used to force a
// content change without triggering UID-conflict errors on the same URL.
const aliceModifiedV4 = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:aaaaaaaa-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Modified\r\n" +
	"N:Modified;Alice;;;\r\n" +
	"END:VCARD\r\n"

func init() {
	suite.Register(suite.Test{
		ID:          "rfc7232.etag-is-strong",
		Suite:       "rfc7232",
		Description: "GET on a vCard resource returns an ETag header without the W/ weak prefix",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§2.1"}, {RFC: "RFC 6352", Section: "§5.3.4"}},
		MinPrincipals: 1,
		Fn:          testETagIsStrong,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.last-modified-present",
		Suite:       "rfc7232",
		Description: "GET on a vCard resource returns a Last-Modified header",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§2.2.1"}},
		MinPrincipals: 1,
		Fn:          testLastModifiedPresent,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.etag-on-put-response",
		Suite:       "rfc7232",
		Description: "PUT of a vCard returns an ETag in the response",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§2.4"}},
		MinPrincipals: 1,
		Fn:          testETagOnPutResponse,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.etag-changes-after-put",
		Suite:       "rfc7232",
		Description: "ETag on a resource changes after a successful PUT update",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§2.3.1"}},
		MinPrincipals: 1,
		Fn:          testETagChangesAfterPut,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-match-matching-etag-succeeds",
		Suite:       "rfc7232",
		Description: "PUT with If-Match: <current-etag> returns 2xx and updates the resource",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.1"}},
		MinPrincipals: 1,
		Fn:          testIfMatchMatchingETagSucceeds,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-match-stale-etag-412",
		Suite:       "rfc7232",
		Description: "PUT with If-Match: <stale-etag> returns 412 Precondition Failed",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.1"}},
		MinPrincipals: 1,
		Fn:          testIfMatchStaleETag412,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-match-wildcard-existing-succeeds",
		Suite:       "rfc7232",
		Description: "PUT with If-Match: * on an existing resource returns 2xx",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.1"}},
		MinPrincipals: 1,
		Fn:          testIfMatchWildcardExistingSucceeds,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-match-wildcard-missing-412",
		Suite:       "rfc7232",
		Description: "PUT with If-Match: * on a non-existent resource returns 412",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.1"}},
		MinPrincipals: 1,
		Fn:          testIfMatchWildcardMissing412,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-none-match-wildcard-new-resource-201",
		Suite:       "rfc7232",
		Description: "PUT with If-None-Match: * on a new URL returns 201 Created",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.2"}, {RFC: "RFC 6352", Section: "§5.3.4"}},
		MinPrincipals: 1,
		Fn:          testIfNoneMatchWildcardNewResource201,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-none-match-wildcard-existing-412",
		Suite:       "rfc7232",
		Description: "PUT with If-None-Match: * on an existing resource returns 412",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.2"}, {RFC: "RFC 6352", Section: "§5.3.4"}},
		MinPrincipals: 1,
		Fn:          testIfNoneMatchWildcardExisting412,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-none-match-get-cached-304",
		Suite:       "rfc7232",
		Description: "GET with If-None-Match: <current-etag> returns 304 Not Modified with no body",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.2"}},
		MinPrincipals: 1,
		Fn:          testIfNoneMatchGetCached304,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-none-match-get-stale-200",
		Suite:       "rfc7232",
		Description: "GET with If-None-Match: <stale-etag> returns 200 with body",
		Severity:    suite.Must,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.2"}},
		MinPrincipals: 1,
		Fn:          testIfNoneMatchGetStale200,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-modified-since-not-modified-304",
		Suite:       "rfc7232",
		Description: "GET with If-Modified-Since: <future-date> returns 304 when resource is unchanged",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.3"}},
		MinPrincipals: 1,
		Fn:          testIfModifiedSinceNotModified304,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-modified-since-modified-200",
		Suite:       "rfc7232",
		Description: "GET with If-Modified-Since: <past-date> returns 200 (resource was created after that date)",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.3"}},
		MinPrincipals: 1,
		Fn:          testIfModifiedSinceModified200,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-unmodified-since-not-modified-succeeds",
		Suite:       "rfc7232",
		Description: "PUT with If-Unmodified-Since: <future-date> returns 2xx (resource not modified since then)",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.4"}},
		MinPrincipals: 1,
		Fn:          testIfUnmodifiedSinceNotModifiedSucceeds,
	})
	suite.Register(suite.Test{
		ID:          "rfc7232.if-unmodified-since-modified-412",
		Suite:       "rfc7232",
		Description: "PUT with If-Unmodified-Since: <past-date> returns 412 (resource was modified after that date)",
		Severity:    suite.Should,
		References:  []suite.RFCRef{{RFC: "RFC 7232", Section: "§3.4"}},
		MinPrincipals: 1,
		Fn:          testIfUnmodifiedSinceModified412,
	})
}

// discoverHomeSet returns the addressbook-home-set URL for the primary client.
func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

// makeTestCollection creates a uniquely-named plain collection under homeSet
// and returns the collection URL and a cleanup func.
func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here
	colURL := fmt.Sprintf("%sdavlint-rfc7232-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

// getETag fetches the current ETag for contactURL via GET.
func getETag(ctx context.Context, c *client.Client, contactURL string) (string, error) {
	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET %s: got %d, want 200", contactURL, resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", fmt.Errorf("GET %s: missing ETag header", contactURL)
	}
	return etag, nil
}

// --- Tests ---

// testETagIsStrong verifies RFC 7232 §2.1 (R-01) and RFC 6352 §5.3.4: the ETag
// returned on GET must be a strong validator — it must not carry the W/ prefix.
func testETagIsStrong(ctx context.Context, sess *suite.Session) error {
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
	if err := assert.HeaderPresent(resp, "ETag"); err != nil {
		return err
	}
	etag := resp.Header.Get("ETag")
	if len(etag) >= 2 && etag[:2] == "W/" {
		return fmt.Errorf("ETag %q is weak (W/ prefix); server MUST return strong ETags for address object resources (RFC 7232 §2.1, RFC 6352 §5.3.4)", etag)
	}
	return nil
}

// testLastModifiedPresent verifies RFC 7232 §2.2.1 (R-03, R-09): GET on a resource
// should return a Last-Modified header.
func testLastModifiedPresent(ctx context.Context, sess *suite.Session) error {
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
	return assert.HeaderPresent(resp, "Last-Modified")
}

// testETagOnPutResponse verifies RFC 7232 §2.4 (R-10): a PUT that creates or
// modifies a resource should include an ETag in the response.
func testETagOnPutResponse(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "test.vcf"
	resp, err := c.Put(ctx, contactURL, "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT %s: got %d, want 201 or 204", contactURL, resp.StatusCode)
	}
	return assert.HeaderPresent(resp, "ETag")
}

// testETagChangesAfterPut verifies RFC 7232 §2.3.1 (R-06, R-08): after a PUT
// update, the ETag must be different from the one before the update.
func testETagChangesAfterPut(ctx context.Context, sess *suite.Session) error {
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

	etag1, err := getETag(ctx, c, contactURL)
	if err != nil {
		return err
	}

	// Overwrite with different content (same UID, different FN).
	resp, err := c.Put(ctx, contactURL, "text/vcard; charset=utf-8", []byte(aliceModifiedV4))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT update %s: got %d, want 200/201/204", contactURL, resp.StatusCode)
	}

	etag2, err := getETag(ctx, c, contactURL)
	if err != nil {
		return err
	}

	if etag1 == etag2 {
		return fmt.Errorf("ETag did not change after PUT update: before=%q after=%q; server MUST change ETag when content changes (RFC 7232 §2.3.1)", etag1, etag2)
	}
	return nil
}

// testIfMatchMatchingETagSucceeds verifies RFC 7232 §3.1 (R-11, R-12): a PUT
// with If-Match: <current-etag> must succeed (2xx).
func testIfMatchMatchingETagSucceeds(ctx context.Context, sess *suite.Session) error {
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
	etag, err := getETag(ctx, c, contactURL)
	if err != nil {
		return err
	}

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-Match": {etag}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("PUT with If-Match: %s: got %d, want 2xx; server MUST allow write when ETag matches (RFC 7232 §3.1 R-11, R-12)", etag, resp.StatusCode)
	}
	return nil
}

// testIfMatchStaleETag412 verifies RFC 7232 §3.1 (R-12, R-13): a PUT with a
// stale (non-matching) If-Match value must return 412.
func testIfMatchStaleETag412(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-Match": {`"davlint-stale-etag"`}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != 412 {
		return fmt.Errorf("PUT with stale If-Match: got %d, want 412; server MUST return 412 when ETag does not match (RFC 7232 §3.1 R-12, R-13)", resp.StatusCode)
	}
	return nil
}

// testIfMatchWildcardExistingSucceeds verifies RFC 7232 §3.1 (R-14): PUT with
// If-Match: * on an existing resource must succeed.
func testIfMatchWildcardExistingSucceeds(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-Match": {"*"}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("PUT with If-Match: * on existing resource: got %d, want 2xx; server MUST allow write when resource exists (RFC 7232 §3.1 R-14)", resp.StatusCode)
	}
	return nil
}

// testIfMatchWildcardMissing412 verifies RFC 7232 §3.1 (R-14): PUT with
// If-Match: * on a resource that does not exist must return 412.
func testIfMatchWildcardMissing412(ctx context.Context, sess *suite.Session) error {
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

	// Use a URL that has never been created.
	freshURL := fmt.Sprintf("%sdavlint-absent-%08x.vcf", colURL, rand.Uint32()) // #nosec G404
	resp, err := c.PutConditional(ctx, freshURL, "text/vcard; charset=utf-8",
		http.Header{"If-Match": {"*"}},
		[]byte(fixtures.AliceV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != 412 {
		return fmt.Errorf("PUT with If-Match: * on absent URL: got %d, want 412; server MUST return 412 when resource does not exist (RFC 7232 §3.1 R-14)", resp.StatusCode)
	}
	return nil
}

// testIfNoneMatchWildcardNewResource201 verifies RFC 7232 §3.2 (R-16, R-19)
// and RFC 6352 §5.3.4: PUT with If-None-Match: * on a new URL returns 201.
func testIfNoneMatchWildcardNewResource201(ctx context.Context, sess *suite.Session) error {
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

	freshURL := fmt.Sprintf("%sdavlint-new-%08x.vcf", colURL, rand.Uint32()) // #nosec G404
	resp, err := c.PutConditional(ctx, freshURL, "text/vcard; charset=utf-8",
		http.Header{"If-None-Match": {"*"}},
		[]byte(fixtures.AliceV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT with If-None-Match: * on new URL: got %d, want 201; server MUST create resource when it does not exist (RFC 7232 §3.2 R-16, R-19)", resp.StatusCode)
	}
	return nil
}

// testIfNoneMatchWildcardExisting412 verifies RFC 7232 §3.2 (R-18, R-19)
// and RFC 6352 §5.3.4: PUT with If-None-Match: * on an existing resource returns 412.
func testIfNoneMatchWildcardExisting412(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-None-Match": {"*"}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != 412 {
		return fmt.Errorf("PUT with If-None-Match: * on existing resource: got %d, want 412; server MUST return 412 when resource already exists (RFC 7232 §3.2 R-18, R-19)", resp.StatusCode)
	}
	return nil
}

// testIfNoneMatchGetCached304 verifies RFC 7232 §3.2 (R-15, R-16, R-17): GET
// with If-None-Match: <current-etag> returns 304 with no body.
func testIfNoneMatchGetCached304(ctx context.Context, sess *suite.Session) error {
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
	etag, err := getETag(ctx, c, contactURL)
	if err != nil {
		return err
	}

	resp, err := c.GetConditional(ctx, contactURL, http.Header{"If-None-Match": {etag}})
	if err != nil {
		return err
	}
	if resp.StatusCode != 304 {
		return fmt.Errorf("GET with If-None-Match: %s: got %d, want 304; server MUST return 304 when ETag matches (RFC 7232 §3.2 R-15, R-16, R-17)", etag, resp.StatusCode)
	}
	if len(resp.Body) != 0 {
		return fmt.Errorf("GET returned 304 but body is non-empty (%d bytes); 304 MUST have no message body (RFC 7232 §4.1)", len(resp.Body))
	}
	return nil
}

// testIfNoneMatchGetStale200 verifies RFC 7232 §3.2 (R-15, R-16): GET with a
// stale (non-matching) If-None-Match returns 200 with the resource body.
func testIfNoneMatchGetStale200(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.GetConditional(ctx, contactURL, http.Header{"If-None-Match": {`"davlint-stale-etag"`}})
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return fmt.Errorf("GET with stale If-None-Match: %w; server MUST return 200 when ETag does not match (RFC 7232 §3.2 R-15, R-16)", err)
	}
	if len(resp.Body) == 0 {
		return fmt.Errorf("GET with stale If-None-Match returned 200 but body is empty; expected resource body")
	}
	return nil
}

// testIfModifiedSinceNotModified304 verifies RFC 7232 §3.3 (R-23): GET with
// If-Modified-Since: <future-date> should return 304 when resource is unchanged.
func testIfModifiedSinceNotModified304(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.GetConditional(ctx, contactURL, http.Header{"If-Modified-Since": {httpDateFuture}})
	if err != nil {
		return err
	}
	if resp.StatusCode != 304 {
		return fmt.Errorf("GET with If-Modified-Since: %s: got %d, want 304; server SHOULD return 304 when resource has not been modified since the given date (RFC 7232 §3.3 R-23)", httpDateFuture, resp.StatusCode)
	}
	return nil
}

// testIfModifiedSinceModified200 verifies RFC 7232 §3.3 (R-23): GET with
// If-Modified-Since: <past-date> returns 200 because the resource was created
// (modified) after that date.
func testIfModifiedSinceModified200(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.GetConditional(ctx, contactURL, http.Header{"If-Modified-Since": {httpDatePast}})
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return fmt.Errorf("GET with If-Modified-Since: %s: %w; server SHOULD return 200 when resource was modified after the given date (RFC 7232 §3.3 R-23)", httpDatePast, err)
	}
	return nil
}

// testIfUnmodifiedSinceNotModifiedSucceeds verifies RFC 7232 §3.4 (R-26): PUT
// with If-Unmodified-Since: <future-date> must succeed because the resource has
// not been modified since 2100.
func testIfUnmodifiedSinceNotModifiedSucceeds(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-Unmodified-Since": {httpDateFuture}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("PUT with If-Unmodified-Since: %s: got %d, want 2xx; server MUST allow write when resource has not been modified since the given date (RFC 7232 §3.4 R-26)", httpDateFuture, resp.StatusCode)
	}
	return nil
}

// testIfUnmodifiedSinceModified412 verifies RFC 7232 §3.4 (R-26, R-27): PUT
// with If-Unmodified-Since: <past-date> must return 412 because the resource
// was created (modified) after 1970.
func testIfUnmodifiedSinceModified412(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutConditional(ctx, contactURL, "text/vcard; charset=utf-8",
		http.Header{"If-Unmodified-Since": {httpDatePast}},
		[]byte(aliceModifiedV4),
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != 412 {
		return fmt.Errorf("PUT with If-Unmodified-Since: %s: got %d, want 412; server MUST return 412 when resource was modified after the given date (RFC 7232 §3.4 R-26, R-27)", httpDatePast, resp.StatusCode)
	}
	return nil
}
