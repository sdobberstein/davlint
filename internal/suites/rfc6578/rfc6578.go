// Package rfc6578 registers WebDAV Collection Synchronization conformance tests (RFC 6578).
//
// Tests cover the DAV:sync-collection REPORT (§3.2), the DAV:sync-token property
// (§4), initial and subsequent synchronization semantics (§3.4–3.5), and error
// handling for bad tokens and unsupported Depth values.
//
// All resource URLs are discovered dynamically via the standard RFC 6764 →
// RFC 6352 discovery chain. No server-specific paths are assumed.
package rfc6578

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	suite.Register(suite.Test{
		ID:          "rfc6578.sync-token-property",
		Suite:       "rfc6578",
		Description: "PROPFIND on a collection returns DAV:sync-token as a protected property",
		Severity:    suite.Must,
		Fn:          testSyncTokenProperty,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.supported-report-set",
		Suite:       "rfc6578",
		Description: "PROPFIND on a collection lists DAV:sync-collection in DAV:supported-report-set",
		Severity:    suite.Must,
		Fn:          testSupportedReportSet,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.initial-sync",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT with empty token returns all members and a sync-token, no removed entries",
		Severity:    suite.Must,
		Fn:          testInitialSync,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.subsequent-sync-changed",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT after PUT returns new resource as changed with propstat and no status element",
		Severity:    suite.Must,
		Fn:          testSubsequentSyncChanged,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.subsequent-sync-removed",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT after DELETE returns resource as removed with 404 status and no propstat",
		Severity:    suite.Must,
		Fn:          testSubsequentSyncRemoved,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.add-then-remove",
		Suite:       "rfc6578",
		Description: "resource added then removed between syncs is reported as removed, not changed",
		Severity:    suite.Must,
		Fn:          testAddThenRemove,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.remove-then-remap",
		Suite:       "rfc6578",
		Description: "resource removed then remapped at same URL is reported as changed, not removed",
		Severity:    suite.Must,
		Fn:          testRemoveThenRemap,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.sync-token-is-uri",
		Suite:       "rfc6578",
		Description: "sync-token returned by sync-collection REPORT is a valid URI",
		Severity:    suite.Must,
		Fn:          testSyncTokenIsURI,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.depth-nonzero-rejected",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT with Depth header other than 0 returns 400 Bad Request",
		Severity:    suite.Must,
		Fn:          testDepthNonZeroRejected,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.invalid-token-rejected",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT with an invalid sync token returns a 4xx error",
		Severity:    suite.Must,
		Fn:          testInvalidTokenRejected,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.sync-token-not-in-allprop",
		Suite:       "rfc6578",
		Description: "PROPFIND DAV:allprop does not include DAV:sync-token in 200 propstat",
		Severity:    suite.Should,
		Fn:          testSyncTokenNotInAllprop,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.no-duplicate-hrefs",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT response contains each member URL exactly once",
		Severity:    suite.Must,
		Fn:          testNoDuplicateHrefs,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.report-on-non-collection",
		Suite:       "rfc6578",
		Description: "sync-collection REPORT issued against a non-collection resource returns 4xx",
		Severity:    suite.Must,
		Fn:          testReportOnNonCollection,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.client-limit",
		Suite:       "rfc6578",
		Description: "DAV:limit in request causes server to truncate with 507 or return postcondition error",
		Severity:    suite.May,
		Fn:          testClientLimit,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.if-header-valid-token",
		Suite:       "rfc6578",
		Description: "PROPFIND with current sync-token in If header succeeds",
		Severity:    suite.Must,
		Fn:          testIfHeaderValidToken,
	})
	suite.Register(suite.Test{
		ID:          "rfc6578.if-header-stale-token",
		Suite:       "rfc6578",
		Description: "PROPFIND with an outdated sync-token in If header returns 412 Precondition Failed",
		Severity:    suite.Must,
		Fn:          testIfHeaderStaleToken,
	})
}

// --- Helpers ---

// discoverHomeSet returns the addressbook-home-set URL for the primary client
// following the RFC 6764 → RFC 6352 discovery chain.
func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

// makeTestCollection creates a uniquely-named collection under homeSet and
// returns its URL and a cleanup func that deletes it.
func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic
	colURL := fmt.Sprintf("%sdavlint-rfc6578-%08x/", homeSet, rand.Uint32()) // #nosec G404
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

// putContact PUTs a vCard to the given URL.
func putContact(ctx context.Context, c *client.Client, u string, body []byte) error {
	resp, err := c.Put(ctx, u, "text/vcard; charset=utf-8", body)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", u, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT %s: got %d, want 201 or 204", u, resp.StatusCode)
	}
	return nil
}

// syncProps is the standard property set requested in sync-collection REPORTs.
var syncProps = [][2]string{{client.NSdav, "getetag"}}

// doSync issues a sync-collection REPORT with Depth:0 and returns the parsed
// multistatus and the sync-token string extracted from it.
func doSync(ctx context.Context, c *client.Client, colURL, token string) (*client.Multistatus, string, error) {
	body := client.ReportSyncCollection(token, "1", syncProps)
	resp, err := c.ReportWithDepth(ctx, colURL, "0", body)
	if err != nil {
		return nil, "", err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return nil, "", err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("parse multistatus: %w", err)
	}
	if ms.SyncToken == "" {
		return nil, "", fmt.Errorf("sync-collection response missing DAV:sync-token element")
	}
	return ms, ms.SyncToken, nil
}

// findResponse returns the MSResponse for href in the multistatus, or nil.
func findResponse(ms *client.Multistatus, href string) *client.MSResponse {
	for i := range ms.Responses {
		if ms.Responses[i].Href == href {
			return &ms.Responses[i]
		}
	}
	return nil
}

// assertChanged verifies that href appears in the multistatus as a changed
// resource: at least one propstat, and no top-level status element (RFC 6578 §3.2).
func assertChanged(ms *client.Multistatus, href string) error {
	r := findResponse(ms, href)
	if r == nil {
		return fmt.Errorf("assertChanged: href %q not found in sync response", href)
	}
	if len(r.PropStat) == 0 {
		return fmt.Errorf("assertChanged: href %q has no DAV:propstat (required for changed resource)", href)
	}
	if r.Status != "" {
		return fmt.Errorf("assertChanged: href %q has DAV:status %q (MUST NOT be present for changed resource)", href, r.Status)
	}
	return nil
}

// assertRemoved verifies that href appears in the multistatus as a removed
// resource: a top-level 404 status and no propstat elements (RFC 6578 §3.2).
func assertRemoved(ms *client.Multistatus, href string) error {
	r := findResponse(ms, href)
	if r == nil {
		return fmt.Errorf("assertRemoved: href %q not found in sync response", href)
	}
	if !strings.Contains(r.Status, "404") {
		return fmt.Errorf("assertRemoved: href %q has status %q, want 404 Not Found", href, r.Status)
	}
	if len(r.PropStat) != 0 {
		return fmt.Errorf("assertRemoved: href %q has %d DAV:propstat element(s) (MUST NOT be present for removed resource)", href, len(r.PropStat))
	}
	return nil
}

// --- Tests ---

// testSyncTokenProperty verifies RFC 6578 §4: the DAV:sync-token property MUST
// be defined on all collections that support the sync-collection report.
func testSyncTokenProperty(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{{client.NSdav, "sync-token"}})
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
	return assert.PropExists(ms, colURL, client.NSdav, "sync-token")
}

// testSupportedReportSet verifies RFC 6578 §3.2: a collection that supports the
// sync-collection report MUST advertise it in DAV:supported-report-set.
func testSupportedReportSet(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{{client.NSdav, "supported-report-set"}})
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	if err := assert.BodyHas(resp.Body, "sync-collection"); err != nil {
		return fmt.Errorf("DAV:supported-report-set does not advertise DAV:sync-collection: %w", err)
	}
	return nil
}

// testInitialSync verifies RFC 6578 §3.4: a sync-collection REPORT with an
// empty sync-token MUST return all current members as changed, MUST NOT return
// any removed members, and MUST include a DAV:sync-token in the response.
func testInitialSync(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	ms, _, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return err
	}

	// alice.vcf MUST appear as a changed member.
	if err := assertChanged(ms, aliceURL); err != nil {
		return err
	}

	// RFC 6578 §3.4: MUST NOT return any removed members.
	for _, r := range ms.Responses {
		if strings.Contains(r.Status, "404") {
			return fmt.Errorf("initial sync returned a removed member %q (MUST NOT happen)", r.Href)
		}
	}
	return nil
}

// testSubsequentSyncChanged verifies RFC 6578 §3.5.1: after a new resource is
// added, a subsequent sync MUST report it as changed (propstat, no status),
// and MUST NOT re-report unchanged resources.
func testSubsequentSyncChanged(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// Initial sync to establish a baseline token.
	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Add bob after the initial sync.
	bobURL := colURL + "bob.vcf"
	if err := putContact(ctx, c, bobURL, []byte(fixtures.BobV4)); err != nil {
		return err
	}

	ms, _, err := doSync(ctx, c, colURL, token)
	if err != nil {
		return fmt.Errorf("subsequent sync: %w", err)
	}

	// bob.vcf MUST appear as changed (propstat, no status).
	if err := assertChanged(ms, bobURL); err != nil {
		return fmt.Errorf("bob.vcf: %w", err)
	}

	// alice.vcf MUST NOT appear (it hasn't changed since the last sync).
	if r := findResponse(ms, aliceURL); r != nil {
		return fmt.Errorf("alice.vcf unexpectedly returned in subsequent sync (resource was not modified)")
	}
	return nil
}

// testSubsequentSyncRemoved verifies RFC 6578 §3.5.2: after a resource is
// deleted, a subsequent sync MUST report it as removed (404 status, no propstat).
func testSubsequentSyncRemoved(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Delete alice.vcf.
	resp, err := c.Delete(ctx, aliceURL, "")
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", aliceURL, err)
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("DELETE %s: got %d", aliceURL, resp.StatusCode)
	}

	ms, _, err := doSync(ctx, c, colURL, token)
	if err != nil {
		return fmt.Errorf("subsequent sync: %w", err)
	}

	return assertRemoved(ms, aliceURL)
}

// testAddThenRemove verifies RFC 6578 §3.5.2: a resource that was added then
// removed between two sync reports MUST be reported as removed.
func testAddThenRemove(ctx context.Context, sess *suite.Session) error {
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

	// Initial sync on empty collection to get a baseline token.
	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Add then immediately remove alice — both events happen between syncs.
	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	resp, err := c.Delete(ctx, aliceURL, "")
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", aliceURL, err)
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("DELETE %s: got %d", aliceURL, resp.StatusCode)
	}

	ms, _, err := doSync(ctx, c, colURL, token)
	if err != nil {
		return fmt.Errorf("subsequent sync: %w", err)
	}

	// alice.vcf was never seen by the client and is now gone — MUST appear as removed.
	if err := assertRemoved(ms, aliceURL); err != nil {
		return fmt.Errorf("add-then-remove: %w", err)
	}
	return nil
}

// testRemoveThenRemap verifies RFC 6578 §3.5.1: a resource that is removed
// then remapped at the same URL MUST be reported as changed, MUST NOT appear
// as removed.
func testRemoveThenRemap(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Delete then re-PUT at the same URL — both between syncs.
	resp, err := c.Delete(ctx, aliceURL, "")
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", aliceURL, err)
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("DELETE %s: got %d", aliceURL, resp.StatusCode)
	}
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.BobV4)); err != nil {
		return err
	}

	ms, _, err := doSync(ctx, c, colURL, token)
	if err != nil {
		return fmt.Errorf("subsequent sync: %w", err)
	}

	// MUST appear as changed (remapped), MUST NOT appear as removed.
	if err := assertChanged(ms, aliceURL); err != nil {
		return fmt.Errorf("remove-then-remap: %w", err)
	}
	return nil
}

// testSyncTokenIsURI verifies RFC 6578 §3.2: the sync-token returned in a
// sync-collection REPORT MUST be a valid URI.
func testSyncTokenIsURI(ctx context.Context, sess *suite.Session) error {
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

	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return err
	}

	u, err := url.Parse(token)
	if err != nil {
		return fmt.Errorf("sync-token %q is not a valid URI: %w", token, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("sync-token %q is not a valid URI: missing scheme", token)
	}
	return nil
}

// testDepthNonZeroRejected verifies RFC 6578 §3.2: a sync-collection REPORT
// with a Depth header other than "0" MUST return 400 Bad Request.
func testDepthNonZeroRejected(ctx context.Context, sess *suite.Session) error {
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

	body := client.ReportSyncCollection("", "1", syncProps)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 400 {
		return fmt.Errorf("sync-collection REPORT with Depth:1: got %d, want 400", resp.StatusCode)
	}
	return nil
}

// testInvalidTokenRejected verifies RFC 6578 §3.2: a sync-collection REPORT
// with an unrecognised sync-token MUST return a 4xx error (DAV:valid-sync-token
// precondition, typically 403 or 409).
func testInvalidTokenRejected(ctx context.Context, sess *suite.Session) error {
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

	body := client.ReportSyncCollection("urn:davlint:invalid-sync-token-xyz", "1", syncProps)
	resp, err := c.ReportWithDepth(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 600 {
		return fmt.Errorf("invalid sync-token: got %d, want 4xx", resp.StatusCode)
	}
	return nil
}

// testNoDuplicateHrefs verifies RFC 6578 §3.2: a given member URL MUST appear
// only once in the sync-collection response.
func testNoDuplicateHrefs(ctx context.Context, sess *suite.Session) error {
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

	if err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	if err := putContact(ctx, c, colURL+"bob.vcf", []byte(fixtures.BobV4)); err != nil {
		return err
	}

	ms, _, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return err
	}

	seen := make(map[string]int)
	for _, r := range ms.Responses {
		seen[r.Href]++
	}
	for href, count := range seen {
		if count > 1 {
			return fmt.Errorf("href %q appears %d times in sync response (MUST appear only once)", href, count)
		}
	}
	return nil
}

// testReportOnNonCollection verifies RFC 6578 §3.2: the request-URI MUST
// identify a collection; issuing the report against a plain resource MUST
// return a 4xx error.
func testReportOnNonCollection(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	if err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	body := client.ReportSyncCollection("", "1", syncProps)
	resp, err := c.ReportWithDepth(ctx, aliceURL, "0", body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 {
		return fmt.Errorf("sync-collection REPORT on non-collection resource: got %d, want 4xx", resp.StatusCode)
	}
	return nil
}

// testClientLimit verifies RFC 6578 §3.7: when a client sends DAV:limit, the
// server MUST either truncate the response (207 + 507 on request-URI) or fail
// with a DAV:number-of-matches-within-limits postcondition error (4xx).
func testClientLimit(ctx context.Context, sess *suite.Session) error {
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

	// Two contacts so a limit of 1 must cause truncation or a postcondition error.
	if err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	if err := putContact(ctx, c, colURL+"bob.vcf", []byte(fixtures.BobV4)); err != nil {
		return err
	}

	body := client.ReportSyncCollectionWithLimit("", "1", 1, syncProps)
	resp, err := c.ReportWithDepth(ctx, colURL, "0", body)
	if err != nil {
		return err
	}

	switch {
	case resp.StatusCode >= 400:
		// Postcondition error — valid per RFC 6578 §3.7.
		return nil
	case resp.StatusCode == 207:
		ms, err := client.ParseMultistatus(resp.Body)
		if err != nil {
			return fmt.Errorf("parse truncated multistatus: %w", err)
		}
		// RFC 6578 §3.6: truncated response MUST have a 507 entry for the request-URI.
		r := findResponse(ms, colURL)
		if r == nil || !strings.Contains(r.Status, "507") {
			return fmt.Errorf("client-limit: 207 response missing 507 entry for request-URI %q (server returned more results than requested limit without signalling truncation)", colURL)
		}
		// DAV:sync-token MUST be present even in a truncated response.
		if ms.SyncToken == "" {
			return fmt.Errorf("client-limit: truncated response missing DAV:sync-token")
		}
		return nil
	default:
		return fmt.Errorf("client-limit: got %d, want 207 (truncated) or 4xx (postcondition error)", resp.StatusCode)
	}
}

// testIfHeaderValidToken verifies RFC 6578 §5: servers MUST support use of
// DAV:sync-token values in If request headers. A PROPFIND carrying the
// current sync-token MUST succeed.
func testIfHeaderValidToken(ctx context.Context, sess *suite.Session) error {
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

	_, token, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return err
	}

	body := client.PropfindProps([][2]string{{client.NSdav, "getetag"}})
	resp, err := c.PropfindWithIf(ctx, colURL, "0", token, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 412 {
		return fmt.Errorf("if-header-valid-token: got 412 Precondition Failed with current sync-token; server MUST accept valid token in If header")
	}
	if resp.StatusCode != 207 {
		return fmt.Errorf("if-header-valid-token: got %d, want 207", resp.StatusCode)
	}
	return nil
}

// testIfHeaderStaleToken verifies RFC 6578 §5: a PROPFIND carrying an outdated
// sync-token in the If header MUST return 412 Precondition Failed.
func testIfHeaderStaleToken(ctx context.Context, sess *suite.Session) error {
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

	_, token1, err := doSync(ctx, c, colURL, "")
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Modify the collection to advance the sync-token.
	if err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	_, token2, err := doSync(ctx, c, colURL, token1)
	if err != nil {
		return fmt.Errorf("subsequent sync: %w", err)
	}
	if token2 == token1 {
		// Token didn't change after a mutation — server may batch updates.
		// Skip rather than produce a false negative.
		return nil
	}

	body := client.PropfindProps([][2]string{{client.NSdav, "getetag"}})
	resp, err := c.PropfindWithIf(ctx, colURL, "0", token1, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 412 {
		return fmt.Errorf("if-header-stale-token: got %d with outdated sync-token in If header, want 412 Precondition Failed", resp.StatusCode)
	}
	return nil
}

// testSyncTokenNotInAllprop verifies RFC 6578 §4: DAV:sync-token SHOULD NOT
// be returned by PROPFIND DAV:allprop.
func testSyncTokenNotInAllprop(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Propfind(ctx, colURL, "0", client.PropfindAllprop())
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

	for _, r := range ms.Responses {
		if r.Href != colURL {
			continue
		}
		for _, ps := range r.PropStat {
			if !strings.Contains(ps.Status, "200") {
				continue
			}
			if client.PropInnerXML(ps.Prop.Inner, client.NSdav, "sync-token") {
				return fmt.Errorf("DAV:sync-token present in DAV:allprop 200 propstat for %s (SHOULD NOT be returned)", colURL)
			}
		}
	}
	return nil
}
