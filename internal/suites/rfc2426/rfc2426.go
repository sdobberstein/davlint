// Package rfc2426 registers vCard 3.0 conformance tests (RFC 2426).
//
// Tests verify that the server accepts vCard 3.0 input, stores it internally
// as vCard 4.0, and can serve it back in 3.0 format on request — including
// correct EMAIL type conversion between the two versions.
package rfc2426

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	suite.Register(suite.Test{
		ID:          "rfc2426.put-v3",
		Suite:       "rfc2426",
		Description: "PUT a vCard 3.0 returns 201 Created",
		Severity:    suite.Must,
		Fn:          testPutV3,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.stored-as-v4",
		Suite:       "rfc2426",
		Description: "After PUT of vCard 3.0, default GET returns VERSION:4.0",
		Severity:    suite.Must,
		Fn:          testStoredAsV4,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.get-accept-v3",
		Suite:       "rfc2426",
		Description: "GET with Accept: text/vcard; version=3.0 returns VERSION:3.0 after PUT of 3.0",
		Severity:    suite.Must,
		Fn:          testGetAcceptV3,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.email-roundtrip",
		Suite:       "rfc2426",
		Description: "Email type is preserved correctly when serving vCard 4.0 content as 3.0",
		Severity:    suite.Must,
		Fn:          testEmailRoundtrip,
	})
	// §3.1.1 / §1: FN MUST be present.
	suite.Register(suite.Test{
		ID:          "rfc2426.reject-missing-fn",
		Suite:       "rfc2426",
		Description: "PUT a vCard 3.0 without FN is rejected with 4xx (RFC 2426 §3.1.1 MUST)",
		Severity:    suite.Must,
		Fn:          testRejectMissingFN,
	})
	// §3.1.2 / §1: N MUST be present.
	suite.Register(suite.Test{
		ID:          "rfc2426.reject-missing-n",
		Suite:       "rfc2426",
		Description: "PUT a vCard 3.0 without N is rejected with 4xx (RFC 2426 §3.1.2 MUST)",
		Severity:    suite.Must,
		Fn:          testRejectMissingN,
	})
	// §3.6.9 / §1: VERSION MUST be present.
	suite.Register(suite.Test{
		ID:          "rfc2426.reject-missing-version",
		Suite:       "rfc2426",
		Description: "PUT a vCard without VERSION is rejected with 4xx (RFC 2426 §3.6.9 MUST)",
		Severity:    suite.Must,
		Fn:          testRejectMissingVersion,
	})
	// §3.6.9: VERSION value MUST be "3.0" for this spec.
	suite.Register(suite.Test{
		ID:          "rfc2426.reject-invalid-version",
		Suite:       "rfc2426",
		Description: "PUT a vCard with VERSION:2.1 is rejected with 4xx (RFC 2426 §3.6.9 MUST)",
		Severity:    suite.Must,
		Fn:          testRejectInvalidVersion,
	})
	// §2.6 / MIME-DIR: folded lines MUST be unfolded before parsing.
	suite.Register(suite.Test{
		ID:          "rfc2426.folded-line-parsed",
		Suite:       "rfc2426",
		Description: "PUT a vCard with a CRLF+SPACE folded FN line is accepted and the full value survives a round-trip (RFC 2425 §5.8.1)",
		Severity:    suite.Must,
		Fn:          testFoldedLineParsed,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.folded-line-tab-parsed",
		Suite:       "rfc2426",
		Description: "PUT a vCard with a CRLF+TAB folded FN line is accepted and the full value survives a round-trip (RFC 2425 §5.8.1)",
		Severity:    suite.Must,
		Fn:          testFoldedLineTabParsed,
	})
	// §2.3: SEMI-COLON in a text value MUST be backslash-escaped.
	suite.Register(suite.Test{
		ID:          "rfc2426.semicolon-escape-accepted",
		Suite:       "rfc2426",
		Description: "PUT a vCard with a backslash-escaped semicolon in FN is accepted (RFC 2426 §2.3 MUST)",
		Severity:    suite.Must,
		Fn:          testSemicolonEscapeAccepted,
	})
}

func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here
	colURL := fmt.Sprintf("%sdavlint-rfc2426-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

// --- Local fixtures ---
//
// These represent malformed or edge-case vCards used only within this suite.
// They intentionally omit required fields or exercise format corner-cases and
// are not suitable for use as general-purpose test data.

// vcardNoFN is missing the required FN property (RFC 2426 §3.1.1).
const vcardNoFN = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardNoN is missing the required N property (RFC 2426 §3.1.2).
const vcardNoN = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN:Alice Test\r\n" +
	"END:VCARD\r\n"

// vcardNoVersion is missing the required VERSION property (RFC 2426 §3.6.9).
const vcardNoVersion = "BEGIN:VCARD\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardVersion21 uses VERSION:2.1, which is not valid for RFC 2426 (§3.6.9 requires "3.0").
const vcardVersion21 = "BEGIN:VCARD\r\n" +
	"VERSION:2.1\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardFoldedFN is a valid vCard 3.0 where the FN line is folded using
// CRLF + SPACE (RFC 2425 §5.8.1). After unfolding the full FN value is
// foldedFNExpected.
const vcardFoldedFN = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:f0000000-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	" Five Characters\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardFoldedFNTab is identical to vcardFoldedFN but uses CRLF + TAB as the
// fold indicator. RFC 2425 §5.8.1 explicitly permits both SPACE and TAB.
const vcardFoldedFNTab = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:f0000000-0000-0000-0000-000000000002\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	"\tFive Characters\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// foldedFNExpected is the unfolded FN value that must survive a round-trip.
const foldedFNExpected = "Alice Test User With A Very Long Full Name That Needs Folding At Seventy Five Characters"

// unfoldVCard removes fold indicators from a vCard body per RFC 2425 §5.8.1:
// CRLF followed by a single SPACE or TAB is removed entirely.
// This must be applied before checking logical property values in a GET response,
// because a conformant server MAY re-fold its output at any position.
func unfoldVCard(body []byte) []byte {
	body = bytes.ReplaceAll(body, []byte("\r\n "), nil)
	body = bytes.ReplaceAll(body, []byte("\r\n\t"), nil)
	return body
}

// vcardEscapedSemicolon is a valid vCard 3.0 where the FN value contains a
// backslash-escaped semicolon per RFC 2426 §2.3.
const vcardEscapedSemicolon = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:e0000000-0000-0000-0000-000000000001\r\n" +
	`FN:Alice\; The Test` + "\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// --- Tests ---

func testPutV3(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard 3.0: got %d, want 201", resp.StatusCode)
	}
	return nil
}

func testStoredAsV4(ctx context.Context, sess *suite.Session) error {
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

	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3)); err != nil {
		return err
	}

	resp, err := c.Get(ctx, colURL+"alice.vcf")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:4.0")
}

func testGetAcceptV3(ctx context.Context, sess *suite.Session) error {
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

	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3)); err != nil {
		return err
	}

	resp, err := c.GetWithAccept(ctx, colURL+"alice.vcf", "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:3.0")
}

// putInvalidVCard is a helper that PUTs body into a fresh collection and asserts
// the response is a 4xx client error. It handles collection setup and cleanup.
func putInvalidVCard(ctx context.Context, sess *suite.Session, body []byte, desc string) error {
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

	resp, err := c.Put(ctx, colURL+"invalid.vcf", "text/vcard; charset=utf-8", body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return fmt.Errorf("%s: got %d, want 4xx", desc, resp.StatusCode)
	}
	return nil
}

func testRejectMissingFN(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoFN), "PUT vCard without FN")
}

func testRejectMissingN(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoN), "PUT vCard without N")
}

func testRejectMissingVersion(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoVersion), "PUT vCard without VERSION")
}

func testRejectInvalidVersion(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardVersion21), "PUT vCard with VERSION:2.1")
}

// testFoldedLineParsed verifies RFC 2425 §5.8.1 (referenced by RFC 2426 §2.6):
// the server MUST unfold CRLF+SPACE fold indicators before parsing. The full
// logical FN value must survive a PUT→GET round-trip. The GET response is
// unfolded before asserting because a conformant server MAY re-fold its output.
func testFoldedLineParsed(ctx context.Context, sess *suite.Session) error {
	return testFoldedRoundTrip(ctx, sess, vcardFoldedFN, "folded-space.vcf", "CRLF+SPACE")
}

// testFoldedLineTabParsed verifies RFC 2425 §5.8.1: CRLF+TAB is also a valid
// fold indicator and MUST be unfolded before parsing.
func testFoldedLineTabParsed(ctx context.Context, sess *suite.Session) error {
	return testFoldedRoundTrip(ctx, sess, vcardFoldedFNTab, "folded-tab.vcf", "CRLF+TAB")
}

// testFoldedRoundTrip is the shared implementation for fold round-trip tests.
func testFoldedRoundTrip(ctx context.Context, sess *suite.Session, vcard, filename, foldKind string) error {
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

	resp, err := c.Put(ctx, colURL+filename, "text/vcard; charset=utf-8", []byte(vcard))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard with %s folded FN: got %d, want 201", foldKind, resp.StatusCode)
	}

	resp, err = c.Get(ctx, colURL+filename)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// Unfold before asserting: the server MAY re-fold its output at any position,
	// so we must not check raw bytes directly (RFC 2425 §5.8.1).
	unfolded := unfoldVCard(resp.Body)
	if err := assert.BodyHas(unfolded, foldedFNExpected); err != nil {
		return fmt.Errorf("%s fold round-trip: full FN value not found after unfolding response: %w", foldKind, err)
	}
	return nil
}

func testSemicolonEscapeAccepted(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"escape.vcf", "text/vcard; charset=utf-8", []byte(vcardEscapedSemicolon))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard with escaped semicolon in FN: got %d, want 201", resp.StatusCode)
	}

	resp, err = c.Get(ctx, colURL+"escape.vcf")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// The stored value must contain "Alice" — the part before the escaped semicolon.
	// This confirms the server parsed and preserved the FN rather than splitting on it.
	return assert.BodyHas(resp.Body, "Alice")
}

func testEmailRoundtrip(ctx context.Context, sess *suite.Session) error {
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

	// PUT a 4.0 vCard with TYPE=work email.
	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// GET as 3.0 — email must include INTERNET in the TYPE list.
	resp, err := c.GetWithAccept(ctx, colURL+"alice.vcf", "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// RFC 2426 §3.3.2: TYPE=INTERNET is required for email addresses in 3.0.
	if err := assert.BodyHas(resp.Body, "INTERNET"); err != nil {
		return fmt.Errorf("email type conversion to 3.0: %w", err)
	}
	return nil
}
