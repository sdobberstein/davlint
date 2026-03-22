// Package rfc2426 registers vCard 3.0 format validation tests (RFC 2426).
//
// Tests verify server-side enforcement of vCard 3.0 format rules observable
// via HTTP: rejection of malformed vCards (missing required properties, invalid
// VERSION), and correct parsing of format features (line folding, escaped
// characters).
package rfc2426

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	// §2.1: Content MUST begin with BEGIN:VCARD.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-missing-begin",
		Suite:         "rfc2426",
		Description:   "PUT a body without BEGIN:VCARD is rejected with 4xx (RFC 2426 §2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.1"},
		},
		Fn: testRejectMissingBegin,
	})
	// §2.1: Content MUST end with END:VCARD.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-missing-end",
		Suite:         "rfc2426",
		Description:   "PUT a body without END:VCARD is rejected with 4xx (RFC 2426 §2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.1"},
		},
		Fn: testRejectMissingEnd,
	})
	// §2.1: BEGIN:VCARD MUST be the first line.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-begin-not-first",
		Suite:         "rfc2426",
		Description:   "PUT a body where BEGIN:VCARD is not the first line is rejected with 4xx (RFC 2426 §2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.1"},
		},
		Fn: testRejectBeginNotFirst,
	})
	// §2.1: END:VCARD MUST be the last line.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-end-not-last",
		Suite:         "rfc2426",
		Description:   "PUT a body where END:VCARD is not the last line is rejected with 4xx (RFC 2426 §2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.1"},
		},
		Fn: testRejectEndNotLast,
	})
	// §3.1.1: FN MUST be present.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-missing-fn",
		Suite:         "rfc2426",
		Description:   "PUT a vCard 3.0 without FN is rejected with 4xx (RFC 2426 §3.1.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§3.1.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-3.1.1"},
		},
		Fn: testRejectMissingFN,
	})
	// §3.1.2: N MUST be present.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-missing-n",
		Suite:         "rfc2426",
		Description:   "PUT a vCard 3.0 without N is rejected with 4xx (RFC 2426 §3.1.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§3.1.2", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-3.1.2"},
		},
		Fn: testRejectMissingN,
	})
	// §3.6.9: VERSION MUST be present.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-missing-version",
		Suite:         "rfc2426",
		Description:   "PUT a vCard without VERSION is rejected with 4xx (RFC 2426 §3.6.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§3.6.9", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-3.6.9"},
		},
		Fn: testRejectMissingVersion,
	})
	// §3.6.9: VERSION value MUST be "3.0" for this spec.
	suite.Register(suite.Test{
		ID:            "rfc2426.reject-invalid-version",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with VERSION:2.1 is rejected with 4xx (RFC 2426 §3.6.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§3.6.9", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-3.6.9"},
		},
		Fn: testRejectInvalidVersion,
	})
	// §2.6 / RFC 2425 §5.8.1: folded lines MUST be unfolded before parsing.
	suite.Register(suite.Test{
		ID:            "rfc2426.folded-line-parsed",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with a CRLF+SPACE folded FN line is accepted and the full value survives a round-trip (RFC 2425 §5.8.1)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2425", Section: "§5.8.1", URL: "https://www.rfc-editor.org/rfc/rfc2425#section-5.8.1"},
			{RFC: "RFC 2426", Section: "§2.6", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.6"},
		},
		Fn: testFoldedLineParsed,
	})
	suite.Register(suite.Test{
		ID:            "rfc2426.folded-line-tab-parsed",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with a CRLF+TAB folded FN line is accepted and the full value survives a round-trip (RFC 2425 §5.8.1)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2425", Section: "§5.8.1", URL: "https://www.rfc-editor.org/rfc/rfc2425#section-5.8.1"},
			{RFC: "RFC 2426", Section: "§2.6", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.6"},
		},
		Fn: testFoldedLineTabParsed,
	})
	// §2.3: Escaped semicolon in NOTE text value MUST survive a round-trip.
	suite.Register(suite.Test{
		ID:            "rfc2426.semicolon-escape-roundtrip-note",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with a backslash-escaped semicolon in NOTE; GET returns both parts of the value (RFC 2426 §2.3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.3", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.3"},
		},
		Fn: testSemicolonEscapeRoundtripNote,
	})
	// §3.2.1: Absent ADR components MUST retain their SEMI-COLON separators.
	suite.Register(suite.Test{
		ID:            "rfc2426.adr-structure-roundtrip",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with a sparse ADR; GET returns ADR with component values in correct positions (RFC 2426 §3.2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-3.2.1"},
		},
		Fn: testADRStructureRoundtrip,
	})
	// §2.3: SEMI-COLON in a text value MUST be backslash-escaped.
	suite.Register(suite.Test{
		ID:            "rfc2426.semicolon-escape-accepted",
		Suite:         "rfc2426",
		Description:   "PUT a vCard with a backslash-escaped semicolon in FN is accepted (RFC 2426 §2.3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 2426", Section: "§2.3", URL: "https://www.rfc-editor.org/rfc/rfc2426#section-2.3"},
		},
		Fn: testSemicolonEscapeAccepted,
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

// vcardNoBegin is missing the required BEGIN:VCARD delimiter (RFC 2426 §2.1).
const vcardNoBegin = "VERSION:3.0\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardNoEnd is missing the required END:VCARD delimiter (RFC 2426 §2.1).
const vcardNoEnd = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n"

// vcardBeginNotFirst has BEGIN:VCARD after a property line (RFC 2426 §2.1
// requires BEGIN:VCARD to be the first line).
const vcardBeginNotFirst = "FN:Alice Test\r\n" +
	"BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardEndNotLast has END:VCARD before a trailing property line (RFC 2426 §2.1
// requires END:VCARD to be the last line).
const vcardEndNotLast = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n" +
	"NOTE:trailing line\r\n"

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

// vcardFoldedFN is a valid vCard 3.0 where the FN line is folded at 75
// characters using CRLF + SPACE (RFC 2425 §5.8.1). The fold is inserted
// between 'y' and ' ' in "Seventy Five", so the continuation line begins
// with two spaces: the first is the fold indicator (removed on unfold), the
// second is the original space that belongs to the value.
// After unfolding the full FN value is foldedFNExpected.
const vcardFoldedFN = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:f0000000-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	"  Five Characters\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardFoldedFNTab is identical to vcardFoldedFN but uses CRLF + TAB as the
// fold indicator. RFC 2425 §5.8.1 explicitly permits both SPACE and TAB.
// The continuation begins with TAB (fold indicator) + SPACE (original value char).
const vcardFoldedFNTab = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:f0000000-0000-0000-0000-000000000002\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	"\t Five Characters\r\n" +
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

// vcardNoteEscapedSemicolon is a valid vCard 3.0 where the NOTE value contains
// a backslash-escaped semicolon per RFC 2426 §2.3. The full value is
// "First part; second part"; if the server incorrectly treats \; as a field
// separator, "second part" will be lost in a round-trip.
const vcardNoteEscapedSemicolon = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:e0000000-0000-0000-0000-000000000002\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"NOTE:First part\\; second part\r\n" +
	"END:VCARD\r\n"

// vcardSparseADR is a valid vCard 3.0 with a sparse ADR where PO Box and
// Extended Address are empty but their SEMI-COLON separators MUST be retained
// per RFC 2426 §3.2.1.
const vcardSparseADR = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:a0000000-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"ADR;TYPE=HOME:;;123 Main St;Springfield;IL;62701;USA\r\n" +
	"END:VCARD\r\n"

// vcardEscapedSemicolon is a valid vCard 3.0 where the FN value contains a
// backslash-escaped semicolon per RFC 2426 §2.3.
const vcardEscapedSemicolon = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:e0000000-0000-0000-0000-000000000001\r\n" +
	`FN:Alice\; The Test` + "\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// --- Tests ---

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

func testRejectMissingBegin(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoBegin), "PUT body without BEGIN:VCARD")
}

func testRejectMissingEnd(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoEnd), "PUT body without END:VCARD")
}

func testRejectBeginNotFirst(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardBeginNotFirst), "PUT body where BEGIN:VCARD is not the first line")
}

func testRejectEndNotLast(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardEndNotLast), "PUT body where END:VCARD is not the last line")
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

	if sess.Verbose {
		fmt.Fprintf(os.Stderr, "\n[%s fold / SENT PUT body]\n%s\n",
			foldKind, showCRLF([]byte(vcard)))
	}

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

	unfolded := unfoldVCard(resp.Body)

	if sess.Verbose {
		fmt.Fprintf(os.Stderr, "[%s fold / RECEIVED raw GET body]\n%s\n",
			foldKind, showCRLF(resp.Body))
		fmt.Fprintf(os.Stderr, "[%s fold / RECEIVED after unfold]\n%s\n",
			foldKind, showCRLF(unfolded))
		fmt.Fprintf(os.Stderr, "[%s fold / LOOKING FOR]\n%s\n",
			foldKind, foldedFNExpected)
	}

	// Unfold before asserting: the server MAY re-fold its output at any position,
	// so we must not check raw bytes directly (RFC 2425 §5.8.1).
	if err := assert.BodyHas(unfolded, foldedFNExpected); err != nil {
		return fmt.Errorf("%s fold round-trip: full FN value not found after unfolding response: %w", foldKind, err)
	}
	return nil
}

// showCRLF returns a human-readable version of body with CRLF shown as "↵\n"
// and TAB shown as "→" so fold indicators are visible in verbose output.
func showCRLF(body []byte) string {
	s := string(body)
	s = strings.ReplaceAll(s, "\r\n", "↵\n")
	s = strings.ReplaceAll(s, "\t", "→")
	return s
}

func testSemicolonEscapeRoundtripNote(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"note-escape.vcf", "text/vcard; charset=utf-8", []byte(vcardNoteEscapedSemicolon))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard with escaped semicolon in NOTE: got %d, want 201", resp.StatusCode)
	}

	resp, err = c.Get(ctx, colURL+"note-escape.vcf")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// Both parts of the NOTE value must be present after unfolding; if the
	// server split on \; the text after the semicolon will be lost.
	unfolded := unfoldVCard(resp.Body)
	if err := assert.BodyHas(unfolded, "second part"); err != nil {
		return fmt.Errorf("NOTE escaped-semicolon round-trip: value after '\\;' not found; server may have split on the semicolon: %w", err)
	}
	return nil
}

func testADRStructureRoundtrip(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"adr.vcf", "text/vcard; charset=utf-8", []byte(vcardSparseADR))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard with sparse ADR: got %d, want 201", resp.StatusCode)
	}

	resp, err = c.Get(ctx, colURL+"adr.vcf")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// Locality and postal code must appear in the response; if absent components
	// collapse their separators, these values shift to wrong positions.
	unfolded := unfoldVCard(resp.Body)
	if err := assert.BodyHas(unfolded, "Springfield"); err != nil {
		return fmt.Errorf("ADR structure round-trip: locality 'Springfield' not found: %w", err)
	}
	return assert.BodyHas(unfolded, "62701")
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

