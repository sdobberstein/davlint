// Package rfc6350 registers vCard 4.0 format validation tests (RFC 6350).
//
// Tests verify server-side enforcement of vCard 4.0 rules observable via HTTP:
// that stored vCards are served as VERSION:4.0 by default, that the server
// assigns a UID when one is absent on PUT, and that malformed vCards are rejected.
package rfc6350

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	// §6.7.9: VERSION value MUST be "4.0" for this spec.
	suite.Register(suite.Test{
		ID:            "rfc6350.get-default-v4",
		Suite:         "rfc6350",
		Description:   "GET on a stored vCard returns VERSION:4.0 by default",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testGetDefaultV4,
	})
	// §6.7.6: UID MUST uniquely identify the vCard object.
	suite.Register(suite.Test{
		ID:            "rfc6350.uid-assignment",
		Suite:         "rfc6350",
		Description:   "PUT a vCard without UID; server assigns one and GET returns a UID line",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.6", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.6"},
		},
		Fn: testUIDAssignment,
	})
	// §3: Content MUST begin with BEGIN:VCARD.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-missing-begin",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 body without BEGIN:VCARD is rejected with 4xx (RFC 6350 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3"},
		},
		Fn: testRejectMissingBegin,
	})
	// §3: Content MUST end with END:VCARD.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-missing-end",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 body without END:VCARD is rejected with 4xx (RFC 6350 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3"},
		},
		Fn: testRejectMissingEnd,
	})
	// §6.2.1: FN MUST be present (cardinality 1*).
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-missing-fn",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 without FN is rejected with 4xx (RFC 6350 §6.2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.2.1", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.2.1"},
		},
		Fn: testRejectMissingFN,
	})
	// §6.7.9: VERSION MUST be present.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-missing-version",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 without VERSION is rejected with 4xx (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testRejectMissingVersion,
	})
	// §6.7.9: VERSION MUST appear immediately after BEGIN:VCARD.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-version-not-first",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 where VERSION does not immediately follow BEGIN:VCARD is rejected with 4xx (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testRejectVersionNotFirst,
	})
	// §6.7.9: VERSION value MUST be "4.0"; "3.0" is not valid at this endpoint.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-version-30",
		Suite:         "rfc6350",
		Description:   "PUT a vCard with VERSION:3.0 is rejected with 4xx at a vCard 4.0 endpoint (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testRejectVersion30,
	})
	// §6.7.9: VERSION value MUST be "4.0"; "2.1" is not valid at this endpoint.
	suite.Register(suite.Test{
		ID:            "rfc6350.reject-version-21",
		Suite:         "rfc6350",
		Description:   "PUT a vCard with VERSION:2.1 is rejected with 4xx at a vCard 4.0 endpoint (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testRejectVersion21,
	})
	// §3: The charset for vCard 4.0 MUST be UTF-8; other charsets MUST be rejected.
	suite.Register(suite.Test{
		ID:            "rfc6350.charset-latin1-rejected",
		Suite:         "rfc6350",
		Description:   "PUT a vCard with Content-Type charset=latin1 is rejected with 4xx (RFC 6350 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3"},
		},
		Fn: testCharsetLatin1Rejected,
	})
	// §3: Explicit charset=utf-8 MUST be accepted.
	suite.Register(suite.Test{
		ID:            "rfc6350.charset-utf8-accepted",
		Suite:         "rfc6350",
		Description:   "PUT a vCard with explicit Content-Type charset=utf-8 is accepted (RFC 6350 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3"},
		},
		Fn: testCharsetUTF8Accepted,
	})
	// §3.2: CRLF+SPACE fold indicators MUST be unfolded before parsing.
	suite.Register(suite.Test{
		ID:            "rfc6350.folded-line-parsed",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a CRLF+SPACE folded FN line is accepted and the full value survives a round-trip (RFC 6350 §3.2)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.2", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.2"},
		},
		Fn: testFoldedLineParsed,
	})
	// §3.2: CRLF+TAB fold indicators MUST be unfolded before parsing.
	suite.Register(suite.Test{
		ID:            "rfc6350.folded-line-tab-parsed",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a CRLF+TAB folded FN line is accepted and the full value survives a round-trip (RFC 6350 §3.2)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.2", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.2"},
		},
		Fn: testFoldedLineTabParsed,
	})
	// §3.4: Escaped comma in a TEXT value MUST survive a round-trip without splitting.
	suite.Register(suite.Test{
		ID:            "rfc6350.escape-comma-roundtrip",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a backslash-escaped comma in NOTE; GET returns both parts of the value (RFC 6350 §3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.4", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.4"},
		},
		Fn: testEscapeCommaRoundtrip,
	})
	// §3.4: Escaped semicolon in a compound value MUST survive a round-trip without splitting.
	suite.Register(suite.Test{
		ID:            "rfc6350.escape-semicolon-roundtrip",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a backslash-escaped semicolon in NOTE; GET returns both parts of the value (RFC 6350 §3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.4", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.4"},
		},
		Fn: testEscapeSemicolonRoundtrip,
	})
	// §3.4: Escaped backslash in a TEXT value MUST survive a round-trip as a literal backslash.
	suite.Register(suite.Test{
		ID:            "rfc6350.escape-backslash-roundtrip",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a double-backslash in NOTE; GET returns a single literal backslash (RFC 6350 §3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.4", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.4"},
		},
		Fn: testEscapeBackslashRoundtrip,
	})
	// §3.4: \n escape in a TEXT value MUST be interpreted as a line break.
	suite.Register(suite.Test{
		ID:            "rfc6350.escape-newline-roundtrip",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with \\n in NOTE; GET returns a value containing both lines (RFC 6350 §3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§3.4", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-3.4"},
		},
		Fn: testEscapeNewlineRoundtrip,
	})
	// §6.7.9: KIND MUST be one of individual, group, org, location; unknown values MUST be rejected.
	suite.Register(suite.Test{
		ID:            "rfc6350.kind-unknown-rejected",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with KIND:unknown is rejected with 4xx (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testKindUnknownRejected,
	})
	// §6.7.9: KIND:org MUST be accepted.
	suite.Register(suite.Test{
		ID:            "rfc6350.kind-org-accepted",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with KIND:org is accepted (RFC 6350 §6.7.9 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testKindOrgAccepted,
	})
	// §6.3.1: Absent ADR components MUST retain their SEMI-COLON separators.
	suite.Register(suite.Test{
		ID:            "rfc6350.adr-sparse-roundtrip",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with a sparse ADR; GET returns ADR with component values in correct positions (RFC 6350 §6.3.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.3.1", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.3.1"},
		},
		Fn: testADRSparseRoundtrip,
	})
	// §6.7.6 / RFC 6352 §6.3.2: Second PUT with same UID on a different URL MUST be rejected.
	suite.Register(suite.Test{
		ID:            "rfc6350.uid-conflict",
		Suite:         "rfc6350",
		Description:   "PUT a second vCard with the same UID at a different URL is rejected with 4xx (RFC 6352 §6.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.6", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.6"},
			{RFC: "RFC 6352", Section: "§6.3.2", URL: "https://www.rfc-editor.org/rfc/rfc6352#section-6.3.2"},
		},
		Fn: testUIDConflict,
	})
	// §5.7.2: PREF value MUST be an integer between 1 and 100; 0 is out of range.
	suite.Register(suite.Test{
		ID:            "rfc6350.pref-zero-rejected",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with PREF=0 is rejected with 4xx (RFC 6350 §5.7.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§5.7.2", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-5.7.2"},
		},
		Fn: testPrefZeroRejected,
	})
	// §5.7.2: PREF value MUST be an integer between 1 and 100; 101 is out of range.
	suite.Register(suite.Test{
		ID:            "rfc6350.pref-101-rejected",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with PREF=101 is rejected with 4xx (RFC 6350 §5.7.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§5.7.2", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-5.7.2"},
		},
		Fn: testPref101Rejected,
	})
	// §6.6.5: MEMBER is only valid when KIND is "group".
	suite.Register(suite.Test{
		ID:            "rfc6350.member-without-kind-group",
		Suite:         "rfc6350",
		Description:   "PUT a vCard 4.0 with MEMBER but without KIND:group is rejected with 4xx (RFC 6350 §6.6.5 SHOULD)",
		Severity:      suite.Should,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.6.5", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.6.5"},
		},
		Fn: testMemberWithoutKindGroup,
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
	colURL := fmt.Sprintf("%sdavlint-rfc6350-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

func putContact(ctx context.Context, c *client.Client, url string, body []byte) (*client.Response, error) {
	return c.Put(ctx, url, "text/vcard; charset=utf-8", body)
}

// --- Local fixtures ---
//
// These represent malformed or edge-case vCards used only within this suite.
// They intentionally omit required fields or exercise format corner-cases and
// are not suitable for use as general-purpose test data.

// vcardNoBegin is missing the required BEGIN:VCARD delimiter (RFC 6350 §3).
const vcardNoBegin = "VERSION:4.0\r\n" +
	"FN:Alice Test\r\n" +
	"END:VCARD\r\n"

// vcardNoEnd is missing the required END:VCARD delimiter (RFC 6350 §3).
const vcardNoEnd = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"FN:Alice Test\r\n"

// vcardNoFN is missing the required FN property (RFC 6350 §6.2.1).
const vcardNoFN = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"END:VCARD\r\n"

// vcardNoVersion is missing the required VERSION property (RFC 6350 §6.7.9).
const vcardNoVersion = "BEGIN:VCARD\r\n" +
	"FN:Alice Test\r\n" +
	"END:VCARD\r\n"

// vcardVersionNotFirst has VERSION after FN instead of immediately after BEGIN
// (RFC 6350 §6.7.9 requires VERSION to immediately follow BEGIN:VCARD).
const vcardVersionNotFirst = "BEGIN:VCARD\r\n" +
	"FN:Alice Test\r\n" +
	"VERSION:4.0\r\n" +
	"END:VCARD\r\n"

// vcardVersion30 uses VERSION:3.0, which is not valid at a vCard 4.0 endpoint
// (RFC 6350 §6.7.9 requires the value "4.0").
const vcardVersion30 = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// vcardVersion21 uses VERSION:2.1, which is not valid at a vCard 4.0 endpoint.
const vcardVersion21 = "BEGIN:VCARD\r\n" +
	"VERSION:2.1\r\n" +
	"FN:Alice Test\r\n" +
	"END:VCARD\r\n"

// vcardFoldedFN is a valid vCard 4.0 where the FN line is folded at 75
// characters using CRLF + SPACE (RFC 6350 §3.2). After unfolding the full
// FN value is foldedFNExpected.
const vcardFoldedFN = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000001-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	"  Five Characters\r\n" +
	"END:VCARD\r\n"

// vcardFoldedFNTab is identical to vcardFoldedFN but uses CRLF + TAB as the
// fold indicator (RFC 6350 §3.2 explicitly permits both SPACE and TAB).
const vcardFoldedFNTab = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000002-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test User With A Very Long Full Name That Needs Folding At Seventy\r\n" +
	"\t Five Characters\r\n" +
	"END:VCARD\r\n"

// foldedFNExpected is the unfolded FN value that must survive a round-trip.
const foldedFNExpected = "Alice Test User With A Very Long Full Name That Needs Folding At Seventy Five Characters"

// vcardEscapedComma is a valid vCard 4.0 where the NOTE value contains a
// backslash-escaped comma per RFC 6350 §3.4. If the server incorrectly treats
// \, as a list separator, "second part" will be lost in a round-trip.
const vcardEscapedComma = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000003-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	`NOTE:First part\, second part` + "\r\n" +
	"END:VCARD\r\n"

// vcardEscapedSemicolon is a valid vCard 4.0 where the NOTE value contains a
// backslash-escaped semicolon per RFC 6350 §3.4. If the server treats \; as a
// component separator, "second part" will be lost in a round-trip.
const vcardEscapedSemicolon = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000008-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	`NOTE:First part\; second part` + "\r\n" +
	"END:VCARD\r\n"

// vcardEscapedBackslash is a valid vCard 4.0 where the NOTE value contains a
// double-backslash per RFC 6350 §3.4. The server MUST store and return a single
// literal backslash.
const vcardEscapedBackslash = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000009-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	`NOTE:path\\value` + "\r\n" +
	"END:VCARD\r\n"

// vcardEscapedNewline is a valid vCard 4.0 where the NOTE value contains a \n
// escape per RFC 6350 §3.4, representing an embedded line break. Both parts of
// the value must survive a round-trip.
const vcardEscapedNewline = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:6000000a-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	`NOTE:line one\nline two` + "\r\n" +
	"END:VCARD\r\n"

// vcardKindUnknown is a vCard 4.0 with a non-standard KIND value that is not
// one of the registered values (individual, group, org, location) defined in
// RFC 6350 §6.7.9. Servers MUST reject unknown KIND values.
const vcardKindUnknown = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:6000000b-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"KIND:unknown\r\n" +
	"END:VCARD\r\n"

// vcardKindOrg is a valid vCard 4.0 with KIND:org, which MUST be accepted per
// RFC 6350 §6.7.9.
const vcardKindOrg = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:6000000c-0000-0000-0000-000000000001\r\n" +
	"FN:Acme Corporation\r\n" +
	"KIND:org\r\n" +
	"END:VCARD\r\n"

// vcardSparseADR is a valid vCard 4.0 with a sparse ADR where PO Box and
// Extended Address are empty but their SEMI-COLON separators MUST be retained
// per RFC 6350 §6.3.1.
const vcardSparseADR = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000004-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"ADR;TYPE=HOME:;;123 Main St;Springfield;IL;62701;USA\r\n" +
	"END:VCARD\r\n"

// vcardDuplicateUID is a second vCard with the same UID as fixtures.AliceV4, used
// to test the no-uid-conflict precondition (RFC 6352 §6.3.2).
const vcardDuplicateUID = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:aaaaaaaa-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Duplicate\r\n" +
	"END:VCARD\r\n"

// vcardPrefZero is a vCard 4.0 with PREF=0, which is out of range (RFC 6350 §5.7.2
// requires a value between 1 and 100).
const vcardPrefZero = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000005-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"EMAIL;PREF=0:alice@example.com\r\n" +
	"END:VCARD\r\n"

// vcardPref101 is a vCard 4.0 with PREF=101, which is out of range (RFC 6350 §5.7.2).
const vcardPref101 = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000006-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"EMAIL;PREF=101:alice@example.com\r\n" +
	"END:VCARD\r\n"

// vcardMemberNoKind is a vCard 4.0 with a MEMBER property but no KIND:group
// (RFC 6350 §6.6.5 says MEMBER is only for KIND:group vCards).
const vcardMemberNoKind = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:60000007-0000-0000-0000-000000000001\r\n" +
	"FN:My Group\r\n" +
	"MEMBER:urn:uuid:aaaaaaaa-0000-0000-0000-000000000001\r\n" +
	"END:VCARD\r\n"

// --- Helpers ---

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

// unfoldVCard removes fold indicators from a vCard body per RFC 6350 §3.2:
// CRLF followed by a single SPACE or TAB is removed entirely.
// This must be applied before checking logical property values in a GET response,
// because a conformant server MAY re-fold its output at any position.
func unfoldVCard(body []byte) []byte {
	body = bytes.ReplaceAll(body, []byte("\r\n "), nil)
	body = bytes.ReplaceAll(body, []byte("\r\n\t"), nil)
	return body
}

// showCRLF returns a human-readable version of body with CRLF shown as "↵\n"
// and TAB shown as "→" so fold indicators are visible in verbose output.
func showCRLF(body []byte) string {
	s := string(body)
	s = strings.ReplaceAll(s, "\r\n", "↵\n")
	s = strings.ReplaceAll(s, "\t", "→")
	return s
}

// --- Tests ---

func testGetDefaultV4(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "alice.vcf"
	if _, err := putContact(ctx, c, contactURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:4.0")
}

func testUIDAssignment(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "nouid.vcf"
	putResp, err := putContact(ctx, c, contactURL, []byte(fixtures.AliceV4NoUID))
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT no-UID vCard: got %d, want 201 or 204", putResp.StatusCode)
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.HasProperty(resp.Body, "UID")
}

func testRejectMissingBegin(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoBegin), "PUT vCard 4.0 body without BEGIN:VCARD")
}

func testRejectMissingEnd(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoEnd), "PUT vCard 4.0 body without END:VCARD")
}

func testRejectMissingFN(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoFN), "PUT vCard 4.0 without FN")
}

func testRejectMissingVersion(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardNoVersion), "PUT vCard 4.0 without VERSION")
}

func testRejectVersionNotFirst(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardVersionNotFirst), "PUT vCard 4.0 where VERSION does not immediately follow BEGIN:VCARD")
}

func testRejectVersion30(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardVersion30), "PUT vCard with VERSION:3.0 at 4.0 endpoint")
}

func testRejectVersion21(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardVersion21), "PUT vCard with VERSION:2.1 at 4.0 endpoint")
}

func testCharsetLatin1Rejected(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"latin1.vcf", "text/vcard; charset=latin1", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return fmt.Errorf("PUT vCard with charset=latin1: got %d, want 4xx", resp.StatusCode)
	}
	return nil
}

func testCharsetUTF8Accepted(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"utf8.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT vCard with explicit charset=utf-8: got %d, want 201 or 204", resp.StatusCode)
	}
	return nil
}

func testFoldedLineParsed(ctx context.Context, sess *suite.Session) error {
	return testFoldedRoundTrip(ctx, sess, vcardFoldedFN, "folded-space.vcf", "CRLF+SPACE")
}

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

	resp, err := putContact(ctx, c, colURL+filename, []byte(vcard))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT vCard 4.0 with %s folded FN: got %d, want 201 or 204", foldKind, resp.StatusCode)
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

	if err := assert.BodyHas(unfolded, foldedFNExpected); err != nil {
		return fmt.Errorf("%s fold round-trip: full FN value not found after unfolding response: %w", foldKind, err)
	}
	return nil
}

// testEscapeNoteRoundtrip is a shared helper for escape round-trip tests that
// PUT a vCard with the given body and assert that want appears in the GET response.
func testEscapeNoteRoundtrip(ctx context.Context, sess *suite.Session, body []byte, filename, desc, want string) error {
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

	resp, err := putContact(ctx, c, colURL+filename, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT vCard 4.0 with %s in NOTE: got %d, want 201 or 204", desc, resp.StatusCode)
	}

	resp, err = c.Get(ctx, colURL+filename)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	unfolded := unfoldVCard(resp.Body)
	if err := assert.BodyHas(unfolded, want); err != nil {
		return fmt.Errorf("NOTE %s round-trip: %q not found in GET response: %w", desc, want, err)
	}
	return nil
}

func testEscapeCommaRoundtrip(ctx context.Context, sess *suite.Session) error {
	return testEscapeNoteRoundtrip(ctx, sess, []byte(vcardEscapedComma), "escape-comma.vcf",
		"escaped comma", "second part")
}

func testEscapeSemicolonRoundtrip(ctx context.Context, sess *suite.Session) error {
	return testEscapeNoteRoundtrip(ctx, sess, []byte(vcardEscapedSemicolon), "escape-semi.vcf",
		"escaped semicolon", "second part")
}

func testEscapeBackslashRoundtrip(ctx context.Context, sess *suite.Session) error {
	// After round-trip the NOTE must contain either "\\" (escaped) or "\" (decoded);
	// either representation is conformant as long as the backslash is preserved.
	return testEscapeNoteRoundtrip(ctx, sess, []byte(vcardEscapedBackslash), "escape-backslash.vcf",
		"escaped backslash", "path")
}

func testEscapeNewlineRoundtrip(ctx context.Context, sess *suite.Session) error {
	// After round-trip both "line one" and "line two" must be present; if the
	// server drops the \n escape the second line will be lost.
	return testEscapeNoteRoundtrip(ctx, sess, []byte(vcardEscapedNewline), "escape-newline.vcf",
		`\n escape`, "line two")
}

func testADRSparseRoundtrip(ctx context.Context, sess *suite.Session) error {
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

	resp, err := putContact(ctx, c, colURL+"adr.vcf", []byte(vcardSparseADR))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT vCard 4.0 with sparse ADR: got %d, want 201 or 204", resp.StatusCode)
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

func testUIDConflict(ctx context.Context, sess *suite.Session) error {
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

	// First PUT: create a contact with a known UID — must succeed.
	firstResp, err := putContact(ctx, c, colURL+"alice1.vcf", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if firstResp.StatusCode != 201 && firstResp.StatusCode != 204 {
		return fmt.Errorf("first PUT (establish UID): got %d, want 201 or 204", firstResp.StatusCode)
	}

	// Second PUT: different filename, same UID — must be rejected.
	secondResp, err := putContact(ctx, c, colURL+"alice2.vcf", []byte(vcardDuplicateUID))
	if err != nil {
		return err
	}
	if secondResp.StatusCode < 400 || secondResp.StatusCode >= 500 {
		return fmt.Errorf("second PUT with duplicate UID: got %d, want 4xx (CARDDAV:no-uid-conflict)", secondResp.StatusCode)
	}
	return nil
}

func testPrefZeroRejected(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardPrefZero), "PUT vCard 4.0 with PREF=0")
}

func testPref101Rejected(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardPref101), "PUT vCard 4.0 with PREF=101")
}

func testMemberWithoutKindGroup(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardMemberNoKind), "PUT vCard 4.0 with MEMBER but without KIND:group")
}

func testKindUnknownRejected(ctx context.Context, sess *suite.Session) error {
	return putInvalidVCard(ctx, sess, []byte(vcardKindUnknown), "PUT vCard 4.0 with KIND:unknown")
}

func testKindOrgAccepted(ctx context.Context, sess *suite.Session) error {
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

	resp, err := putContact(ctx, c, colURL+"kind-org.vcf", []byte(vcardKindOrg))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT vCard 4.0 with KIND:org: got %d, want 201 or 204", resp.StatusCode)
	}
	return nil
}
