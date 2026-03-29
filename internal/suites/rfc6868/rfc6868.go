// Package rfc6868 registers conformance tests for caret-encoding of parameter
// values in iCalendar and vCard (RFC 6868).
//
// RFC 6868 defines three escape sequences for use in property parameter values:
//
//	^^  — literal caret (U+005E)
//	^n  — newline (U+000A)
//	^'  — double-quote (U+0022)
//
// Unknown sequences (e.g. ^x) MUST be passed through unchanged per §4.
//
// Tests follow a PUT→GET round-trip pattern and assert that the property VALUE
// (not the parameter itself) survives intact. Caret sequences appear only in
// parameter values; a parser that misreads them can corrupt the property value.
// Both vCard (addressbook) and iCalendar (calendar) surfaces are exercised.
package rfc6868

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
	// §3: ^^ represents a literal caret in a vCard parameter value.
	suite.Register(suite.Test{
		ID:            "rfc6868.vcard-caret-caret-roundtrip",
		Suite:         "rfc6868",
		Description:   "PUT vCard with ^^ in parameter value; GET returns FN value intact (RFC 6868 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-3"},
		},
		Fn: testVCardCaretCaret,
	})
	// §3: ^n represents a newline in a vCard parameter value.
	suite.Register(suite.Test{
		ID:            "rfc6868.vcard-caret-n-roundtrip",
		Suite:         "rfc6868",
		Description:   "PUT vCard with ^n in parameter value; GET returns FN value intact (RFC 6868 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-3"},
		},
		Fn: testVCardCaretN,
	})
	// §3: ^' represents a double-quote in a vCard parameter value.
	suite.Register(suite.Test{
		ID:            "rfc6868.vcard-caret-quote-roundtrip",
		Suite:         "rfc6868",
		Description:   "PUT vCard with ^' in parameter value; GET returns FN value intact (RFC 6868 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-3"},
		},
		Fn: testVCardCaretQuote,
	})
	// §4: Unknown caret sequence ^x MUST be accepted (passed through, not rejected).
	suite.Register(suite.Test{
		ID:            "rfc6868.vcard-caret-unknown-accepted",
		Suite:         "rfc6868",
		Description:   "PUT vCard with unknown ^x sequence in parameter; server accepts without 4xx (RFC 6868 §4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§4", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-4"},
		},
		Fn: testVCardCaretUnknown,
	})
	// §3: ^^ in an iCalendar parameter value.
	suite.Register(suite.Test{
		ID:            "rfc6868.icalendar-caret-caret-roundtrip",
		Suite:         "rfc6868",
		Description:   "PUT VEVENT with ^^ in parameter value; GET returns SUMMARY value intact (RFC 6868 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-3"},
		},
		Fn: testICalCaretCaret,
	})
	// §3: ^' in an iCalendar parameter value.
	suite.Register(suite.Test{
		ID:            "rfc6868.icalendar-caret-quote-roundtrip",
		Suite:         "rfc6868",
		Description:   "PUT VEVENT with ^' in parameter value; GET returns SUMMARY value intact (RFC 6868 §3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6868", Section: "§3", URL: "https://www.rfc-editor.org/rfc/rfc6868#section-3"},
		},
		Fn: testICalCaretQuote,
	})
}

// --- vCard fixtures ---
//
// Each fixture uses an X-TEST parameter on the FN property so the caret
// sequence appears in a parameter value. The FN property value ("Alice Test")
// must survive the round-trip regardless of how the server handles the
// parameter encoding.

const vcardCaretCaret = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN;X-TEST=path^^to^^file:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

const vcardCaretN = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN;X-TEST=line1^nline2:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

const vcardCaretQuote = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN;X-TEST=say^'hello^':Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

const vcardCaretUnknown = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"FN;X-TEST=bad^x:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"END:VCARD\r\n"

// --- iCalendar fixtures ---
//
// The X-TEST parameter is placed on the SUMMARY property. The SUMMARY value
// ("Caret Test") must survive the round-trip.

const icalCaretCaret = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r6868-caret-caret@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY;X-TEST=path^^to^^file:Caret Test\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

const icalCaretQuote = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r6868-caret-quote@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY;X-TEST=say^'hello^':Caret Test\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// --- Helpers ---

func discoverAddressbookHome(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

func discoverCalendarHome(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.CalendarHomeSetURL(ctx, c, principalURL)
}

func makeTestAddressbook(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic
	colURL := fmt.Sprintf("%sdavlint-rfc6868-%08x/", homeSet, rand.Uint32()) // #nosec G404
	resp, err := c.Mkcol(ctx, colURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("MKCOL %s: %w", colURL, err)
	}
	if resp.StatusCode != 201 {
		return "", nil, fmt.Errorf("MKCOL %s: got %d, want 201", colURL, resp.StatusCode)
	}
	cleanup := func(ctx context.Context) {
		_, _ = c.Delete(ctx, colURL, "") //nolint:errcheck // best-effort cleanup; error not actionable here
	}
	return colURL, cleanup, nil
}

func makeTestCalendar(ctx context.Context, c *client.Client, calHome string) (string, func(context.Context), error) { //nolint:gocritic
	calURL := fmt.Sprintf("%sdavlint-rfc6868-%08x/", calHome, rand.Uint32()) // #nosec G404
	resp, err := c.Mkcalendar(ctx, calURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("MKCALENDAR %s: %w", calURL, err)
	}
	if resp.StatusCode != 201 {
		return "", nil, fmt.Errorf("MKCALENDAR %s: got %d, want 201", calURL, resp.StatusCode)
	}
	cleanup := func(ctx context.Context) {
		_, _ = c.Delete(ctx, calURL, "") //nolint:errcheck // best-effort cleanup; error not actionable here
	}
	return calURL, cleanup, nil
}

// vcardRoundtrip PUTs a vCard, GETs it back (unfolded), and asserts want is present.
func vcardRoundtrip(ctx context.Context, sess *suite.Session, body []byte, filename, want string) error {
	c := sess.Primary()
	homeSet, err := discoverAddressbookHome(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestAddressbook(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	putResp, err := c.Put(ctx, colURL+filename, "text/vcard; charset=utf-8", body)
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT %s: got %d, want 201 or 204", colURL+filename, putResp.StatusCode)
	}
	getResp, err := c.Get(ctx, colURL+filename)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(getResp, 200); err != nil {
		return err
	}
	return assert.BodyHas(unfoldLines(getResp.Body), want)
}

// icalRoundtrip PUTs a calendar object, GETs it back, and asserts want is present.
func icalRoundtrip(ctx context.Context, sess *suite.Session, body []byte, filename, want string) error {
	c := sess.Primary()
	calHome, err := discoverCalendarHome(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	calURL, cleanup, err := makeTestCalendar(ctx, c, calHome)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	putResp, err := c.Put(ctx, calURL+filename, "text/calendar; charset=utf-8", body)
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT %s: got %d, want 201 or 204", calURL+filename, putResp.StatusCode)
	}
	getResp, err := c.Get(ctx, calURL+filename)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(getResp, 200); err != nil {
		return err
	}
	return assert.BodyHas(unfoldLines(getResp.Body), want)
}

// unfoldLines removes RFC 2425 / RFC 5545 line folding (CRLF + single space/tab)
// so that long property lines can be matched as a single string.
func unfoldLines(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+2 < len(b) && b[i+1] == '\n' && (b[i+2] == ' ' || b[i+2] == '\t') {
			i += 2 // skip CRLF + whitespace
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// --- Tests ---

func testVCardCaretCaret(ctx context.Context, sess *suite.Session) error {
	return vcardRoundtrip(ctx, sess, []byte(vcardCaretCaret), "caret-caret.vcf", "Alice Test")
}

func testVCardCaretN(ctx context.Context, sess *suite.Session) error {
	return vcardRoundtrip(ctx, sess, []byte(vcardCaretN), "caret-n.vcf", "Alice Test")
}

func testVCardCaretQuote(ctx context.Context, sess *suite.Session) error {
	return vcardRoundtrip(ctx, sess, []byte(vcardCaretQuote), "caret-quote.vcf", "Alice Test")
}

func testVCardCaretUnknown(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverAddressbookHome(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	colURL, cleanup, err := makeTestAddressbook(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)

	resp, err := c.Put(ctx, colURL+"caret-unknown.vcf", "text/vcard; charset=utf-8", []byte(vcardCaretUnknown))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("PUT vCard with unknown ^x sequence: got %d, want 2xx (RFC 6868 §4: unknown sequences MUST pass through)", resp.StatusCode)
	}
	return nil
}

func testICalCaretCaret(ctx context.Context, sess *suite.Session) error {
	return icalRoundtrip(ctx, sess, []byte(icalCaretCaret), "caret-caret.ics", "Caret Test")
}

func testICalCaretQuote(ctx context.Context, sess *suite.Session) error {
	return icalRoundtrip(ctx, sess, []byte(icalCaretQuote), "caret-quote.ics", "Caret Test")
}
