// Package rfc4791 registers CalDAV core conformance tests (RFC 4791).
//
// Covers: calendar collection creation (MKCALENDAR), collection resource type,
// PUT/GET/ETag semantics for calendar objects, CalDAV PUT preconditions
// (valid-calendar-data, no-uid-conflict, supported-calendar-data, method-rejected),
// supported-report-set, calendar-query, calendar-multiget, and free-busy-query.
//
// All resource URLs are discovered dynamically via the RFC 6764 → RFC 4791 chain.
// No server-specific paths are assumed.
package rfc4791

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
	// §5.1: A CalDAV server MUST include "calendar-access" in the DAV response header.
	suite.Register(suite.Test{
		ID:            "rfc4791.options-calendar-access",
		Suite:         "rfc4791",
		Description:   "OPTIONS response includes 'calendar-access' in the DAV header (RFC 4791 §5.1 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.1"},
		},
		Fn: testOptionsCalendarAccess,
	})
	// §6.2.1: Principal MUST have a caldav:calendar-home-set property.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-home-set",
		Suite:         "rfc4791",
		Description:   "PROPFIND on principal URL returns caldav:calendar-home-set (RFC 4791 §6.2.1 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§6.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-6.2.1"},
		},
		Fn: testCalendarHomeSet,
	})
	// §5.3.1: MKCALENDAR creates a calendar collection (201 Created).
	suite.Register(suite.Test{
		ID:            "rfc4791.mkcalendar-creates",
		Suite:         "rfc4791",
		Description:   "MKCALENDAR on a new path creates a calendar collection (RFC 4791 §5.3.1 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.1"},
		},
		Fn: testMkcalendarCreates,
	})
	// §4.2: A calendar collection MUST have DAV:collection and CALDAV:calendar in its resourcetype.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-resourcetype",
		Suite:         "rfc4791",
		Description:   "PROPFIND on a calendar collection returns CALDAV:calendar in DAV:resourcetype (RFC 4791 §4.2 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§4.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-4.2"},
		},
		Fn: testCalendarResourcetype,
	})
	// §4.2: Calendar collections MUST NOT be nested within other calendar collections.
	suite.Register(suite.Test{
		ID:            "rfc4791.no-nested-calendars",
		Suite:         "rfc4791",
		Description:   "MKCALENDAR inside a calendar collection is rejected (RFC 4791 §4.2 MUST NOT)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§4.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-4.2"},
		},
		Fn: testNoNestedCalendars,
	})
	// §5.3.2: PUT a new calendar object resource returns 201 Created.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-event-creates",
		Suite:         "rfc4791",
		Description:   "PUT a valid iCalendar object to a new URL returns 201 Created (RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testPutEventCreates,
	})
	// §5.3.2: PUT to an existing calendar object resource returns 204 No Content.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-event-updates",
		Suite:         "rfc4791",
		Description:   "PUT to an existing calendar object URL returns 204 No Content (RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testPutEventUpdates,
	})
	// §5.3.2: GET on a stored calendar object returns the UID in the response body.
	suite.Register(suite.Test{
		ID:            "rfc4791.get-event-roundtrip",
		Suite:         "rfc4791",
		Description:   "GET on a stored calendar object returns the UID (RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testGetEventRoundtrip,
	})
	// §5.3.4: Server MUST return a strong ETag on GET of a calendar object resource.
	suite.Register(suite.Test{
		ID:            "rfc4791.etag-on-get",
		Suite:         "rfc4791",
		Description:   "GET on a calendar object resource returns a strong ETag header (RFC 4791 §5.3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"conditional"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.4", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.4"},
		},
		Fn: testETagOnGet,
	})
	// §5.3.4: ETag MUST change when the calendar object resource is modified.
	suite.Register(suite.Test{
		ID:            "rfc4791.etag-changes-on-put",
		Suite:         "rfc4791",
		Description:   "ETag changes after a PUT that modifies a calendar object resource (RFC 4791 §5.3.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"conditional"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.4", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.4"},
		},
		Fn: testETagChangesOnPut,
	})
	// §5.3.2.1: PUT with invalid iCalendar data returns 4xx with CALDAV:valid-calendar-data.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-valid-calendar-data",
		Suite:         "rfc4791",
		Description:   "PUT invalid iCalendar returns 4xx with CALDAV:valid-calendar-data precondition (RFC 4791 §5.3.2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testPutValidCalendarData,
	})
	// §5.3.2.1: PUT with duplicate UID returns 4xx with CALDAV:no-uid-conflict.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-no-uid-conflict",
		Suite:         "rfc4791",
		Description:   "PUT with a UID that already exists in the collection returns 4xx with CALDAV:no-uid-conflict (RFC 4791 §5.3.2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testPutNoUIDConflict,
	})
	// §5.3.2.1: PUT with unsupported Content-Type returns 4xx with CALDAV:supported-calendar-data.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-supported-calendar-data",
		Suite:         "rfc4791",
		Description:   "PUT with Content-Type other than text/calendar returns 4xx (RFC 4791 §5.3.2.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testPutSupportedCalendarData,
	})
	// §4.2: Calendar object resources MUST NOT include the iCalendar METHOD property.
	suite.Register(suite.Test{
		ID:            "rfc4791.put-method-rejected",
		Suite:         "rfc4791",
		Description:   "PUT iCalendar with METHOD property is rejected with 4xx (RFC 4791 §4.2 MUST NOT)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§4.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-4.2"},
		},
		Fn: testPutMethodRejected,
	})
	// §7.1: Calendar collection MUST list calendar-query and calendar-multiget in supported-report-set.
	suite.Register(suite.Test{
		ID:            "rfc4791.supported-report-set",
		Suite:         "rfc4791",
		Description:   "PROPFIND lists CALDAV:calendar-query and CALDAV:calendar-multiget in DAV:supported-report-set (RFC 4791 §7.1 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.1"},
		},
		Fn: testSupportedReportSet,
	})
	// §7.8: calendar-query REPORT with no comp-filter returns all calendar objects.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-query-all",
		Suite:         "rfc4791",
		Description:   "calendar-query REPORT with VCALENDAR comp-filter returns stored events (RFC 4791 §7.8 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.8", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.8"},
		},
		Fn: testCalendarQueryAll,
	})
	// §7.8: calendar-query REPORT with VEVENT comp-filter returns only VEVENT objects.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-query-vevent-filter",
		Suite:         "rfc4791",
		Description:   "calendar-query REPORT with VEVENT comp-filter returns matching events (RFC 4791 §7.8.5 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.8.5", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.8.5"},
		},
		Fn: testCalendarQueryVEVENTFilter,
	})
	// §7.9: calendar-multiget REPORT returns requested resources.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-multiget",
		Suite:         "rfc4791",
		Description:   "calendar-multiget REPORT returns 207 with data for each requested href (RFC 4791 §7.9 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.9", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.9"},
		},
		Fn: testCalendarMultiget,
	})
	// §7.9: calendar-multiget with a non-existent href returns 404 for that resource.
	suite.Register(suite.Test{
		ID:            "rfc4791.calendar-multiget-not-found",
		Suite:         "rfc4791",
		Description:   "calendar-multiget REPORT returns 404 in propstat for non-existent hrefs (RFC 4791 §7.9 MUST)",
		Severity:      suite.Must,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.9", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.9"},
		},
		Fn: testCalendarMultigetNotFound,
	})
	// §7.10: free-busy-query REPORT returns a VFREEBUSY component for the queried range.
	suite.Register(suite.Test{
		ID:            "rfc4791.free-busy-query",
		Suite:         "rfc4791",
		Description:   "free-busy-query REPORT returns 200 with VFREEBUSY calendar data (RFC 4791 §7.10 MUST)",
		Severity:      suite.Should,
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 4791", Section: "§7.10", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-7.10"},
		},
		Fn: testFreeBusyQuery,
	})
}

// --- Helpers ---

func discoverCalendarHome(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.CalendarHomeSetURL(ctx, c, principalURL)
}

func makeTestCalendar(ctx context.Context, c *client.Client, calHome string) (string, func(context.Context), error) { //nolint:gocritic
	calURL := fmt.Sprintf("%sdavlint-rfc4791-%08x/", calHome, rand.Uint32()) // #nosec G404
	resp, err := c.Mkcalendar(ctx, calURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("MKCALENDAR %s: %w", calURL, err)
	}
	if resp.StatusCode != 201 {
		return "", nil, fmt.Errorf("MKCALENDAR %s: got %d, want 201", calURL, resp.StatusCode)
	}
	cleanup := func(ctx context.Context) {
		_, _ = c.Delete(ctx, calURL, "") //nolint:errcheck // best-effort cleanup
	}
	return calURL, cleanup, nil
}

func putEvent(ctx context.Context, c *client.Client, u string, body []byte) error {
	resp, err := c.Put(ctx, u, "text/calendar; charset=utf-8", body)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", u, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT %s: got %d, want 201 or 204", u, resp.StatusCode)
	}
	return nil
}

// --- Tests ---

func testOptionsCalendarAccess(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	resp, err := c.Options(ctx, sess.ContextPath)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	dav := resp.Header.Get("DAV")
	if !strings.Contains(dav, "calendar-access") {
		return fmt.Errorf("OPTIONS DAV header %q does not contain 'calendar-access' (RFC 4791 §5.1 MUST)", dav)
	}
	return nil
}

func testCalendarHomeSet(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	homeSet, err := webdav.CalendarHomeSetURL(ctx, c, principalURL)
	if err != nil {
		return err
	}
	if homeSet == "" {
		return fmt.Errorf("caldav:calendar-home-set href is empty")
	}
	return nil
}

func testMkcalendarCreates(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	calHome, err := discoverCalendarHome(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	_, cleanup, err := makeTestCalendar(ctx, c, calHome)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanup)
	return nil
}

func testCalendarResourcetype(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{{client.NSdav, "resourcetype"}})
	resp, err := c.Propfind(ctx, calURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return fmt.Errorf("parse multistatus: %w", err)
	}
	if err := assert.ResourceTypeContains(ms, calURL, client.NSdav, "collection"); err != nil {
		return fmt.Errorf("calendar collection missing DAV:collection in resourcetype: %w", err)
	}
	return assert.ResourceTypeContains(ms, calURL, client.NScaldav, "calendar")
}

func testNoNestedCalendars(ctx context.Context, sess *suite.Session) error {
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

	nestedURL := calURL + "nested/"
	resp, err := c.Mkcalendar(ctx, nestedURL, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 {
		// Best-effort cleanup of nested calendar if server incorrectly allowed it.
		_, _ = c.Delete(ctx, nestedURL, "") //nolint:errcheck // best-effort cleanup; error not actionable here
		return fmt.Errorf("MKCALENDAR inside calendar collection: got 201, want 4xx (RFC 4791 §4.2 MUST NOT)")
	}
	return nil
}

func testPutEventCreates(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, calURL+"alice.ics", "text/calendar; charset=utf-8", []byte(fixtures.EventAlice))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT new calendar object: got %d, want 201", resp.StatusCode)
	}
	return nil
}

func testPutEventUpdates(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}
	resp, err := c.Put(ctx, aliceURL, "text/calendar; charset=utf-8", []byte(fixtures.EventAliceUpdated))
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("PUT existing calendar object: got %d, want 204", resp.StatusCode)
	}
	return nil
}

func testGetEventRoundtrip(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}
	resp, err := c.Get(ctx, aliceURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "urn:uuid:e1000000-0000-0000-0000-000000000001")
}

func testETagOnGet(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}
	resp, err := c.Get(ctx, aliceURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return fmt.Errorf("GET calendar object: missing ETag header (RFC 4791 §5.3.4 MUST)")
	}
	if strings.HasPrefix(etag, "W/") {
		return fmt.Errorf("GET calendar object: ETag is weak (%q); CalDAV requires strong ETags (RFC 4791 §5.3.4)", etag)
	}
	return nil
}

func testETagChangesOnPut(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}
	resp1, err := c.Get(ctx, aliceURL)
	if err != nil {
		return err
	}
	etag1 := resp1.Header.Get("ETag")
	if etag1 == "" {
		return fmt.Errorf("first GET: missing ETag header")
	}

	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAliceUpdated)); err != nil {
		return err
	}
	resp2, err := c.Get(ctx, aliceURL)
	if err != nil {
		return err
	}
	etag2 := resp2.Header.Get("ETag")
	if etag2 == "" {
		return fmt.Errorf("second GET: missing ETag header")
	}
	if etag1 == etag2 {
		return fmt.Errorf("ETag did not change after PUT update: %q (RFC 4791 §5.3.4 MUST)", etag1)
	}
	return nil
}

func testPutValidCalendarData(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, calURL+"invalid.ics", "text/calendar; charset=utf-8", []byte("NOT VALID ICALENDAR\r\n"))
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return fmt.Errorf("PUT invalid iCalendar: got %d, want 4xx (RFC 4791 §5.3.2.1 MUST)", resp.StatusCode)
	}
	return assert.BodyContainsElement(resp.Body, client.NScaldav, "valid-calendar-data")
}

func testPutNoUIDConflict(ctx context.Context, sess *suite.Session) error {
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

	// PUT EventAlice (UID: urn:uuid:e1000000-...) at alice.ics.
	if err := putEvent(ctx, c, calURL+"alice.ics", []byte(fixtures.EventAlice)); err != nil {
		return err
	}

	// Attempt to PUT a different object with the same UID at a different URL.
	const sameUID = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"PRODID:-//davlint//davlint//EN\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:urn:uuid:e1000000-0000-0000-0000-000000000001\r\n" +
		"DTSTAMP:20240103T000000Z\r\n" +
		"DTSTART:20240701T100000Z\r\n" +
		"DTEND:20240701T110000Z\r\n" +
		"SUMMARY:Conflicting Event\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"

	resp, err := c.Put(ctx, calURL+"alice-dup.ics", "text/calendar; charset=utf-8", []byte(sameUID))
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return fmt.Errorf("PUT with duplicate UID: got %d, want 4xx (RFC 4791 §5.3.2.1 MUST)", resp.StatusCode)
	}
	return assert.BodyContainsElement(resp.Body, client.NScaldav, "no-uid-conflict")
}

func testPutSupportedCalendarData(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, calURL+"alice.ics", "text/plain", []byte(fixtures.EventAlice))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Errorf("PUT text/calendar data with Content-Type: text/plain: got %d, want 4xx (RFC 4791 §5.3.2.1 MUST)", resp.StatusCode)
	}
	return nil
}

func testPutMethodRejected(ctx context.Context, sess *suite.Session) error {
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

	const withMethod = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"PRODID:-//davlint//davlint//EN\r\n" +
		"METHOD:REQUEST\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:urn:uuid:m1000000-0000-0000-0000-000000000001\r\n" +
		"DTSTAMP:20240101T000000Z\r\n" +
		"DTSTART:20240601T100000Z\r\n" +
		"DTEND:20240601T110000Z\r\n" +
		"SUMMARY:Method Event\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"

	resp, err := c.Put(ctx, calURL+"method.ics", "text/calendar; charset=utf-8", []byte(withMethod))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Errorf("PUT iCalendar with METHOD property: got %d, want 4xx (RFC 4791 §4.2 MUST NOT)", resp.StatusCode)
	}
	return nil
}

func testSupportedReportSet(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{{client.NSdav, "supported-report-set"}})
	resp, err := c.Propfind(ctx, calURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	if err := assert.BodyContainsElement(resp.Body, client.NScaldav, "calendar-query"); err != nil {
		return fmt.Errorf("supported-report-set missing CALDAV:calendar-query: %w", err)
	}
	return assert.BodyContainsElement(resp.Body, client.NScaldav, "calendar-multiget")
}

func testCalendarQueryAll(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}

	queryBody := client.ReportCalendarQuery([][2]string{{client.NSdav, "getetag"}}, nil)
	resp, err := c.ReportWithDepth(ctx, calURL, "1", queryBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return fmt.Errorf("parse multistatus: %w", err)
	}
	return assert.PropExists(ms, aliceURL, client.NSdav, "getetag")
}

func testCalendarQueryVEVENTFilter(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}

	queryBody := client.ReportCalendarQuery(
		[][2]string{{client.NSdav, "getetag"}},
		client.CalendarQueryVEVENTFilter(),
	)
	resp, err := c.ReportWithDepth(ctx, calURL, "1", queryBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return fmt.Errorf("parse multistatus: %w", err)
	}
	return assert.PropExists(ms, aliceURL, client.NSdav, "getetag")
}

func testCalendarMultiget(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := calURL + "alice.ics"
	if err := putEvent(ctx, c, aliceURL, []byte(fixtures.EventAlice)); err != nil {
		return err
	}

	multigetBody := client.ReportCalendarMultiget(
		[][2]string{{client.NSdav, "getetag"}},
		[]string{aliceURL},
	)
	resp, err := c.ReportWithDepth(ctx, calURL, "1", multigetBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return fmt.Errorf("parse multistatus: %w", err)
	}
	return assert.PropExists(ms, aliceURL, client.NSdav, "getetag")
}

func testCalendarMultigetNotFound(ctx context.Context, sess *suite.Session) error {
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

	nonexistentURL := calURL + "nonexistent.ics"
	multigetBody := client.ReportCalendarMultiget(
		[][2]string{{client.NSdav, "getetag"}},
		[]string{nonexistentURL},
	)
	resp, err := c.ReportWithDepth(ctx, calURL, "1", multigetBody)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return fmt.Errorf("parse multistatus: %w", err)
	}
	return assert.ResponseNotFound(ms, nonexistentURL)
}

// testFreeBusyQuery verifies RFC 4791 §7.10: a free-busy-query REPORT returns
// 200 with a text/calendar body containing a VFREEBUSY component for the
// queried time range. The response is NOT a multistatus — it is a plain 200.
func testFreeBusyQuery(ctx context.Context, sess *suite.Session) error {
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

	// EventAlice has DTSTART:20240601T100000Z — query covers that range.
	if err := putEvent(ctx, c, calURL+"alice.ics", []byte(fixtures.EventAlice)); err != nil {
		return err
	}

	fbBody := client.ReportFreeBusyQuery("20240601T000000Z", "20240602T000000Z")
	resp, err := c.ReportWithDepth(ctx, calURL, "0", fbBody)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("free-busy-query: got %d, want 200 (RFC 4791 §7.10)", resp.StatusCode)
	}
	return assert.BodyHas(resp.Body, "VFREEBUSY")
}
