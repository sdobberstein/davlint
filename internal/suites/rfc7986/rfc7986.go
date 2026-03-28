// Package rfc7986 registers conformance tests for new iCalendar properties
// defined in RFC 7986 (New Properties for iCalendar).
//
// All tests follow a PUT/GET round-trip pattern: store a calendar object
// containing an RFC 7986 property, retrieve it, and verify the property
// survived. RFC 4791 §5.3.2 requires servers not to alter stored calendar
// objects, so round-trip preservation is a MUST regardless of whether the
// server implements RFC 7986 natively.
//
// Covered: COLOR (component-level), NAME (VCALENDAR-level), DESCRIPTION
// (VCALENDAR-level), URL (VCALENDAR-level), CONFERENCE (component-level).
//
// Deferred: IMAGE (requires binary encoding), REFRESH-INTERVAL (server-side
// scheduling behavior; not observable via HTTP).
package rfc7986

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
	// §5.4 / §6: COLOR on a VEVENT component MUST survive PUT/GET round-trip.
	suite.Register(suite.Test{
		ID:            "rfc7986.color-vevent-roundtrip",
		Suite:         "rfc7986",
		Description:   "PUT VEVENT with COLOR property; GET returns COLOR (RFC 7986 §5.4 / RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 7986", Section: "§5.4", URL: "https://www.rfc-editor.org/rfc/rfc7986#section-5.4"},
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testColorVEventRoundtrip,
	})
	// §5.1: NAME at the VCALENDAR level MUST survive PUT/GET round-trip.
	suite.Register(suite.Test{
		ID:            "rfc7986.name-vcalendar-roundtrip",
		Suite:         "rfc7986",
		Description:   "PUT VCALENDAR with NAME property; GET returns NAME (RFC 7986 §5.1 / RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 7986", Section: "§5.1", URL: "https://www.rfc-editor.org/rfc/rfc7986#section-5.1"},
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testNameVCalendarRoundtrip,
	})
	// §4: DESCRIPTION at the VCALENDAR level (RFC 7986 extension) MUST survive PUT/GET.
	suite.Register(suite.Test{
		ID:            "rfc7986.description-vcalendar-roundtrip",
		Suite:         "rfc7986",
		Description:   "PUT VCALENDAR with DESCRIPTION property; GET returns DESCRIPTION (RFC 7986 §4 / RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 7986", Section: "§4", URL: "https://www.rfc-editor.org/rfc/rfc7986#section-4"},
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testDescriptionVCalendarRoundtrip,
	})
	// §4: URL at the VCALENDAR level MUST survive PUT/GET round-trip.
	suite.Register(suite.Test{
		ID:            "rfc7986.url-vcalendar-roundtrip",
		Suite:         "rfc7986",
		Description:   "PUT VCALENDAR with URL property; GET returns URL (RFC 7986 §4 / RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 7986", Section: "§4", URL: "https://www.rfc-editor.org/rfc/rfc7986#section-4"},
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testURLVCalendarRoundtrip,
	})
	// §6.1: CONFERENCE on a VEVENT MUST survive PUT/GET round-trip.
	suite.Register(suite.Test{
		ID:            "rfc7986.conference-vevent-roundtrip",
		Suite:         "rfc7986",
		Description:   "PUT VEVENT with CONFERENCE property; GET returns CONFERENCE (RFC 7986 §6.1 / RFC 4791 §5.3.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 7986", Section: "§6.1", URL: "https://www.rfc-editor.org/rfc/rfc7986#section-6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2"},
		},
		Fn: testConferenceVEventRoundtrip,
	})
}

// --- Fixtures ---

// eventWithColor: a VEVENT containing the RFC 7986 COLOR property.
const eventWithColor = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r7986-color@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Color Test Event\r\n" +
	"COLOR:red\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// eventWithVCalendarName: a VCALENDAR with the RFC 7986 NAME property at the
// calendar level (not inside a component).
const eventWithVCalendarName = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"NAME:davlint Test Calendar\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r7986-name@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Name Test Event\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// eventWithVCalendarDescription: a VCALENDAR with DESCRIPTION at the calendar
// level (RFC 7986 §4 extends VCALENDAR to allow DESCRIPTION).
const eventWithVCalendarDescription = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"DESCRIPTION:A calendar used for davlint conformance testing.\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r7986-description@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Description Test Event\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// eventWithVCalendarURL: a VCALENDAR with URL at the calendar level.
const eventWithVCalendarURL = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"URL:https://example.com/davlint-test-calendar\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r7986-url@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:URL Test Event\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// eventWithConference: a VEVENT containing the RFC 7986 CONFERENCE property.
const eventWithConference = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r7986-conference@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Conference Test Event\r\n" +
	"CONFERENCE;VALUE=URI;FEATURE=VIDEO:https://example.com/meeting/davlint\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// --- Helpers ---

func discoverCalendarHome(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.CalendarHomeSetURL(ctx, c, principalURL)
}

func makeTestCalendar(ctx context.Context, c *client.Client, calHome string) (string, func(context.Context), error) { //nolint:gocritic
	calURL := fmt.Sprintf("%sdavlint-rfc7986-%08x/", calHome, rand.Uint32()) // #nosec G404
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

// putAndGet PUTs body to url with text/calendar Content-Type, then GETs and
// returns the response body. Fails if the PUT or GET does not succeed.
func putAndGet(ctx context.Context, c *client.Client, url string, body []byte) ([]byte, error) {
	putResp, err := c.Put(ctx, url, "text/calendar; charset=utf-8", body)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", url, err)
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return nil, fmt.Errorf("PUT %s: got %d, want 201 or 204", url, putResp.StatusCode)
	}
	getResp, err := c.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if err := assert.StatusCode(getResp, 200); err != nil {
		return nil, err
	}
	return getResp.Body, nil
}

// roundtripCheck creates a test calendar, PUTs body, GETs the resource, and
// asserts that want appears in the response body.
func roundtripCheck(ctx context.Context, sess *suite.Session, body []byte, filename, want string) error {
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

	got, err := putAndGet(ctx, c, calURL+filename, body)
	if err != nil {
		return err
	}
	return assert.BodyHas(got, want)
}

// --- Tests ---

func testColorVEventRoundtrip(ctx context.Context, sess *suite.Session) error {
	return roundtripCheck(ctx, sess, []byte(eventWithColor), "color.ics", "COLOR")
}

func testNameVCalendarRoundtrip(ctx context.Context, sess *suite.Session) error {
	return roundtripCheck(ctx, sess, []byte(eventWithVCalendarName), "name.ics", "NAME:davlint Test Calendar")
}

func testDescriptionVCalendarRoundtrip(ctx context.Context, sess *suite.Session) error {
	return roundtripCheck(ctx, sess, []byte(eventWithVCalendarDescription), "description.ics", "DESCRIPTION:A calendar")
}

func testURLVCalendarRoundtrip(ctx context.Context, sess *suite.Session) error {
	return roundtripCheck(ctx, sess, []byte(eventWithVCalendarURL), "url.ics", "URL:https://example.com/davlint-test-calendar")
}

func testConferenceVEventRoundtrip(ctx context.Context, sess *suite.Session) error {
	return roundtripCheck(ctx, sess, []byte(eventWithConference), "conference.ics", "CONFERENCE")
}
