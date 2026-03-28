// Package rfc5545 registers iCalendar format conformance tests (RFC 5545).
//
// Covers: required VCALENDAR properties (VERSION, PRODID), required VEVENT
// properties (UID, DTSTAMP), exclusive property constraints (DTEND/DURATION,
// DUE/DURATION), RRULE UNTIL+COUNT exclusivity, VTIMEZONE presence when
// referenced, METHOD property rejection, and VALARM required properties
// (ACTION, TRIGGER).
//
// All invalid-data tests rely on the CalDAV server enforcing RFC 5545 grammar
// via the CALDAV:valid-calendar-data precondition (RFC 4791 §5.3.2.1).
package rfc5545

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/fixtures"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	// §3.4 / §3.6.1: A valid VCALENDAR with a VEVENT MUST be accepted.
	suite.Register(suite.Test{
		ID:            "rfc5545.valid-vevent-accepted",
		Suite:         "rfc5545",
		Description:   "PUT a valid VCALENDAR+VEVENT is accepted by the server (RFC 5545 §3.6.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testValidVEventAccepted,
	})
	// §3.6.2: A valid VCALENDAR with a VTODO MUST be accepted.
	suite.Register(suite.Test{
		ID:            "rfc5545.vtodo-valid-accepted",
		Suite:         "rfc5545",
		Description:   "PUT a valid VCALENDAR+VTODO is accepted by the server (RFC 5545 §3.6.2 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.2", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.2"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVTodoValidAccepted,
	})
	// §3.7.4: VERSION is REQUIRED in VCALENDAR.
	suite.Register(suite.Test{
		ID:            "rfc5545.vcalendar-missing-version",
		Suite:         "rfc5545",
		Description:   "PUT VCALENDAR without VERSION is rejected with 4xx (RFC 5545 §3.7.4 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.7.4", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.7.4"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVCalendarMissingVersion,
	})
	// §3.7.3: PRODID is REQUIRED in VCALENDAR.
	suite.Register(suite.Test{
		ID:            "rfc5545.vcalendar-missing-prodid",
		Suite:         "rfc5545",
		Description:   "PUT VCALENDAR without PRODID is rejected with 4xx (RFC 5545 §3.7.3 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.7.3", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.7.3"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVCalendarMissingProdid,
	})
	// §3.6.1: UID is REQUIRED in VEVENT.
	suite.Register(suite.Test{
		ID:            "rfc5545.vevent-missing-uid",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT without UID is rejected with 4xx (RFC 5545 §3.6.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVEventMissingUID,
	})
	// §3.6.1: DTSTAMP is REQUIRED in VEVENT.
	suite.Register(suite.Test{
		ID:            "rfc5545.vevent-missing-dtstamp",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT without DTSTAMP is rejected with 4xx (RFC 5545 §3.6.1 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVEventMissingDTSTAMP,
	})
	// §3.6.1: DTEND and DURATION MUST NOT both appear in a VEVENT.
	suite.Register(suite.Test{
		ID:            "rfc5545.vevent-dtend-duration-exclusive",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT with both DTEND and DURATION is rejected with 4xx (RFC 5545 §3.6.1 MUST NOT)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVEventDTENDDurationExclusive,
	})
	// §3.6.1: DTSTART value type and DTEND value type SHOULD match (both DATE-TIME or both DATE).
	suite.Register(suite.Test{
		ID:            "rfc5545.vevent-dtstart-dtend-type-mismatch",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT with DATE DTSTART and DATE-TIME DTEND is rejected (RFC 5545 §3.6.1 SHOULD)",
		Severity:      suite.Should,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.1", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVEventDTStartDTEndTypeMismatch,
	})
	// §3.6.5: VTIMEZONE MUST be present when its TZID is referenced.
	suite.Register(suite.Test{
		ID:            "rfc5545.vtimezone-referenced-but-missing",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT referencing a TZID without a matching VTIMEZONE is rejected (RFC 5545 §3.6.5 MUST)",
		Severity:      suite.Should,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.5", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.5"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVTimezoneReferencedButMissing,
	})
	// §3.6.2: VTODO DUE and DURATION MUST NOT both appear.
	suite.Register(suite.Test{
		ID:            "rfc5545.vtodo-due-duration-exclusive",
		Suite:         "rfc5545",
		Description:   "PUT VTODO with both DUE and DURATION is rejected with 4xx (RFC 5545 §3.6.2 MUST NOT)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.2", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.2"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVTodoDueDurationExclusive,
	})
	// §3.8.5.3: RRULE UNTIL and COUNT MUST NOT both appear.
	suite.Register(suite.Test{
		ID:            "rfc5545.rrule-until-count-exclusive",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT with RRULE containing both UNTIL and COUNT is rejected (RFC 5545 §3.8.5.3 MUST NOT)",
		Severity:      suite.Should,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.8.5.3", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.8.5.3"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testRRuleUntilCountExclusive,
	})
	// §3.6.6: ACTION is REQUIRED in VALARM.
	suite.Register(suite.Test{
		ID:            "rfc5545.valarm-missing-action",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT with VALARM missing ACTION is rejected with 4xx (RFC 5545 §3.6.6 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.6", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.6"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVAlarmMissingAction,
	})
	// §3.6.6: TRIGGER is REQUIRED in VALARM.
	suite.Register(suite.Test{
		ID:            "rfc5545.valarm-missing-trigger",
		Suite:         "rfc5545",
		Description:   "PUT VEVENT with VALARM missing TRIGGER is rejected with 4xx (RFC 5545 §3.6.6 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"icalendar"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 5545", Section: "§3.6.6", URL: "https://www.rfc-editor.org/rfc/rfc5545#section-3.6.6"},
			{RFC: "RFC 4791", Section: "§5.3.2.1", URL: "https://www.rfc-editor.org/rfc/rfc4791#section-5.3.2.1"},
		},
		Fn: testVAlarmMissingTrigger,
	})
}

// --- Invalid iCalendar fixtures ---

const icalNoVersion = "BEGIN:VCALENDAR\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-no-version@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

const icalNoProdid = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-no-prodid@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

const icalNoUID = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

const icalNoDTSTAMP = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-no-dtstamp@davlint\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

const icalDTENDAndDuration = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-dtend-duration@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"DURATION:PT1H\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// icalDTStartDTEndTypeMismatch: DTSTART is a DATE (no time), DTEND is a DATE-TIME.
// RFC 5545 §3.6.1: "The value type of DTEND MUST be the same as the value type of DTSTART."
const icalDTStartDTEndTypeMismatch = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-type-mismatch@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART;VALUE=DATE:20240601\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// icalTZIDWithoutVTIMEZONE: DTSTART references America/New_York but no VTIMEZONE is included.
const icalTZIDWithoutVTIMEZONE = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-tzid-missing@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART;TZID=America/New_York:20240601T100000\r\n" +
	"DTEND;TZID=America/New_York:20240601T110000\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// icalVTodoDueDuration: VTODO with both DUE and DURATION.
const icalVTodoDueDuration = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VTODO\r\n" +
	"UID:urn:uuid:r5545-due-duration@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DUE:20240601T110000Z\r\n" +
	"DURATION:PT1H\r\n" +
	"END:VTODO\r\n" +
	"END:VCALENDAR\r\n"

// icalRRuleUntilCount: RRULE with both UNTIL and COUNT.
const icalRRuleUntilCount = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-rrule-until-count@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"RRULE:FREQ=DAILY;UNTIL=20240630T000000Z;COUNT=5\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// icalVAlarmNoAction: VALARM without ACTION.
const icalVAlarmNoAction = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-valarm-no-action@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"BEGIN:VALARM\r\n" +
	"TRIGGER:-PT15M\r\n" +
	"END:VALARM\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// icalVAlarmNoTrigger: VALARM without TRIGGER.
const icalVAlarmNoTrigger = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:r5545-valarm-no-trigger@davlint\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"BEGIN:VALARM\r\n" +
	"ACTION:DISPLAY\r\n" +
	"DESCRIPTION:Reminder\r\n" +
	"END:VALARM\r\n" +
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
	calURL := fmt.Sprintf("%sdavlint-rfc5545-%08x/", calHome, rand.Uint32()) // #nosec G404
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

// putInvalidICal creates a test calendar, PUTs the given body, and asserts
// that the server rejects it with a 4xx status code.
func putInvalidICal(ctx context.Context, sess *suite.Session, body []byte, description string) error {
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

	resp, err := c.Put(ctx, calURL+"invalid.ics", "text/calendar; charset=utf-8", body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 400 {
		return fmt.Errorf("%s: got %d, want 4xx", description, resp.StatusCode)
	}
	return nil
}

// --- Tests ---

func testValidVEventAccepted(ctx context.Context, sess *suite.Session) error {
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
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT valid VEVENT: got %d, want 201 or 204", resp.StatusCode)
	}
	return nil
}

func testVTodoValidAccepted(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, calURL+"todo.ics", "text/calendar; charset=utf-8", []byte(fixtures.TodoAlice))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT valid VTODO: got %d, want 201 or 204", resp.StatusCode)
	}
	return nil
}

func testVCalendarMissingVersion(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalNoVersion), "VCALENDAR missing VERSION")
}

func testVCalendarMissingProdid(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalNoProdid), "VCALENDAR missing PRODID")
}

func testVEventMissingUID(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalNoUID), "VEVENT missing UID")
}

func testVEventMissingDTSTAMP(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalNoDTSTAMP), "VEVENT missing DTSTAMP")
}

func testVEventDTENDDurationExclusive(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalDTENDAndDuration), "VEVENT with both DTEND and DURATION")
}

func testVEventDTStartDTEndTypeMismatch(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalDTStartDTEndTypeMismatch), "VEVENT DTSTART/DTEND value type mismatch")
}

func testVTimezoneReferencedButMissing(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalTZIDWithoutVTIMEZONE), "VEVENT TZID referenced without VTIMEZONE")
}

func testVTodoDueDurationExclusive(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalVTodoDueDuration), "VTODO with both DUE and DURATION")
}

func testRRuleUntilCountExclusive(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalRRuleUntilCount), "VEVENT RRULE with both UNTIL and COUNT")
}

func testVAlarmMissingAction(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalVAlarmNoAction), "VALARM missing ACTION")
}

func testVAlarmMissingTrigger(ctx context.Context, sess *suite.Session) error {
	return putInvalidICal(ctx, sess, []byte(icalVAlarmNoTrigger), "VALARM missing TRIGGER")
}

