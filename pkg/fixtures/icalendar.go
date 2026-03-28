package fixtures

// EventAlice is a minimal valid iCalendar VEVENT for the primary test principal.
const EventAlice = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:e1000000-0000-0000-0000-000000000001\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Alice Test Event\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// EventBob is a minimal valid iCalendar VEVENT for the secondary test principal.
const EventBob = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:e2000000-0000-0000-0000-000000000001\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"DTSTART:20240601T120000Z\r\n" +
	"DTEND:20240601T130000Z\r\n" +
	"SUMMARY:Bob Test Event\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// EventAliceUpdated is EventAlice with an updated SUMMARY and DTSTAMP and the
// same UID. Used to force an ETag change without triggering no-uid-conflict errors.
const EventAliceUpdated = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:urn:uuid:e1000000-0000-0000-0000-000000000001\r\n" +
	"DTSTAMP:20240102T000000Z\r\n" +
	"DTSTART:20240601T100000Z\r\n" +
	"DTEND:20240601T110000Z\r\n" +
	"SUMMARY:Alice Test Event Updated\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// TodoAlice is a minimal valid iCalendar VTODO for the primary test principal.
const TodoAlice = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//davlint//davlint//EN\r\n" +
	"BEGIN:VTODO\r\n" +
	"UID:urn:uuid:t1000000-0000-0000-0000-000000000001\r\n" +
	"DTSTAMP:20240101T000000Z\r\n" +
	"SUMMARY:Alice Test Todo\r\n" +
	"END:VTODO\r\n" +
	"END:VCALENDAR\r\n"
