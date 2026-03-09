// Package fixtures provides pre-built vCard test data for davlint conformance tests.
package fixtures

// AliceV4 is a minimal vCard 4.0 for the primary test principal.
const AliceV4 = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:aaaaaaaa-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"EMAIL;TYPE=work:alice@example.com\r\n" +
	"END:VCARD\r\n"

// BobV4 is a minimal vCard 4.0 for the secondary test principal.
const BobV4 = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"UID:urn:uuid:bbbbbbbb-0000-0000-0000-000000000001\r\n" +
	"FN:Bob Test\r\n" +
	"N:Test;Bob;;;\r\n" +
	"EMAIL;TYPE=work:bob@example.com\r\n" +
	"END:VCARD\r\n"

// AliceV3 is AliceV4 converted to vCard 3.0 (for conversion tests).
const AliceV3 = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:aaaaaaaa-0000-0000-0000-000000000001\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"EMAIL;TYPE=INTERNET,WORK:alice@example.com\r\n" +
	"END:VCARD\r\n"

// BobV3 is BobV4 converted to vCard 3.0.
const BobV3 = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:urn:uuid:bbbbbbbb-0000-0000-0000-000000000001\r\n" +
	"FN:Bob Test\r\n" +
	"N:Test;Bob;;;\r\n" +
	"EMAIL;TYPE=INTERNET,WORK:bob@example.com\r\n" +
	"END:VCARD\r\n"
