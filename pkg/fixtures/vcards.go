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

// AliceV4NoUID is AliceV4 without the UID property, for testing server-side UID assignment.
const AliceV4NoUID = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"FN:Alice Test\r\n" +
	"N:Test;Alice;;;\r\n" +
	"EMAIL;TYPE=work:alice@example.com\r\n" +
	"END:VCARD\r\n"

// LargePhotoV4 returns a vCard 4.0 with an inline PHOTO that exceeds 250 KB decoded.
// The base64 data is ~342 KB of repeated 'A', which decodes to ~256 KB.
func LargePhotoV4() string {
	// 341336 base64 chars × 3/4 ≈ 256002 bytes > 250 KB
	photoData := repeatString("AAAA", 85334) // 85334 × 4 = 341336 chars
	return "BEGIN:VCARD\r\n" +
		"VERSION:4.0\r\n" +
		"UID:urn:uuid:cccccccc-0000-0000-0000-000000000001\r\n" +
		"FN:Large Photo Test\r\n" +
		"PHOTO:data:image/jpeg;base64," + photoData + "\r\n" +
		"END:VCARD\r\n"
}

func repeatString(s string, n int) string {
	b := make([]byte, len(s)*n)
	for i := 0; i < n; i++ {
		copy(b[i*len(s):], s)
	}
	return string(b)
}
