// Package rfc6352 registers CardDAV conformance tests (RFC 6352).
//
// Tests cover the REPORT method with the two required report types:
// addressbook-query (§8.6) and addressbook-multiget (§8.7), as well as the
// supported-report-set property (§9.1) that advertises them.
//
// All resource URLs are discovered dynamically via the standard RFC 6764 →
// RFC 6352 discovery chain. No server-specific paths are assumed.
package rfc6352

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
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-report-set",
		Suite:       "rfc6352",
		Description: "PROPFIND on an address book returns D:supported-report-set advertising addressbook-query and addressbook-multiget",
		Severity:    suite.Must,
		Fn:          testSupportedReportSet,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-query-no-filter",
		Suite:       "rfc6352",
		Description: "addressbook-query REPORT with no filter returns all contacts with getetag and address-data",
		Severity:    suite.Must,
		Fn:          testAddressbookQueryNoFilter,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-query-prop-filter",
		Suite:       "rfc6352",
		Description: "addressbook-query REPORT with a C:prop-filter text-match returns only matching contacts",
		Severity:    suite.Must,
		Fn:          testAddressbookQueryPropFilter,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-multiget",
		Suite:       "rfc6352",
		Description: "addressbook-multiget REPORT returns getetag and address-data for each requested href",
		Severity:    suite.Must,
		Fn:          testAddressbookMultiget,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-multiget-not-found",
		Suite:       "rfc6352",
		Description: "addressbook-multiget REPORT returns a 404 response entry for a non-existent href",
		Severity:    suite.Must,
		Fn:          testAddressbookMultigetNotFound,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.options-addressbook-token",
		Suite:       "rfc6352",
		Description: `OPTIONS on an address book collection returns "addressbook" in the DAV response header`,
		Severity:    suite.Must,
		Fn:          testOptionsAddressbookToken,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-resourcetype",
		Suite:       "rfc6352",
		Description: "PROPFIND on an address book collection reports CARDDAV:addressbook in DAV:resourcetype",
		Severity:    suite.Must,
		Fn:          testAddressbookResourceType,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.get-etag-header",
		Suite:       "rfc6352",
		Description: "GET on an address object resource returns an ETag response header",
		Severity:    suite.Must,
		Fn:          testGetETagHeader,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.getetag-strong",
		Suite:       "rfc6352",
		Description: "ETag returned for an address object resource is a strong entity tag (no W/ prefix)",
		Severity:    suite.Must,
		Fn:          testGetETagStrong,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-etag-response",
		Suite:       "rfc6352",
		Description: "PUT response for a new address object resource includes an ETag header",
		Severity:    suite.Should,
		Fn:          testPutETagResponse,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-collation-set",
		Suite:       "rfc6352",
		Description: "PROPFIND on an address book returns CARDDAV:supported-collation-set including the two required collations",
		Severity:    suite.Must,
		Fn:          testSupportedCollationSet,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.unauthenticated-access-denied",
		Suite:       "rfc6352",
		Description: "Unauthenticated PROPFIND on an address book collection is rejected with 401 or 403",
		Severity:    suite.Must,
		Fn:          testUnauthenticatedAccessDenied,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.home-set-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on the principal does not include CARDDAV:addressbook-home-set",
		Severity:    suite.Should,
		Fn:          testHomeSetNotInAllprop,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-unsupported-media-type",
		Suite:       "rfc6352",
		Description: "PUT with an unsupported media type is rejected with CARDDAV:supported-address-data precondition",
		Severity:    suite.Must,
		Fn:          testPutUnsupportedMediaType,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-invalid-vcard",
		Suite:       "rfc6352",
		Description: "PUT with invalid vCard data is rejected with CARDDAV:valid-address-data precondition",
		Severity:    suite.Must,
		Fn:          testPutInvalidVCard,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-uid-conflict",
		Suite:       "rfc6352",
		Description: "PUT with a UID already in use is rejected with CARDDAV:no-uid-conflict precondition",
		Severity:    suite.Must,
		Fn:          testPutUIDConflict,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-max-resource-size",
		Suite:       "rfc6352",
		Description: "PUT of an oversized address object is rejected with CARDDAV:max-resource-size precondition",
		Severity:    suite.Must,
		Fn:          testPutMaxResourceSize,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.no-nested-addressbook",
		Suite:       "rfc6352",
		Description: "Creating an address book collection inside another address book collection is rejected",
		Severity:    suite.Must,
		Fn:          testNoNestedAddressbook,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.query-collation-unicode",
		Suite:       "rfc6352",
		Description: "addressbook-query with collation=i;unicode-casemap returns matching contacts only",
		Severity:    suite.Must,
		Fn:          testQueryCollationUnicode,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.query-collation-ascii",
		Suite:       "rfc6352",
		Description: "addressbook-query with collation=i;ascii-casemap returns matching contacts only",
		Severity:    suite.Must,
		Fn:          testQueryCollationASCII,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.query-unsupported-collation",
		Suite:       "rfc6352",
		Description: "addressbook-query with an unsupported collation is rejected with CARDDAV:supported-collation precondition",
		Severity:    suite.Must,
		Fn:          testQueryUnsupportedCollation,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.put-nonstandard-props",
		Suite:       "rfc6352",
		Description: "PUT an address object with non-standard X- properties is accepted and the properties are preserved on GET",
		Severity:    suite.Must,
		Fn:          testPutNonstandardProps,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.principal-address-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on the principal does not include CARDDAV:principal-address",
		Severity:    suite.Should,
		Fn:          testPrincipalAddressNotInAllprop,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.query-param-filter",
		Suite:       "rfc6352",
		Description: "addressbook-query with C:param-filter restricts results by vCard property parameter value",
		Severity:    suite.Must,
		Fn:          testQueryParamFilter,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-filter-precondition",
		Suite:       "rfc6352",
		Description: "addressbook-query referencing an unsupported filter property is rejected with CARDDAV:supported-filter precondition",
		Severity:    suite.Must,
		Fn:          testSupportedFilterPrecondition,
	})
}

// discoverHomeSet returns the addressbook-home-set URL for the primary client,
// following the RFC 6764 → RFC 6352 discovery chain.
func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

// makeTestCollection creates a uniquely-named address book collection under
// homeSet and returns the collection URL and a cleanup func that deletes it.
func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here
	colURL := fmt.Sprintf("%sdavlint-rfc6352-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

// putContact PUTs a vCard to the given URL with the text/vcard content type.
func putContact(ctx context.Context, c *client.Client, url string, body []byte) (*client.Response, error) {
	resp, err := c.Put(ctx, url, "text/vcard; charset=utf-8", body)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", url, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return nil, fmt.Errorf("PUT %s: got %d, want 201 or 204", url, resp.StatusCode)
	}
	return resp, nil
}

// --- Tests ---

// testSupportedReportSet verifies RFC 6352 §9.1: a CardDAV address book MUST
// advertise addressbook-query and addressbook-multiget in D:supported-report-set.
func testSupportedReportSet(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{
		{client.NSdav, "supported-report-set"},
	})
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, colURL, client.NSdav, "supported-report-set"); err != nil {
		return err
	}
	// Both report types MUST be advertised (RFC 6352 §9.1).
	if err := assert.BodyHas(resp.Body, "addressbook-query"); err != nil {
		return fmt.Errorf("supported-report-set missing addressbook-query: %w", err)
	}
	return assert.BodyHas(resp.Body, "addressbook-multiget")
}

// testAddressbookQueryNoFilter verifies RFC 6352 §8.6: an addressbook-query
// REPORT with no filter MUST return all address objects in the collection,
// each with the requested properties (getetag and address-data).
func testAddressbookQueryNoFilter(ctx context.Context, sess *suite.Session) error {
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

	// RFC 6352 §8.6: no C:filter element means return all address objects.
	body := client.ReportAddressbookQuery(
		[][2]string{
			{client.NSdav, "getetag"},
			{client.NScarddav, "address-data"},
		},
		nil,
	)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, contactURL, client.NSdav, "getetag"); err != nil {
		return err
	}
	if err := assert.PropExists(ms, contactURL, client.NScarddav, "address-data"); err != nil {
		return err
	}
	// RFC 6352 §10.4: C:address-data MUST contain the vCard object data.
	return assert.PropTextContains(ms, contactURL, client.NScarddav, "address-data", "FN:Alice Test")
}

// testAddressbookQueryPropFilter verifies RFC 6352 §8.6.4: a C:prop-filter
// with a C:text-match restricts results to matching address objects only.
func testAddressbookQueryPropFilter(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	bobURL := colURL + "bob.vcf"
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, bobURL, []byte(fixtures.BobV4)); err != nil {
		return err
	}

	// Filter: FN contains "Alice" (default collation i;ascii-casemap, match-type contains).
	filter := client.ReportAddressbookQueryPropFilter("FN", "Alice")
	body := client.ReportAddressbookQuery(
		[][2]string{{client.NSdav, "getetag"}},
		filter,
	)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	// alice.vcf matches; bob.vcf does not.
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("alice.vcf not returned by prop-filter: %w", err)
	}
	return assert.NoResponseFor(ms, bobURL)
}

// testAddressbookMultiget verifies RFC 6352 §8.7: an addressbook-multiget
// REPORT returns the requested properties for each specified href.
func testAddressbookMultiget(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	bobURL := colURL + "bob.vcf"
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, bobURL, []byte(fixtures.BobV4)); err != nil {
		return err
	}

	body := client.ReportAddressbookMultiget(
		[][2]string{
			{client.NSdav, "getetag"},
			{client.NScarddav, "address-data"},
		},
		[]string{aliceURL, bobURL},
	)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("alice.vcf: %w", err)
	}
	if err := assert.PropExists(ms, aliceURL, client.NScarddav, "address-data"); err != nil {
		return fmt.Errorf("alice.vcf: %w", err)
	}
	if err := assert.PropExists(ms, bobURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("bob.vcf: %w", err)
	}
	if err := assert.PropExists(ms, bobURL, client.NScarddav, "address-data"); err != nil {
		return fmt.Errorf("bob.vcf: %w", err)
	}
	// RFC 6352 §10.4: each C:address-data MUST contain the correct vCard.
	if err := assert.PropTextContains(ms, aliceURL, client.NScarddav, "address-data", "FN:Alice Test"); err != nil {
		return err
	}
	return assert.PropTextContains(ms, bobURL, client.NScarddav, "address-data", "FN:Bob Test")
}

// testOptionsAddressbookToken verifies RFC 6352 §6.1: a server MUST include
// "addressbook" as a field in the DAV response header from an OPTIONS request.
func testOptionsAddressbookToken(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Options(ctx, colURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// RFC 6352 §6.1: DAV header MUST contain "addressbook".
	return assert.HeaderContains(resp, "DAV", "addressbook")
}

// testAddressbookResourceType verifies RFC 6352 §5.2: an address book collection
// MUST report CARDDAV:addressbook in the value of the DAV:resourcetype property.
func testAddressbookResourceType(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{
		{client.NSdav, "resourcetype"},
	})
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, colURL, client.NSdav, "resourcetype"); err != nil {
		return err
	}
	// RFC 6352 §5.2: resourcetype MUST contain CARDDAV:addressbook.
	if err := assert.BodyHas(resp.Body, "addressbook"); err != nil {
		return fmt.Errorf("DAV:resourcetype does not contain CARDDAV:addressbook: %w", err)
	}
	return nil
}

// testGetETagHeader verifies RFC 6352 §6.3.2.3: a response to a GET request
// targeting an address object resource MUST contain an ETag response header.
func testGetETagHeader(ctx context.Context, sess *suite.Session) error {
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
	return assert.HeaderPresent(resp, "ETag")
}

// testGetETagStrong verifies RFC 6352 §6.3.2.3: the DAV:getetag property MUST
// be set to a strong entity tag on all address object resources. A strong ETag
// does not carry the W/ prefix defined in RFC 7232 §2.3.
func testGetETagStrong(ctx context.Context, sess *suite.Session) error {
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
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return fmt.Errorf("ETag header missing on GET response for address object resource")
	}
	if strings.HasPrefix(etag, "W/") {
		return fmt.Errorf("ETag MUST be a strong entity tag; got weak ETag %q (RFC 6352 §6.3.2.3)", etag)
	}
	return nil
}

// testPutETagResponse verifies RFC 6352 §6.3.2.3: servers SHOULD return a
// strong ETag in the PUT response when the stored address object resource is
// equivalent by octet equality to the submitted data.
func testPutETagResponse(ctx context.Context, sess *suite.Session) error {
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
	resp, err := c.Put(ctx, contactURL, "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return fmt.Errorf("PUT %s: %w", contactURL, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return fmt.Errorf("PUT: got %d, want 201 or 204", resp.StatusCode)
	}
	return assert.HeaderPresent(resp, "ETag")
}

// testSupportedCollationSet verifies RFC 6352 §8.3 and §8.3.1: servers MUST
// advertise supported collations via CARDDAV:supported-collation-set, and MUST
// support i;ascii-casemap and i;unicode-casemap.
func testSupportedCollationSet(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{
		{client.NScarddav, "supported-collation-set"},
	})
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, colURL, client.NScarddav, "supported-collation-set"); err != nil {
		return err
	}
	// RFC 6352 §8.3: servers REQUIRED to support i;ascii-casemap [RFC4790] and
	// i;unicode-casemap [RFC5051].
	if err := assert.PropTextContains(ms, colURL, client.NScarddav, "supported-collation-set", "i;ascii-casemap"); err != nil {
		return fmt.Errorf("supported-collation-set missing required collation i;ascii-casemap: %w", err)
	}
	if err := assert.PropTextContains(ms, colURL, client.NScarddav, "supported-collation-set", "i;unicode-casemap"); err != nil {
		return fmt.Errorf("supported-collation-set missing required collation i;unicode-casemap: %w", err)
	}
	return nil
}

// testUnauthenticatedAccessDenied verifies RFC 6352 §13: private and shared
// address books MUST NOT be accessible by unauthenticated users.
func testUnauthenticatedAccessDenied(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindProps([][2]string{
		{client.NSdav, "resourcetype"},
	})
	resp, err := c.PropfindNoAuth(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return fmt.Errorf("unauthenticated PROPFIND on address book: got %d, want 401 or 403 (RFC 6352 §13)", resp.StatusCode)
	}
	return nil
}

// testHomeSetNotInAllprop verifies RFC 6352 §7.1.1: CARDDAV:addressbook-home-set
// SHOULD NOT be returned by a PROPFIND DAV:allprop request.
func testHomeSetNotInAllprop(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, principalURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §7.1.1: allprop SHOULD NOT return addressbook-home-set.
	if strings.Contains(string(resp.Body), "addressbook-home-set") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:addressbook-home-set, which SHOULD NOT be included (RFC 6352 §7.1.1)")
	}
	return nil
}

// testAddressbookMultigetNotFound verifies RFC 6352 §8.7: a non-existent href
// in an addressbook-multiget request MUST produce a 404 response entry.
func testAddressbookMultigetNotFound(ctx context.Context, sess *suite.Session) error {
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

	aliceURL := colURL + "alice.vcf"
	missingURL := colURL + "missing.vcf"
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	body := client.ReportAddressbookMultiget(
		[][2]string{
			{client.NSdav, "getetag"},
			{client.NScarddav, "address-data"},
		},
		[]string{aliceURL, missingURL},
	)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	// Existing resource must be returned normally.
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("alice.vcf: %w", err)
	}
	// RFC 6352 §8.7: "If a vCard object that matches the Request-URI does not
	// exist, then the server MUST return a response for that object with a
	// DAV:status of 'HTTP/1.1 404 Not Found'."
	return assert.ResponseNotFound(ms, missingURL)
}

// testPutUnsupportedMediaType verifies RFC 6352 §6.3.2.1: a PUT request with a
// media type not listed in CARDDAV:supported-address-data MUST be rejected and
// the response MUST include the CARDDAV:supported-address-data precondition.
func testPutUnsupportedMediaType(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"alice.vcf", "text/plain; charset=utf-8", []byte("hello"))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT with text/plain media type was accepted (got %d); server MUST reject unsupported media types (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "supported-address-data") {
		return fmt.Errorf("PUT with unsupported media type: got %d but response body missing CARDDAV:supported-address-data precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testPutInvalidVCard verifies RFC 6352 §6.3.2.1: a PUT request with data that
// is not a valid vCard MUST be rejected and the response MUST include the
// CARDDAV:valid-address-data precondition.
func testPutInvalidVCard(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"invalid.vcf", "text/vcard; charset=utf-8", []byte("NOT A VCARD"))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT with invalid vCard data was accepted (got %d); server MUST reject invalid data (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "valid-address-data") {
		return fmt.Errorf("PUT with invalid vCard: got %d but response body missing CARDDAV:valid-address-data precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testPutUIDConflict verifies RFC 6352 §6.3.2.1: a PUT request whose vCard UID
// is already in use by another resource in the same address book MUST be rejected
// and the response MUST include the CARDDAV:no-uid-conflict precondition.
func testPutUIDConflict(ctx context.Context, sess *suite.Session) error {
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

	// PUT the first copy at alice.vcf — must succeed.
	if _, err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// PUT the same UID at a different path — must be rejected.
	resp, err := c.Put(ctx, colURL+"alice-copy.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT with duplicate UID was accepted (got %d); server MUST reject conflicting UIDs (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "no-uid-conflict") {
		return fmt.Errorf("PUT with duplicate UID: got %d but response body missing CARDDAV:no-uid-conflict precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testPutMaxResourceSize verifies RFC 6352 §6.3.2.1: when a server enforces a
// maximum resource size, a PUT that exceeds it MUST be rejected with the
// CARDDAV:max-resource-size precondition. If the server has no size limit the
// test passes trivially.
func testPutMaxResourceSize(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"large.vcf", "text/vcard; charset=utf-8", []byte(fixtures.LargePhotoV4()))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		// Server has no resource-size limit — requirement is not triggered.
		return nil
	}
	if !strings.Contains(string(resp.Body), "max-resource-size") {
		return fmt.Errorf("PUT of oversized resource: got %d but response body missing CARDDAV:max-resource-size precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testNoNestedAddressbook verifies RFC 6352 §5.2: collections inside an address
// book collection MUST NOT themselves be address book collections. An attempt to
// create a nested address book MUST be rejected by the server.
func testNoNestedAddressbook(ctx context.Context, sess *suite.Session) error {
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

	// Extended MKCOL (RFC 5689) requesting CARDDAV:addressbook resourcetype.
	mkcolBody := []byte(
		`<?xml version="1.0" encoding="utf-8"?>` +
			`<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">` +
			`<D:set><D:prop><D:resourcetype><D:collection/><C:addressbook/></D:resourcetype></D:prop></D:set>` +
			`</D:mkcol>`,
	)
	nestedURL := colURL + "nested/"
	resp, err := c.Mkcol(ctx, nestedURL, mkcolBody)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 {
		sess.AddCleanup(func(ctx context.Context) { _, _ = c.Delete(ctx, nestedURL, "") }) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("server accepted MKCOL creating address book inside address book (got 201); MUST be rejected (RFC 6352 §5.2)")
	}
	return nil
}

// testQueryCollationUnicode verifies RFC 6352 §8.3: a server MUST support the
// i;unicode-casemap collation in addressbook-query text-match filters.
func testQueryCollationUnicode(ctx context.Context, sess *suite.Session) error {
	return runCollationPropFilterTest(ctx, sess, "i;unicode-casemap")
}

// testQueryCollationASCII verifies RFC 6352 §8.3: a server MUST support the
// i;ascii-casemap collation in addressbook-query text-match filters.
func testQueryCollationASCII(ctx context.Context, sess *suite.Session) error {
	return runCollationPropFilterTest(ctx, sess, "i;ascii-casemap")
}

// runCollationPropFilterTest is shared logic for the two required-collation
// tests. It creates Alice and Bob, queries FN contains "Alice" with the given
// collation, and asserts Alice is returned while Bob is excluded.
func runCollationPropFilterTest(ctx context.Context, sess *suite.Session, collation string) error {
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

	aliceURL := colURL + "alice.vcf"
	bobURL := colURL + "bob.vcf"
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, bobURL, []byte(fixtures.BobV4)); err != nil {
		return err
	}

	filter := client.ReportAddressbookQueryPropFilterCollation("FN", "Alice", collation)
	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, filter)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return fmt.Errorf("collation %q: %w", collation, err)
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("collation %q: alice.vcf not returned: %w", collation, err)
	}
	return assert.NoResponseFor(ms, bobURL)
}

// testQueryUnsupportedCollation verifies RFC 6352 §8.3: when a client specifies
// a collation not supported by the server, the server MUST respond with a
// CARDDAV:supported-collation precondition error.
func testQueryUnsupportedCollation(ctx context.Context, sess *suite.Session) error {
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

	if _, err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	filter := client.ReportAddressbookQueryPropFilterCollation("FN", "Alice", "i;bogus-collation")
	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, filter)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 207 {
		return fmt.Errorf("addressbook-query with unsupported collation returned 207; MUST return an error with CARDDAV:supported-collation precondition (RFC 6352 §8.3)")
	}
	if !strings.Contains(string(resp.Body), "supported-collation") {
		return fmt.Errorf("addressbook-query with unsupported collation: got %d but response body missing CARDDAV:supported-collation precondition (RFC 6352 §8.3)", resp.StatusCode)
	}
	return nil
}

// testPutNonstandardProps verifies RFC 6352 §6.3.2.2: servers MUST support the
// use of non-standard properties (X- prefixed) in address object resources
// stored via PUT, and must preserve them on subsequent GET.
func testPutNonstandardProps(ctx context.Context, sess *suite.Session) error {
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

	// vCard with a non-standard X- property.
	vcard := "BEGIN:VCARD\r\n" +
		"VERSION:4.0\r\n" +
		"UID:urn:uuid:dddddddd-0000-0000-0000-000000000001\r\n" +
		"FN:Custom Test\r\n" +
		"N:Test;Custom;;;\r\n" +
		"X-CUSTOM-PROP:custom-value\r\n" +
		"END:VCARD\r\n"

	contactURL := colURL + "custom.vcf"
	if _, err := putContact(ctx, c, contactURL, []byte(vcard)); err != nil {
		return fmt.Errorf("PUT with X- property rejected: %w", err)
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// RFC 6352 §6.3.2.2: server MUST preserve non-standard properties.
	return assert.BodyHas(resp.Body, "X-CUSTOM-PROP")
}

// testPrincipalAddressNotInAllprop verifies RFC 6352 §7.1.2: CARDDAV:principal-address
// SHOULD NOT be returned by a PROPFIND DAV:allprop request.
func testPrincipalAddressNotInAllprop(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, principalURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §7.1.2: allprop SHOULD NOT return principal-address.
	if strings.Contains(string(resp.Body), "principal-address") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:principal-address, which SHOULD NOT be included (RFC 6352 §7.1.2)")
	}
	return nil
}

// testQueryParamFilter verifies RFC 6352 §8.6.4: a C:param-filter with a
// C:text-match restricts results to address objects whose named vCard property
// has a parameter matching the given value. Two contacts are created — one with
// EMAIL;TYPE=work and one with EMAIL;TYPE=home — and the filter for TYPE=work
// must return only the first.
func testQueryParamFilter(ctx context.Context, sess *suite.Session) error {
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

	workURL := colURL + "work.vcf"
	homeURL := colURL + "home.vcf"

	workCard := []byte("BEGIN:VCARD\r\n" +
		"VERSION:4.0\r\n" +
		"UID:urn:uuid:eeeeeeee-0000-0000-0000-000000000001\r\n" +
		"FN:Work Contact\r\n" +
		"N:Contact;Work;;;\r\n" +
		"EMAIL;TYPE=work:work@example.com\r\n" +
		"END:VCARD\r\n")

	homeCard := []byte("BEGIN:VCARD\r\n" +
		"VERSION:4.0\r\n" +
		"UID:urn:uuid:ffffffff-0000-0000-0000-000000000001\r\n" +
		"FN:Home Contact\r\n" +
		"N:Contact;Home;;;\r\n" +
		"EMAIL;TYPE=home:home@example.com\r\n" +
		"END:VCARD\r\n")

	if _, err := putContact(ctx, c, workURL, workCard); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, homeURL, homeCard); err != nil {
		return err
	}

	// Filter: EMAIL parameter TYPE contains "work".
	filter := client.ReportAddressbookQueryParamFilter("EMAIL", "TYPE", "work")
	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, filter)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return err
	}
	// work.vcf matches TYPE=work; home.vcf does not.
	if err := assert.PropExists(ms, workURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("work.vcf not returned by param-filter: %w", err)
	}
	return assert.NoResponseFor(ms, homeURL)
}

// testSupportedFilterPrecondition verifies RFC 6352 §8.5: when a server does
// not support queries against a non-standard vCard property, it MUST reject the
// REPORT with a CARDDAV:supported-filter precondition. If the server accepts
// the query (it MAY support non-standard filters), the test passes trivially.
func testSupportedFilterPrecondition(ctx context.Context, sess *suite.Session) error {
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

	if _, err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// Use a highly unlikely non-standard property name so any server that does
	// not support non-standard filters will trigger the precondition.
	filter := client.ReportAddressbookQueryPropFilter("X-DAVLINT-NONEXISTENT-PROP-ZZZ", "anything")
	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, filter)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 207 {
		// Server supports non-standard filter queries — requirement not triggered.
		return nil
	}
	// Server rejected the query: the response MUST contain the supported-filter precondition.
	if !strings.Contains(string(resp.Body), "supported-filter") {
		return fmt.Errorf("addressbook-query with unsupported filter: got %d but response body missing CARDDAV:supported-filter precondition (RFC 6352 §8.5)", resp.StatusCode)
	}
	return nil
}
