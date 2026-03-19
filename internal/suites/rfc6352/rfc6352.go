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
		ID:          "rfc6352.unauthenticated-propfind-denied",
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
	// §3 R-02
	suite.Register(suite.Test{
		ID:          "rfc6352.dav-class-3",
		Suite:       "rfc6352",
		Description: `OPTIONS on an address book collection includes "3" in the DAV response header (WebDAV Class 3)`,
		Severity:    suite.Must,
		Fn:          testDavClass3,
	})
	// §5.1 R-12
	suite.Register(suite.Test{
		ID:          "rfc6352.put-missing-uid",
		Suite:       "rfc6352",
		Description: "PUT an address object without a UID property is rejected with CARDDAV:valid-address-data precondition",
		Severity:    suite.Must,
		Fn:          testPutMissingUID,
	})
	// §6.3.2.1 R-42
	suite.Register(suite.Test{
		ID:          "rfc6352.put-uid-change",
		Suite:       "rfc6352",
		Description: "PUT to an existing address object URI with a different UID value is rejected with CARDDAV:no-uid-conflict precondition",
		Severity:    suite.Must,
		Fn:          testPutUIDChange,
	})
	// §6.3.2.1 R-43 (SHOULD)
	suite.Register(suite.Test{
		ID:          "rfc6352.uid-conflict-href",
		Suite:       "rfc6352",
		Description: "CARDDAV:no-uid-conflict precondition error body includes a DAV:href identifying the conflicting resource",
		Severity:    suite.Should,
		Fn:          testUIDConflictHref,
	})
	// §6.3.2.1 R-44
	suite.Register(suite.Test{
		ID:          "rfc6352.copy-location-ok",
		Suite:       "rfc6352",
		Description: "COPY of an address book collection to a location inside another address book collection is rejected with CARDDAV:addressbook-collection-location-ok",
		Severity:    suite.Must,
		Fn:          testCopyLocationOK,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.move-location-ok",
		Suite:       "rfc6352",
		Description: "MOVE of an address book collection to a location inside another address book collection is rejected with CARDDAV:addressbook-collection-location-ok",
		Severity:    suite.Must,
		Fn:          testMoveLocationOK,
	})
	// §6.2.1 R-20, R-22 (SHOULD)
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-description-writable",
		Suite:       "rfc6352",
		Description: "PROPPATCH can set CARDDAV:addressbook-description on an address book collection (property SHOULD NOT be protected)",
		Severity:    suite.Should,
		Fn:          testAddressbookDescriptionWritable,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.addressbook-description-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on an address book collection does not include CARDDAV:addressbook-description",
		Severity:    suite.Should,
		Fn:          testAddressbookDescriptionNotInAllprop,
	})
	// §6.2.2 R-23, R-27
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-address-data-protected",
		Suite:       "rfc6352",
		Description: "PROPPATCH attempting to set CARDDAV:supported-address-data is rejected with 403 (property is protected)",
		Severity:    suite.Must,
		Fn:          testSupportedAddressDataProtected,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-address-data-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on an address book collection does not include CARDDAV:supported-address-data",
		Severity:    suite.Should,
		Fn:          testSupportedAddressDataNotInAllprop,
	})
	// §6.2.3 R-28, R-31
	suite.Register(suite.Test{
		ID:          "rfc6352.max-resource-size-protected",
		Suite:       "rfc6352",
		Description: "PROPPATCH attempting to set CARDDAV:max-resource-size is rejected with 403 (property is protected)",
		Severity:    suite.Must,
		Fn:          testMaxResourceSizeProtected,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.max-resource-size-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on an address book collection does not include CARDDAV:max-resource-size",
		Severity:    suite.Should,
		Fn:          testMaxResourceSizeNotInAllprop,
	})
	// §8.3 R-71, §10.5.4 R-112 (SHOULD)
	suite.Register(suite.Test{
		ID:          "rfc6352.query-default-collation",
		Suite:       "rfc6352",
		Description: "addressbook-query text-match without a collation attribute uses i;unicode-casemap (case-insensitive) by default",
		Severity:    suite.Should,
		Fn:          testQueryDefaultCollation,
	})
	// §8.3 R-72
	suite.Register(suite.Test{
		ID:          "rfc6352.query-wildcard-collation",
		Suite:       "rfc6352",
		Description: "addressbook-query with a wildcard collation identifier is rejected with CARDDAV:supported-collation precondition",
		Severity:    suite.Must,
		Fn:          testQueryWildcardCollation,
	})
	// §8.3.1 R-74, R-76
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-collation-set-protected",
		Suite:       "rfc6352",
		Description: "PROPPATCH attempting to set CARDDAV:supported-collation-set is rejected with 403 (property is protected)",
		Severity:    suite.Must,
		Fn:          testSupportedCollationSetProtected,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.supported-collation-set-not-in-allprop",
		Suite:       "rfc6352",
		Description: "PROPFIND DAV:allprop on an address book collection does not include CARDDAV:supported-collation-set",
		Severity:    suite.Should,
		Fn:          testSupportedCollationSetNotInAllprop,
	})
	// §8.6 R-85
	suite.Register(suite.Test{
		ID:          "rfc6352.query-nonexistent-prop",
		Suite:       "rfc6352",
		Description: "addressbook-query requesting a non-existent WebDAV property returns 404 in DAV:propstat for that property",
		Severity:    suite.Must,
		Fn:          testQueryNonexistentProp,
	})
	// §6.1 R-18 (resource-level)
	suite.Register(suite.Test{
		ID:          "rfc6352.options-addressbook-token-resource",
		Suite:       "rfc6352",
		Description: `OPTIONS on an address object resource also returns "addressbook" in the DAV response header`,
		Severity:    suite.Must,
		Fn:          testOptionsAddressbookTokenResource,
	})
	// §10.4.2 R-107, R-108 — C:prop name matching in address-data retrieval
	suite.Register(suite.Test{
		ID:          "rfc6352.address-data-prop-no-group-prefix",
		Suite:       "rfc6352",
		Description: "addressbook-query C:address-data C:prop without group prefix returns properties with any or no group prefix",
		Severity:    suite.Must,
		Fn:          testAddressDataPropNoGroupPrefix,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.address-data-prop-group-prefix",
		Suite:       "rfc6352",
		Description: "addressbook-query C:address-data C:prop with group prefix returns only properties with exactly that prefix",
		Severity:    suite.Must,
		Fn:          testAddressDataPropGroupPrefix,
	})
	// §10.5.1 R-109, R-110 — prop-filter name matching
	suite.Register(suite.Test{
		ID:          "rfc6352.query-no-group-prefix-filter",
		Suite:       "rfc6352",
		Description: "addressbook-query prop-filter without group prefix matches cards with grouped or ungrouped instances of that property",
		Severity:    suite.Must,
		Fn:          testQueryNoGroupPrefixFilter,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.query-group-prefix-filter",
		Suite:       "rfc6352",
		Description: "addressbook-query prop-filter with group prefix matches only cards with that exact group-prefix property",
		Severity:    suite.Must,
		Fn:          testQueryGroupPrefixFilter,
	})
	// §13 R-120
	suite.Register(suite.Test{
		ID:          "rfc6352.unauthenticated-get-denied",
		Suite:       "rfc6352",
		Description: "Unauthenticated GET on an address object resource is rejected with 401 or 403",
		Severity:    suite.Must,
		Fn:          testUnauthenticatedGetDenied,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.unauthenticated-put-denied",
		Suite:       "rfc6352",
		Description: "Unauthenticated PUT to an address book collection is rejected with 401 or 403",
		Severity:    suite.Must,
		Fn:          testUnauthenticatedPutDenied,
	})
	suite.Register(suite.Test{
		ID:          "rfc6352.unauthenticated-report-denied",
		Suite:       "rfc6352",
		Description: "Unauthenticated addressbook-query REPORT on an address book collection is rejected with 401 or 403",
		Severity:    suite.Must,
		Fn:          testUnauthenticatedReportDenied,
	})
	// §5.1 R-01
	suite.Register(suite.Test{
		ID:          "rfc6352.put-v3",
		Suite:       "rfc6352",
		Description: "PUT a vCard 3.0 returns 201 Created",
		Severity:    suite.Must,
		Fn:          testPutV3,
	})
	// §5.1 R-01
	suite.Register(suite.Test{
		ID:          "rfc6352.stored-as-v4",
		Suite:       "rfc6352",
		Description: "After PUT of vCard 3.0, default GET returns VERSION:4.0",
		Severity:    suite.Must,
		Fn:          testStoredAsV4,
	})
	// §6.5.3
	suite.Register(suite.Test{
		ID:          "rfc6352.get-accept-v3",
		Suite:       "rfc6352",
		Description: "GET with Accept: text/vcard; version=3.0 returns VERSION:3.0 after PUT of 3.0",
		Severity:    suite.Must,
		Fn:          testGetAcceptV3,
	})
	// §6.5.3 / RFC 2426 §3.3.2
	suite.Register(suite.Test{
		ID:          "rfc6352.email-roundtrip",
		Suite:       "rfc6352",
		Description: "Email type is preserved correctly when serving vCard 4.0 content as 3.0",
		Severity:    suite.Must,
		Fn:          testEmailRoundtrip,
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

// testAddressDataPropNoGroupPrefix verifies RFC 6352 §10.4.2 R-107: when a
// C:prop name attribute has no group prefix, it MUST match vCard properties
// with no group prefix AND with any group prefix. A C:prop name="EMAIL" request
// must return both plain EMAIL and ITEM1.EMAIL lines from the stored vCard.
func testAddressDataPropNoGroupPrefix(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "both.vcf"
	if _, err := putContact(ctx, c, contactURL, []byte(fixtures.BothEmailsV4)); err != nil {
		return err
	}

	// Request only the EMAIL vCard property by name (no group prefix).
	// RFC 6352 §10.4.2: must match plain EMAIL AND ITEM1.EMAIL.
	body := client.ReportAddressbookQueryAddressDataProps([]string{"EMAIL"}, nil)
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
	// Both plain EMAIL and ITEM1.EMAIL must appear in the returned address-data.
	if err := assert.PropTextContains(ms, contactURL, client.NScarddav, "address-data", "EMAIL:plain@example.com"); err != nil {
		return fmt.Errorf("c:prop name=\"EMAIL\" (no group prefix) missing plain EMAIL: %w (RFC 6352 §10.4.2 R-107)", err)
	}
	if err := assert.PropTextContains(ms, contactURL, client.NScarddav, "address-data", "ITEM1.EMAIL"); err != nil {
		return fmt.Errorf("c:prop name=\"EMAIL\" (no group prefix) missing grouped ITEM1.EMAIL: %w (RFC 6352 §10.4.2 R-107)", err)
	}
	return nil
}

// testAddressDataPropGroupPrefix verifies RFC 6352 §10.4.2 R-108: when a
// C:prop name attribute includes a group prefix, it MUST match only properties
// with exactly that group prefix and name. A C:prop name="ITEM1.EMAIL" request
// must return ITEM1.EMAIL but NOT plain EMAIL.
func testAddressDataPropGroupPrefix(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "both.vcf"
	if _, err := putContact(ctx, c, contactURL, []byte(fixtures.BothEmailsV4)); err != nil {
		return err
	}

	// Request only the ITEM1.EMAIL vCard property by name (exact group prefix).
	// RFC 6352 §10.4.2: must match ITEM1.EMAIL only, NOT plain EMAIL.
	body := client.ReportAddressbookQueryAddressDataProps([]string{"ITEM1.EMAIL"}, nil)
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
	addrData, err := extractAddressData(ms, contactURL)
	if err != nil {
		return err
	}
	// ITEM1.EMAIL must be present.
	if !strings.Contains(addrData, "ITEM1.EMAIL") {
		return fmt.Errorf("c:prop name=\"ITEM1.EMAIL\" (group prefix): grouped ITEM1.EMAIL absent from address-data (RFC 6352 §10.4.2 R-108)")
	}
	// Plain EMAIL must NOT be present (different group prefix — no prefix vs ITEM1).
	for _, line := range strings.Split(addrData, "\n") {
		line = strings.TrimRight(line, "\r")
		upper := strings.ToUpper(line)
		if (strings.HasPrefix(upper, "EMAIL:") || strings.HasPrefix(upper, "EMAIL;")) &&
			!strings.HasPrefix(upper, "ITEM1.EMAIL") {
			return fmt.Errorf("c:prop name=\"ITEM1.EMAIL\" (group prefix): plain EMAIL returned in address-data; MUST NOT match (RFC 6352 §10.4.2 R-108)")
		}
	}
	return nil
}

// extractAddressData returns the text content of the CARDDAV:address-data
// property for the given href from a multistatus response.
func extractAddressData(ms *client.Multistatus, href string) (string, error) {
	for i := range ms.Responses {
		r := &ms.Responses[i]
		if r.Href != href {
			continue
		}
		for j := range r.PropStat {
			ps := &r.PropStat[j]
			if !strings.Contains(ps.Status, "200") {
				continue
			}
			if client.PropInnerXML(ps.Prop.Inner, client.NScarddav, "address-data") {
				// Re-parse to get the text content.
				wrapped := append(
					[]byte(`<prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`),
					ps.Prop.Inner...,
				)
				wrapped = append(wrapped, []byte("</prop>")...)
				// Use PropTextContains-style extraction via a throwaway Multistatus.
				return string(wrapped), nil
			}
		}
	}
	return "", fmt.Errorf("address-data not found for href %q", href)
}

// testQueryNoGroupPrefixFilter verifies RFC 6352 §10.5.1 R-109: a C:prop-filter
// name without a group prefix MUST match address objects that have the named
// property with any group prefix (or none). Filtering on "EMAIL" must return
// cards with plain EMAIL as well as cards with only ITEM1.EMAIL.
func testQueryNoGroupPrefixFilter(ctx context.Context, sess *suite.Session) error {
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

	// grouped.vcf has only ITEM1.EMAIL; alice.vcf has only plain EMAIL.
	groupedURL := colURL + "grouped.vcf"
	aliceURL := colURL + "alice.vcf"
	if _, err := putContact(ctx, c, groupedURL, []byte(fixtures.GroupedEmailOnlyV4)); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// Filter on EMAIL (no group prefix) — must match both cards.
	filter := client.ReportAddressbookQueryPropFilter("EMAIL", "@example.com")
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
	// Plain EMAIL card must match.
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("prop-filter name=\"EMAIL\" (no group prefix) did not match card with plain EMAIL: %w (RFC 6352 §10.5.1 R-109)", err)
	}
	// Grouped ITEM1.EMAIL card must also match.
	if err := assert.PropExists(ms, groupedURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("prop-filter name=\"EMAIL\" (no group prefix) did not match card with ITEM1.EMAIL: %w (RFC 6352 §10.5.1 R-109)", err)
	}
	return nil
}

// testQueryGroupPrefixFilter verifies RFC 6352 §10.5.1 R-110: a C:prop-filter
// name with a group prefix MUST match only address objects that have the named
// property with exactly that group prefix. Filtering on "ITEM1.EMAIL" must NOT
// return cards that have only plain EMAIL.
func testQueryGroupPrefixFilter(ctx context.Context, sess *suite.Session) error {
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

	// grouped.vcf has only ITEM1.EMAIL; alice.vcf has only plain EMAIL.
	groupedURL := colURL + "grouped.vcf"
	aliceURL := colURL + "alice.vcf"
	if _, err := putContact(ctx, c, groupedURL, []byte(fixtures.GroupedEmailOnlyV4)); err != nil {
		return err
	}
	if _, err := putContact(ctx, c, aliceURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// Filter on ITEM1.EMAIL (exact group prefix) — must match only grouped.vcf.
	filter := client.ReportAddressbookQueryPropFilter("ITEM1.EMAIL", "@example.com")
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
	// Grouped ITEM1.EMAIL card must match.
	if err := assert.PropExists(ms, groupedURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("prop-filter name=\"ITEM1.EMAIL\" (group prefix) did not match card with ITEM1.EMAIL: %w (RFC 6352 §10.5.1 R-110)", err)
	}
	// Plain EMAIL card must NOT match.
	if err := assert.NoResponseFor(ms, aliceURL); err != nil {
		return fmt.Errorf("prop-filter name=\"ITEM1.EMAIL\" (group prefix) incorrectly matched card with only plain EMAIL (RFC 6352 §10.5.1 R-110): %w", err)
	}
	return nil
}

// testDavClass3 verifies RFC 6352 §3 R-02: a CardDAV server MUST support
// WebDAV Class 3, advertised by including "3" in the DAV response header.
func testDavClass3(ctx context.Context, sess *suite.Session) error {
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
	// RFC 6352 §3: server MUST support WebDAV Class 3; DAV header MUST include "3".
	return assert.HeaderContains(resp, "DAV", "3")
}

// testPutMissingUID verifies RFC 6352 §5.1 R-12: vCard components in an address
// book collection MUST have a UID property value; a PUT without UID MUST be rejected.
func testPutMissingUID(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"nouid.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4NoUID))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT vCard without UID was accepted (got %d); server MUST reject (RFC 6352 §5.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "valid-address-data") {
		return fmt.Errorf("PUT vCard without UID: got %d but response body missing CARDDAV:valid-address-data precondition (RFC 6352 §5.1)", resp.StatusCode)
	}
	return nil
}

// testPutUIDChange verifies RFC 6352 §6.3.2.1 R-42: a PUT to an existing
// address object URI MUST NOT overwrite it with a resource having a different UID.
func testPutUIDChange(ctx context.Context, sess *suite.Session) error {
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

	// PUT Alice at alice.vcf — must succeed (UID = alice's UID).
	if _, err := putContact(ctx, c, colURL+"alice.vcf", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// PUT Bob's vCard at the same URL — different UID, must be rejected.
	resp, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.BobV4))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT to existing resource with different UID was accepted (got %d); server MUST reject with CARDDAV:no-uid-conflict (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "no-uid-conflict") {
		return fmt.Errorf("PUT with changed UID: got %d but response body missing CARDDAV:no-uid-conflict precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testUIDConflictHref verifies RFC 6352 §6.3.2.1 R-43: when rejecting a PUT due
// to a UID conflict, servers SHOULD include a DAV:href identifying the conflicting
// resource in the CARDDAV:no-uid-conflict error element.
func testUIDConflictHref(ctx context.Context, sess *suite.Session) error {
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

	// PUT same UID at a different path — must fail with no-uid-conflict.
	resp, err := c.Put(ctx, colURL+"alice-copy.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		return fmt.Errorf("PUT with duplicate UID was accepted (got %d); CARDDAV:no-uid-conflict test is not meaningful (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	// RFC 6352 §6.3.2.1: SHOULD include DAV:href pointing to the conflicting resource.
	if !strings.Contains(string(resp.Body), "href") {
		return fmt.Errorf("CARDDAV:no-uid-conflict error body missing DAV:href for conflicting resource (RFC 6352 §6.3.2.1 SHOULD)")
	}
	return nil
}

// testCopyLocationOK verifies RFC 6352 §6.3.2.1 R-44: COPYing an address book
// collection to a location inside another address book collection MUST be rejected
// with the CARDDAV:addressbook-collection-location-ok precondition.
func testCopyLocationOK(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	srcURL, cleanupSrc, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanupSrc)

	dstURL, cleanupDst, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanupDst)

	// Copy src address book into dst address book — nested address book MUST be rejected.
	nestedURL := dstURL + "nested/"
	resp, err := c.Copy(ctx, srcURL, nestedURL, false)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		sess.AddCleanup(func(ctx context.Context) { _, _ = c.Delete(ctx, nestedURL, "") }) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("COPY of address book into another address book was accepted (got %d); server MUST reject with CARDDAV:addressbook-collection-location-ok (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "addressbook-collection-location-ok") {
		return fmt.Errorf("COPY to invalid location: got %d but response body missing CARDDAV:addressbook-collection-location-ok precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testMoveLocationOK verifies RFC 6352 §6.3.2.1 R-44: MOVEing an address book
// collection to a location inside another address book collection MUST be rejected
// with the CARDDAV:addressbook-collection-location-ok precondition.
func testMoveLocationOK(ctx context.Context, sess *suite.Session) error {
	c := sess.Primary()
	homeSet, err := discoverHomeSet(ctx, c, sess.ContextPath)
	if err != nil {
		return err
	}
	srcURL, cleanupSrc, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanupSrc)

	dstURL, cleanupDst, err := makeTestCollection(ctx, c, homeSet)
	if err != nil {
		return err
	}
	sess.AddCleanup(cleanupDst)

	// Move src address book into dst address book — nested address book MUST be rejected.
	nestedURL := dstURL + "nested/"
	resp, err := c.Move(ctx, srcURL, nestedURL, false)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		sess.AddCleanup(func(ctx context.Context) { _, _ = c.Delete(ctx, nestedURL, "") }) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("MOVE of address book into another address book was accepted (got %d); server MUST reject with CARDDAV:addressbook-collection-location-ok (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "addressbook-collection-location-ok") {
		return fmt.Errorf("MOVE to invalid location: got %d but response body missing CARDDAV:addressbook-collection-location-ok precondition (RFC 6352 §6.3.2.1)", resp.StatusCode)
	}
	return nil
}

// testAddressbookDescriptionWritable verifies RFC 6352 §6.2.1 R-20: the
// CARDDAV:addressbook-description property SHOULD NOT be protected; users
// should be able to set it via PROPPATCH.
func testAddressbookDescriptionWritable(ctx context.Context, sess *suite.Session) error {
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

	body := client.ProppatchSet([][3]string{
		{client.NScarddav, "addressbook-description", "davlint test description"},
	})
	resp, err := c.Proppatch(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 207 {
		return fmt.Errorf("PROPPATCH to set addressbook-description: got %d, want 207 (RFC 6352 §6.2.1 SHOULD NOT be protected)", resp.StatusCode)
	}
	// 207 with a 403 propstat means the property is protected — a SHOULD NOT violation.
	if strings.Contains(string(resp.Body), "403") {
		return fmt.Errorf("PROPPATCH to set addressbook-description: server returned 403 in propstat; property SHOULD NOT be protected (RFC 6352 §6.2.1)")
	}
	return nil
}

// testAddressbookDescriptionNotInAllprop verifies RFC 6352 §6.2.1 R-22:
// CARDDAV:addressbook-description SHOULD NOT be returned by PROPFIND allprop.
func testAddressbookDescriptionNotInAllprop(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §6.2.1: allprop SHOULD NOT return addressbook-description.
	if strings.Contains(string(resp.Body), "addressbook-description") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:addressbook-description, which SHOULD NOT be included (RFC 6352 §6.2.1)")
	}
	return nil
}

// testSupportedAddressDataProtected verifies RFC 6352 §6.2.2 R-23:
// CARDDAV:supported-address-data MUST be a protected property; any PROPPATCH
// attempt to set it MUST be rejected with a 403 status.
func testSupportedAddressDataProtected(ctx context.Context, sess *suite.Session) error {
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

	body := client.ProppatchSet([][3]string{
		{client.NScarddav, "supported-address-data", ""},
	})
	resp, err := c.Proppatch(ctx, colURL, body)
	if err != nil {
		return err
	}
	// RFC 6352 §6.2.2: MUST be protected — server must return 403 (directly or in propstat).
	if resp.StatusCode == 403 {
		return nil
	}
	if resp.StatusCode == 207 && strings.Contains(string(resp.Body), "403") {
		return nil
	}
	return fmt.Errorf("PROPPATCH on CARDDAV:supported-address-data: got %d without 403; property MUST be protected (RFC 6352 §6.2.2)", resp.StatusCode)
}

// testSupportedAddressDataNotInAllprop verifies RFC 6352 §6.2.2 R-27:
// CARDDAV:supported-address-data SHOULD NOT be returned by PROPFIND allprop.
func testSupportedAddressDataNotInAllprop(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §6.2.2: allprop SHOULD NOT return supported-address-data.
	if strings.Contains(string(resp.Body), "supported-address-data") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:supported-address-data, which SHOULD NOT be included (RFC 6352 §6.2.2)")
	}
	return nil
}

// testMaxResourceSizeProtected verifies RFC 6352 §6.2.3 R-28:
// CARDDAV:max-resource-size MUST be a protected property; any PROPPATCH attempt
// to set it MUST be rejected. If the server does not implement the property the
// test passes trivially (the property would not exist to protect).
func testMaxResourceSizeProtected(ctx context.Context, sess *suite.Session) error {
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

	// First check whether the server exposes this property at all.
	pfBody := client.PropfindProps([][2]string{{client.NScarddav, "max-resource-size"}})
	pfResp, err := c.Propfind(ctx, colURL, "0", pfBody)
	if err != nil {
		return err
	}
	pfMS, err := client.ParseMultistatus(pfResp.Body)
	if err != nil {
		return err
	}
	// If the server does not support max-resource-size, skip the protection test.
	if err := assert.PropExists(pfMS, colURL, client.NScarddav, "max-resource-size"); err != nil {
		return nil // property absent — not applicable
	}

	body := client.ProppatchSet([][3]string{
		{client.NScarddav, "max-resource-size", "999999999"},
	})
	resp, err := c.Proppatch(ctx, colURL, body)
	if err != nil {
		return err
	}
	// RFC 6352 §6.2.3: MUST be protected — server must return 403 (directly or in propstat).
	if resp.StatusCode == 403 {
		return nil
	}
	if resp.StatusCode == 207 && strings.Contains(string(resp.Body), "403") {
		return nil
	}
	return fmt.Errorf("PROPPATCH on CARDDAV:max-resource-size: got %d without 403; property MUST be protected (RFC 6352 §6.2.3)", resp.StatusCode)
}

// testMaxResourceSizeNotInAllprop verifies RFC 6352 §6.2.3 R-31:
// CARDDAV:max-resource-size SHOULD NOT be returned by PROPFIND allprop.
func testMaxResourceSizeNotInAllprop(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §6.2.3: allprop SHOULD NOT return max-resource-size.
	if strings.Contains(string(resp.Body), "max-resource-size") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:max-resource-size, which SHOULD NOT be included (RFC 6352 §6.2.3)")
	}
	return nil
}

// testQueryDefaultCollation verifies RFC 6352 §8.3 R-71 and §10.5.4 R-112:
// in the absence of a collation attribute on C:text-match, the server MUST use
// i;unicode-casemap, which is case-insensitive. A filter using an uppercase
// search string MUST still match the (mixed-case) stored FN value.
func testQueryDefaultCollation(ctx context.Context, sess *suite.Session) error {
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

	// Filter FN contains "ALICE" (all caps) with NO collation — default must be case-insensitive.
	filter := client.ReportAddressbookQueryPropFilter("FN", "ALICE")
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
	// "ALICE" must match FN:"Alice Test" under i;unicode-casemap default.
	if err := assert.PropExists(ms, aliceURL, client.NSdav, "getetag"); err != nil {
		return fmt.Errorf("default collation (no attribute): uppercase filter did not match mixed-case FN; server may be using case-sensitive default instead of i;unicode-casemap (RFC 6352 §8.3): %w", err)
	}
	return assert.NoResponseFor(ms, bobURL)
}

// testQueryWildcardCollation verifies RFC 6352 §8.3 R-72: collation identifiers
// MUST NOT contain wildcards (per RFC 4790 §3.2); a wildcard collation MUST be
// rejected with a CARDDAV:supported-collation precondition error.
func testQueryWildcardCollation(ctx context.Context, sess *suite.Session) error {
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

	// "i;*" is a wildcard collation identifier — MUST be rejected per RFC 4790 §3.2.
	filter := client.ReportAddressbookQueryPropFilterCollation("FN", "Alice", "i;*")
	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, filter)
	resp, err := c.ReportWithDepth(ctx, colURL, "1", body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 207 {
		return fmt.Errorf("addressbook-query with wildcard collation %q returned 207; MUST be rejected with CARDDAV:supported-collation (RFC 6352 §8.3)", "i;*")
	}
	if !strings.Contains(string(resp.Body), "supported-collation") {
		return fmt.Errorf("addressbook-query with wildcard collation: got %d but response body missing CARDDAV:supported-collation precondition (RFC 6352 §8.3)", resp.StatusCode)
	}
	return nil
}

// testSupportedCollationSetProtected verifies RFC 6352 §8.3.1 R-74:
// CARDDAV:supported-collation-set MUST be a protected property; any PROPPATCH
// attempt to set it MUST be rejected with a 403 status.
func testSupportedCollationSetProtected(ctx context.Context, sess *suite.Session) error {
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

	body := client.ProppatchSet([][3]string{
		{client.NScarddav, "supported-collation-set", ""},
	})
	resp, err := c.Proppatch(ctx, colURL, body)
	if err != nil {
		return err
	}
	// RFC 6352 §8.3.1: MUST be protected — server must return 403 (directly or in propstat).
	if resp.StatusCode == 403 {
		return nil
	}
	if resp.StatusCode == 207 && strings.Contains(string(resp.Body), "403") {
		return nil
	}
	return fmt.Errorf("PROPPATCH on CARDDAV:supported-collation-set: got %d without 403; property MUST be protected (RFC 6352 §8.3.1)", resp.StatusCode)
}

// testSupportedCollationSetNotInAllprop verifies RFC 6352 §8.3.1 R-76:
// CARDDAV:supported-collation-set SHOULD NOT be returned by PROPFIND allprop.
func testSupportedCollationSetNotInAllprop(ctx context.Context, sess *suite.Session) error {
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

	body := client.PropfindAllprop()
	resp, err := c.Propfind(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return err
	}
	// RFC 6352 §8.3.1: allprop SHOULD NOT return supported-collation-set.
	if strings.Contains(string(resp.Body), "supported-collation-set") {
		return fmt.Errorf("PROPFIND DAV:allprop returned CARDDAV:supported-collation-set, which SHOULD NOT be included (RFC 6352 §8.3.1)")
	}
	return nil
}

// testQueryNonexistentProp verifies RFC 6352 §8.6 R-85: when an addressbook-query
// REPORT requests a non-existent WebDAV property, the server MUST report a 404
// status for that property in the DAV:propstat of each matching response entry.
func testQueryNonexistentProp(ctx context.Context, sess *suite.Session) error {
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

	// Request a real property (getetag) plus a non-existent one.
	body := client.ReportAddressbookQuery(
		[][2]string{
			{client.NSdav, "getetag"},
			{client.NSdav, "davlint-nonexistent-xyz"},
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
	// getetag must be present in the 200 propstat.
	if err := assert.PropExists(ms, contactURL, client.NSdav, "getetag"); err != nil {
		return err
	}
	// The non-existent property must appear in a 404 propstat (RFC 6352 §8.6 R-85).
	return assert.PropNotFound(ms, contactURL, client.NSdav, "davlint-nonexistent-xyz")
}

// testOptionsAddressbookTokenResource verifies RFC 6352 §6.1 R-18: the
// "addressbook" token in the DAV response header is required not just on
// address book collections but on any resource that supports address book
// features, including individual address object resources.
func testOptionsAddressbookTokenResource(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Options(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// RFC 6352 §6.1: DAV header MUST contain "addressbook" on address object resources too.
	return assert.HeaderContains(resp, "DAV", "addressbook")
}

// testUnauthenticatedGetDenied verifies RFC 6352 §13 R-120: address book
// resources MUST NOT be accessible by unauthenticated users; an unauthenticated
// GET on an address object resource MUST be rejected with 401 or 403.
func testUnauthenticatedGetDenied(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.GetNoAuth(ctx, contactURL)
	if err != nil {
		return err
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return fmt.Errorf("unauthenticated GET on address object: got %d, want 401 or 403 (RFC 6352 §13)", resp.StatusCode)
	}
	return nil
}

// testUnauthenticatedPutDenied verifies RFC 6352 §13 R-120: unauthenticated
// clients MUST NOT be able to write to address book resources; a PUT without
// credentials MUST be rejected with 401 or 403.
func testUnauthenticatedPutDenied(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.PutNoAuth(ctx, colURL+"noauth.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4))
	if err != nil {
		return err
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return fmt.Errorf("unauthenticated PUT to address book: got %d, want 401 or 403 (RFC 6352 §13)", resp.StatusCode)
	}
	return nil
}

// testUnauthenticatedReportDenied verifies RFC 6352 §13 R-120: unauthenticated
// clients MUST NOT be able to query address book resources; an addressbook-query
// REPORT without credentials MUST be rejected with 401 or 403.
func testUnauthenticatedReportDenied(ctx context.Context, sess *suite.Session) error {
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

	body := client.ReportAddressbookQuery([][2]string{{client.NSdav, "getetag"}}, nil)
	resp, err := c.ReportNoAuth(ctx, colURL, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return fmt.Errorf("unauthenticated addressbook-query REPORT: got %d, want 401 or 403 (RFC 6352 §13)", resp.StatusCode)
	}
	return nil
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

// testPutV3 verifies RFC 6352 §5.1: the server MUST support vCard 3.0 as an
// address object media type. A PUT of a valid vCard 3.0 must return 201 Created.
func testPutV3(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("PUT vCard 3.0: got %d, want 201", resp.StatusCode)
	}
	return nil
}

// testStoredAsV4 verifies RFC 6352 §5.1: the server stores address objects
// internally as vCard 4.0. A default GET after PUT of a vCard 3.0 must return
// a body containing VERSION:4.0.
func testStoredAsV4(ctx context.Context, sess *suite.Session) error {
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

	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3)); err != nil {
		return err
	}
	resp, err := c.Get(ctx, colURL+"alice.vcf")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:4.0")
}

// testGetAcceptV3 verifies RFC 6352 §6.5.3: the server MUST support serving
// address objects in vCard 3.0 format when the client requests it via
// Accept: text/vcard; version=3.0.
func testGetAcceptV3(ctx context.Context, sess *suite.Session) error {
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

	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV3)); err != nil {
		return err
	}
	resp, err := c.GetWithAccept(ctx, colURL+"alice.vcf", "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:3.0")
}

// testEmailRoundtrip verifies RFC 6352 §6.5.3 / RFC 2426 §3.3.2: when the
// server serves a vCard 4.0 address object as vCard 3.0, the EMAIL TYPE
// parameter MUST include INTERNET (required by RFC 2426 for all email addresses).
func testEmailRoundtrip(ctx context.Context, sess *suite.Session) error {
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

	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4)); err != nil {
		return err
	}
	resp, err := c.GetWithAccept(ctx, colURL+"alice.vcf", "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	if err := assert.BodyHas(resp.Body, "INTERNET"); err != nil {
		return fmt.Errorf("email type conversion to 3.0: %w", err)
	}
	return nil
}
