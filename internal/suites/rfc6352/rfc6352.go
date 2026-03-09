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
