// Package rfc6350 registers vCard 4.0 conformance tests (RFC 6350).
//
// Tests cover content negotiation on GET (version parameter), server-side UID
// assignment, the supported-address-data CardDAV property, and the 250 KB
// inline photo size limit.
package rfc6350

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
		ID:          "rfc6350.get-default-v4",
		Suite:       "rfc6350",
		Description: "GET on a stored vCard returns VERSION:4.0 by default",
		Severity:    suite.Must,
		Fn:          testGetDefaultV4,
	})
	suite.Register(suite.Test{
		ID:          "rfc6350.get-accept-v4",
		Suite:       "rfc6350",
		Description: "GET with Accept: text/vcard; version=4.0 returns VERSION:4.0",
		Severity:    suite.Must,
		Fn:          testGetAcceptV4,
	})
	suite.Register(suite.Test{
		ID:          "rfc6350.get-accept-v3",
		Suite:       "rfc6350",
		Description: "GET with Accept: text/vcard; version=3.0 returns VERSION:3.0",
		Severity:    suite.Must,
		Fn:          testGetAcceptV3,
	})
	suite.Register(suite.Test{
		ID:          "rfc6350.uid-assignment",
		Suite:       "rfc6350",
		Description: "PUT a vCard without UID; server assigns one and GET returns a UID line",
		Severity:    suite.Must,
		Fn:          testUIDAssignment,
	})
	suite.Register(suite.Test{
		ID:          "rfc6350.supported-address-data",
		Suite:       "rfc6350",
		Description: "PROPFIND on an address book returns C:supported-address-data with 3.0 and 4.0",
		Severity:    suite.Must,
		Fn:          testSupportedAddressData,
	})
	suite.Register(suite.Test{
		ID:          "rfc6350.photo-size-limit",
		Suite:       "rfc6350",
		Description: "PUT a vCard with an inline PHOTO exceeding 250 KB returns 413",
		Severity:    suite.Must,
		Fn:          testPhotoSizeLimit,
	})
}

func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic // unnamed results are clearer here
	colURL := fmt.Sprintf("%sdavlint-rfc6350-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

func putContact(ctx context.Context, c *client.Client, url string, body []byte) (*client.Response, error) {
	return c.Put(ctx, url, "text/vcard; charset=utf-8", body)
}

// --- Tests ---

func testGetDefaultV4(ctx context.Context, sess *suite.Session) error {
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
	return assert.BodyHas(resp.Body, "VERSION:4.0")
}

func testGetAcceptV4(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.GetWithAccept(ctx, contactURL, "text/vcard; version=4.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:4.0")
}

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

	contactURL := colURL + "alice.vcf"
	if _, err := putContact(ctx, c, contactURL, []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	resp, err := c.GetWithAccept(ctx, contactURL, "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.BodyHas(resp.Body, "VERSION:3.0")
}

func testUIDAssignment(ctx context.Context, sess *suite.Session) error {
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

	contactURL := colURL + "nouid.vcf"
	putResp, err := putContact(ctx, c, contactURL, []byte(fixtures.AliceV4NoUID))
	if err != nil {
		return err
	}
	if putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return fmt.Errorf("PUT no-UID vCard: got %d, want 201 or 204", putResp.StatusCode)
	}

	resp, err := c.Get(ctx, contactURL)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	return assert.HasProperty(resp.Body, "UID")
}

func testSupportedAddressData(ctx context.Context, sess *suite.Session) error {
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
		{client.NScarddav, "supported-address-data"},
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
	if err := assert.PropExists(ms, colURL, client.NScarddav, "supported-address-data"); err != nil {
		return err
	}
	// Verify both versions are advertised in the property value.
	if err := assert.BodyHas(resp.Body, `version="3.0"`); err != nil {
		return fmt.Errorf("supported-address-data missing version 3.0: %w", err)
	}
	return assert.BodyHas(resp.Body, `version="4.0"`)
}

func testPhotoSizeLimit(ctx context.Context, sess *suite.Session) error {
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

	resp, err := putContact(ctx, c, colURL+"large.vcf", []byte(fixtures.LargePhotoV4()))
	if err != nil {
		return err
	}
	// RFC 6350 / server policy: oversized inline photo → 413 Request Entity Too Large.
	return assert.StatusCode(resp, 413)
}
