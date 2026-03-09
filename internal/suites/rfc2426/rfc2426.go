// Package rfc2426 registers vCard 3.0 conformance tests (RFC 2426).
//
// Tests verify that the server accepts vCard 3.0 input, stores it internally
// as vCard 4.0, and can serve it back in 3.0 format on request — including
// correct EMAIL type conversion between the two versions.
package rfc2426

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
		ID:          "rfc2426.put-v3",
		Suite:       "rfc2426",
		Description: "PUT a vCard 3.0 returns 201 Created",
		Severity:    suite.Must,
		Fn:          testPutV3,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.stored-as-v4",
		Suite:       "rfc2426",
		Description: "After PUT of vCard 3.0, default GET returns VERSION:4.0",
		Severity:    suite.Must,
		Fn:          testStoredAsV4,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.get-accept-v3",
		Suite:       "rfc2426",
		Description: "GET with Accept: text/vcard; version=3.0 returns VERSION:3.0 after PUT of 3.0",
		Severity:    suite.Must,
		Fn:          testGetAcceptV3,
	})
	suite.Register(suite.Test{
		ID:          "rfc2426.email-roundtrip",
		Suite:       "rfc2426",
		Description: "Email type is preserved correctly when serving vCard 4.0 content as 3.0",
		Severity:    suite.Must,
		Fn:          testEmailRoundtrip,
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
	colURL := fmt.Sprintf("%sdavlint-rfc2426-%08x/", homeSet, rand.Uint32()) // #nosec G404 -- non-crypto random is fine for unique test collection names
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

// --- Tests ---

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

	// PUT a 4.0 vCard with TYPE=work email.
	if _, err := c.Put(ctx, colURL+"alice.vcf", "text/vcard; charset=utf-8", []byte(fixtures.AliceV4)); err != nil {
		return err
	}

	// GET as 3.0 — email must include INTERNET in the TYPE list.
	resp, err := c.GetWithAccept(ctx, colURL+"alice.vcf", "text/vcard; version=3.0")
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp, 200); err != nil {
		return err
	}
	// RFC 2426 §3.3.2: TYPE=INTERNET is required for email addresses in 3.0.
	if err := assert.BodyHas(resp.Body, "INTERNET"); err != nil {
		return fmt.Errorf("email type conversion to 3.0: %w", err)
	}
	return nil
}
