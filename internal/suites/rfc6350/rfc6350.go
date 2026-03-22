// Package rfc6350 registers vCard 4.0 format validation tests (RFC 6350).
//
// Tests verify server-side enforcement of vCard 4.0 rules observable via HTTP:
// that stored vCards are served as VERSION:4.0 by default, and that the server
// assigns a UID when one is absent on PUT.
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
	// §6.7.9: VERSION value MUST be "4.0" for this spec.
	suite.Register(suite.Test{
		ID:            "rfc6350.get-default-v4",
		Suite:         "rfc6350",
		Description:   "GET on a stored vCard returns VERSION:4.0 by default",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.9", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.9"},
		},
		Fn: testGetDefaultV4,
	})
	// §6.7.6: UID MUST uniquely identify the vCard object.
	suite.Register(suite.Test{
		ID:            "rfc6350.uid-assignment",
		Suite:         "rfc6350",
		Description:   "PUT a vCard without UID; server assigns one and GET returns a UID line",
		Severity:      suite.Must,
		Tags:          []string{"vcard"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 6350", Section: "§6.7.6", URL: "https://www.rfc-editor.org/rfc/rfc6350#section-6.7.6"},
		},
		Fn: testUIDAssignment,
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

