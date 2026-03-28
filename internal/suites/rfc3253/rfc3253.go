// Package rfc3253 registers WebDAV DeltaV REPORT method conformance tests (RFC 3253 §3.6).
//
// Only the generic REPORT method contract is tested; all versioning requirements
// (§4+) are deferred — DeltaV versioning is not implemented by modern
// CalDAV/CardDAV servers.
//
// Tests cover: unsupported report type returns 403 with DAV:supported-report
// precondition, and REPORT idempotence (two identical REPORTs leave the
// sync-token unchanged, proving no server state was modified).
package rfc3253

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/suite"
	"github.com/sdobberstein/davlint/pkg/webdav"
)

func init() {
	// §3.6: A server MUST return 403 with a DAV:supported-report error body when
	// the requested report type is not in the server's supported-report-set.
	suite.Register(suite.Test{
		ID:            "rfc3253.unsupported-report-type",
		Suite:         "rfc3253",
		Description:   "REPORT with an unrecognised report element returns 403 with DAV:supported-report precondition body (RFC 3253 §3.6 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"report"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 3253", Section: "§3.6", URL: "https://www.rfc-editor.org/rfc/rfc3253#section-3.6"},
		},
		Fn: testUnsupportedReportType,
	})
	// §3.6: REPORT MUST be "non-modifying"; the server MUST NOT change the
	// resource as a result of a REPORT request. Two identical REPORTs on an
	// unchanged collection MUST return the same sync-token.
	suite.Register(suite.Test{
		ID:            "rfc3253.report-idempotent",
		Suite:         "rfc3253",
		Description:   "Two identical sync-collection REPORTs return the same sync-token; REPORT does not modify server state (RFC 3253 §3.6 MUST)",
		Severity:      suite.Must,
		Tags:          []string{"report", "sync"},
		MinPrincipals: 1,
		References: []suite.RFCRef{
			{RFC: "RFC 3253", Section: "§3.6", URL: "https://www.rfc-editor.org/rfc/rfc3253#section-3.6"},
			{RFC: "RFC 6578", Section: "§3.4", URL: "https://www.rfc-editor.org/rfc/rfc6578#section-3.4"},
		},
		Fn: testReportIdempotent,
	})
}

// unknownReportBody is a well-formed XML document with a report element in a
// namespace no server will recognise, triggering the DAV:supported-report check.
var unknownReportBody = []byte(
	`<?xml version="1.0" encoding="utf-8"?>` +
		`<x:unknown-report xmlns:x="urn:davlint:test"/>`,
)

// testUnsupportedReportType verifies RFC 3253 §3.6: when the requested report
// element is not in the server's DAV:supported-report-set, the server MUST
// return 403 Forbidden and include DAV:supported-report inside a DAV:error body.
func testUnsupportedReportType(ctx context.Context, sess *suite.Session) error {
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

	resp, err := c.Report(ctx, colURL, unknownReportBody)
	if err != nil {
		return err
	}
	if resp.StatusCode != 403 {
		return fmt.Errorf("REPORT with unrecognised type: got %d, want 403 (RFC 3253 §3.6 MUST)", resp.StatusCode)
	}
	return assert.BodyContainsElement(resp.Body, client.NSdav, "supported-report")
}

// testReportIdempotent verifies RFC 3253 §3.6: REPORT is "non-modifying".
// Two identical initial sync-collection REPORTs on an empty collection MUST
// return the same DAV:sync-token, confirming that the first REPORT did not
// alter any observable server state.
func testReportIdempotent(ctx context.Context, sess *suite.Session) error {
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

	props := [][2]string{{client.NSdav, "getetag"}}
	body := client.ReportSyncCollection("", "1", props)

	resp1, err := c.ReportWithDepth(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp1, 207); err != nil {
		return fmt.Errorf("first REPORT: %w", err)
	}
	ms1, err := client.ParseMultistatus(resp1.Body)
	if err != nil {
		return fmt.Errorf("first REPORT: parse multistatus: %w", err)
	}
	if ms1.SyncToken == "" {
		return fmt.Errorf("first REPORT: response missing DAV:sync-token")
	}

	resp2, err := c.ReportWithDepth(ctx, colURL, "0", body)
	if err != nil {
		return err
	}
	if err := assert.StatusCode(resp2, 207); err != nil {
		return fmt.Errorf("second REPORT: %w", err)
	}
	ms2, err := client.ParseMultistatus(resp2.Body)
	if err != nil {
		return fmt.Errorf("second REPORT: parse multistatus: %w", err)
	}
	if ms2.SyncToken != ms1.SyncToken {
		return fmt.Errorf(
			"REPORT idempotence: sync-token changed after identical REPORT (%q → %q); REPORT MUST NOT modify server state (RFC 3253 §3.6)",
			ms1.SyncToken, ms2.SyncToken,
		)
	}
	return nil
}

// --- Helpers ---

func discoverHomeSet(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	principalURL, err := webdav.CurrentUserPrincipalURL(ctx, c, contextPath)
	if err != nil {
		return "", err
	}
	return webdav.AddressbookHomeSetURL(ctx, c, principalURL)
}

func makeTestCollection(ctx context.Context, c *client.Client, homeSet string) (string, func(context.Context), error) { //nolint:gocritic
	colURL := fmt.Sprintf("%sdavlint-rfc3253-%08x/", homeSet, rand.Uint32()) // #nosec G404
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
