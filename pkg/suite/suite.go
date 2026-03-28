// Package suite provides test registration, session management, and the
// execution engine for davlint conformance tests.
package suite

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sdobberstein/davlint/pkg/client"
	"github.com/sdobberstein/davlint/pkg/config"
)

// Severity indicates the RFC requirement level of a test.
type Severity string

// RFC requirement levels, from most to least binding.
const (
	Must   Severity = "must"
	Should Severity = "should"
	May    Severity = "may"
)

// RFCRef is a citation to a specific RFC section.
type RFCRef struct {
	RFC     string // e.g. "RFC 6578"
	Section string // e.g. "§5"
	URL     string // e.g. "https://www.rfc-editor.org/rfc/rfc6578#section-5"
}

// Test is a single conformance test that can be registered with the suite.
type Test struct {
	// ID is a unique dot-path identifier, e.g. "RFC4918.propfind-allprop".
	ID string
	// Suite groups related tests, e.g. "rfc4918".
	Suite string
	// Description is a human-readable one-liner for list output.
	Description string
	// Severity is the RFC requirement level.
	Severity Severity
	// Tags are optional labels used to filter tests (e.g. ["sync", "conditional"]).
	// Nil means untagged — the test always runs unless filtered by suite/mode/etc.
	Tags []string
	// Mode is "" or "lint" (runs in both modes) or "conformance" (skipped in lint mode).
	Mode string
	// MinPrincipals is the minimum number of configured principals required.
	// 1 is the baseline for any test that uses Primary(). 2 means
	// Secondary() must be available. 0 is reserved for tests that use only
	// Unauthenticated() and need no configured principal at all.
	MinPrincipals int
	// References are RFC section citations for this test.
	References []RFCRef
	// Fn runs the test against the server. Return non-nil to fail.
	Fn func(ctx context.Context, sess *Session) error
}

// SkipReason describes why a test was skipped.
type SkipReason string

// Skip reason constants. SkipNone means the test was not skipped; all other
// values identify the filter that caused the skip.
const (
	SkipNone       SkipReason = ""
	SkipConfig     SkipReason = "config"     // in cfg.Skip list
	SkipSuite      SkipReason = "suite"      // suite not in active set
	SkipSeverity   SkipReason = "severity"   // below configured threshold
	SkipTag        SkipReason = "tag"        // excluded by tag filter
	SkipMode       SkipReason = "mode"       // conformance-only test in lint mode
	SkipPrincipals SkipReason = "principals" // MinPrincipals not met
)

// Result is the outcome of running a single Test.
type Result struct {
	Test       Test
	Passed     bool
	Skipped    bool
	SkipReason SkipReason
	Err        error
	Elapsed    time.Duration
}

// Report summarises a complete test run.
type Report struct {
	Results           []Result
	Passed            int
	Failed            int
	Skipped           int
	SkippedConfig     int
	SkippedSuite      int
	SkippedSeverity   int
	SkippedTag        int
	SkippedMode       int
	SkippedPrincipals int
	Duration          time.Duration
}

var (
	mu       sync.Mutex
	registry []Test
)

// Register adds a Test to the global registry.
// It is safe to call from init() functions in multiple packages.
func Register(t Test) { //nolint:gocritic // hugeParam: Test is intentionally passed by value as a literal
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, t)
}

// All returns a snapshot of all registered tests, in registration order.
func All() []Test {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Test, len(registry))
	copy(out, registry)
	return out
}

// Protocol bundle definitions: map protocol name → suite IDs.
var bundles = map[string][]string{
	"webdav":  {"rfc4918"},
	"carddav": {"rfc4918", "rfc6352", "rfc6578", "rfc6764", "rfc2426"},
	"caldav":  {"rfc4918", "rfc4791", "rfc5545", "rfc7986", "rfc6578", "rfc6764"},
}

// Default excluded tags per protocol (optional features).
var bundleExcludeTags = map[string][]string{
	"webdav":  {"locking", "acl", "quota"},
	"carddav": {"locking", "acl", "quota"},
	"caldav":  {"locking", "acl", "quota"},
}

// severityOrder maps severity names to a comparable integer (higher = more permissive).
var severityOrder = map[Severity]int{
	Must:   0,
	Should: 1,
	May:    2,
}

// Run executes the given tests against the server described by cfg and returns
// a Report. If there are no tests, it returns immediately without connecting.
func Run(ctx context.Context, cfg *config.Config, tests []Test) *Report {
	start := time.Now()
	report := &Report{}

	skipSet := make(map[string]bool, len(cfg.Skip))
	for _, id := range cfg.Skip {
		skipSet[id] = true
	}

	// Resolve active suites from protocol bundle + explicit suites.
	activeSuites := cfg.Suites
	var effectiveExcludeTags []string
	if cfg.Protocol != "" {
		activeSuites = mergeSuites(bundles[cfg.Protocol], cfg.Suites)
		// Merge default exclude tags for protocol unless user explicitly opted in via Tags.
		for _, tag := range bundleExcludeTags[cfg.Protocol] {
			if !containsString(cfg.Tags, tag) {
				effectiveExcludeTags = append(effectiveExcludeTags, tag)
			}
		}
	}
	for _, tag := range cfg.ExcludeTags {
		if !containsString(effectiveExcludeTags, tag) {
			effectiveExcludeTags = append(effectiveExcludeTags, tag)
		}
	}

	// Resolve severity threshold.
	thresholdOrder, ok := severityOrder[Severity(cfg.Severity)]
	if !ok {
		thresholdOrder = severityOrder[Must]
	}

	// In discover mode, connect early so we can update activeSuites from the
	// DAV header before running the pre-filter.
	var clients []*client.Client
	var unauthed *client.Client
	if cfg.Options.Discover {
		c, err := buildClients(cfg)
		if err != nil {
			return connectError(report, start, "build clients: %w", err)
		}
		clients = c
		u, err := client.New(cfg.Server.URL, "", "", cfg.Options.Timeout)
		if err != nil {
			return connectError(report, start, "build unauthenticated client: %w", err)
		}
		unauthed = u
		discovered, discErr := discoverSuites(ctx, cfg, clients[0])
		if discErr != nil {
			discovered = nil // non-fatal: proceed with existing suite list
		}
		if len(discovered) > 0 {
			activeSuites = mergeSuites(activeSuites, discovered)
		}
	}

	// Pre-filter: config, suite, severity, tag, mode.
	// MinPrincipals is checked per-test at run time after clients are built.
	var active []Test
	for i := range tests {
		t := &tests[i]
		switch {
		case skipSet[t.ID]:
			report.addSkip(t, SkipConfig)
		case !suiteEnabled(activeSuites, t.Suite):
			report.addSkip(t, SkipSuite)
		case severityOrder[t.Severity] > thresholdOrder:
			report.addSkip(t, SkipSeverity)
		case len(cfg.Tags) > 0 && !hasAnyTag(t.Tags, cfg.Tags):
			report.addSkip(t, SkipTag)
		case hasAnyTag(t.Tags, effectiveExcludeTags):
			report.addSkip(t, SkipTag)
		case t.Mode == "conformance" && cfg.Mode != "conformance":
			report.addSkip(t, SkipMode)
		default:
			active = append(active, *t)
		}
	}

	if len(active) == 0 {
		report.Duration = time.Since(start)
		return report
	}

	// Build clients on non-discover path.
	if clients == nil {
		c, err := buildClients(cfg)
		if err != nil {
			return connectError(report, start, "build clients: %w", err)
		}
		clients = c
		u, err := client.New(cfg.Server.URL, "", "", cfg.Options.Timeout)
		if err != nil {
			return connectError(report, start, "build unauthenticated client: %w", err)
		}
		unauthed = u
	}

	contextPath, err := discoverContextPath(ctx, cfg, clients[0])
	if err != nil {
		report.Results = append(report.Results, Result{
			Test:   Test{ID: "_discovery", Description: "discover context path"},
			Passed: false,
			Err:    err,
		})
		report.Failed = 1
		report.Duration = time.Since(start)
		return report
	}

	for i := range active {
		t := &active[i]
		// MinPrincipals check at run time.
		if t.MinPrincipals > len(clients) {
			report.addSkip(t, SkipPrincipals)
			continue
		}

		sess := &Session{
			Clients:     clients,
			unauthed:    unauthed,
			ContextPath: contextPath,
			Verbose:     cfg.Options.Verbose,
		}
		tStart := time.Now()
		testErr := t.Fn(ctx, sess)
		elapsed := time.Since(tStart)

		// Run cleanups in LIFO order.
		for j := len(sess.cleanups) - 1; j >= 0; j-- {
			sess.cleanups[j](ctx)
		}

		res := Result{Test: *t, Elapsed: elapsed}
		if testErr != nil {
			res.Err = testErr
			report.Failed++
		} else {
			res.Passed = true
			report.Passed++
		}
		report.Results = append(report.Results, res)

		if cfg.Options.FailFast && !res.Passed {
			break
		}
	}

	report.Duration = time.Since(start)
	return report
}

// connectError records a connection failure result and returns the report.
func connectError(report *Report, start time.Time, format string, err error) *Report {
	report.Results = append(report.Results, Result{
		Test:   Test{ID: "_connection", Description: "connect to server"},
		Passed: false,
		Err:    fmt.Errorf(format, err),
	})
	report.Failed = 1
	report.Duration = time.Since(start)
	return report
}

// addSkip records a skipped result and increments the relevant counter.
func (r *Report) addSkip(t *Test, reason SkipReason) { //nolint:gocritic // pointer receiver; t is *Test to avoid copy
	r.Results = append(r.Results, Result{Test: *t, Skipped: true, SkipReason: reason})
	r.Skipped++
	switch reason {
	case SkipConfig:
		r.SkippedConfig++
	case SkipSuite:
		r.SkippedSuite++
	case SkipSeverity:
		r.SkippedSeverity++
	case SkipTag:
		r.SkippedTag++
	case SkipMode:
		r.SkippedMode++
	case SkipPrincipals:
		r.SkippedPrincipals++
	}
}

// discoverContextPath returns the context path. If cfg.Server.ContextPath
// is non-empty it is returned directly. Otherwise the path is discovered by
// issuing GET /.well-known/carddav and extracting the Location header from the
// redirect response (RFC 6764 §5).
func discoverContextPath(ctx context.Context, cfg *config.Config, primary *client.Client) (string, error) {
	if cfg.Server.ContextPath != "" {
		return cfg.Server.ContextPath, nil
	}
	resp, err := primary.GetNoRedirect(ctx, "/.well-known/carddav")
	if err != nil {
		return "", fmt.Errorf("discover context path: %w", err)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("discover context path: /.well-known/carddav did not return a Location header")
	}
	// Location may be an absolute URL (e.g. https://example.com/dav/) or a path.
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		u, parseErr := url.Parse(loc)
		if parseErr != nil {
			return "", fmt.Errorf("discover context path: parse Location %q: %w", loc, parseErr)
		}
		return u.Path, nil
	}
	return loc, nil
}

// davTokenSuites maps DAV header tokens to suite IDs.
var davTokenSuites = map[string][]string{
	"2":               {"rfc4918"},
	"access-control":  {"rfc3744"},
	"addressbook":     {"rfc6352", "rfc2426"},
	"calendar-access": {"rfc4791", "rfc5545", "rfc7986"},
	"sync-collection": {"rfc6578"},
	"extended-mkcol":  {"rfc5689"},
}

// discoverSuites queries OPTIONS on the context path and maps DAV tokens to suite IDs.
func discoverSuites(ctx context.Context, cfg *config.Config, primary *client.Client) ([]string, error) {
	path := cfg.Server.ContextPath
	if path == "" {
		path = "/"
	}
	resp, err := primary.Options(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("discover suites: OPTIONS %s: %w", path, err)
	}
	dav := resp.Header.Get("DAV")
	if dav == "" {
		return nil, nil
	}
	var discovered []string
	seen := make(map[string]bool)
	for _, token := range strings.Split(dav, ",") {
		token = strings.TrimSpace(token)
		if suiteIDs, ok := davTokenSuites[token]; ok {
			for _, id := range suiteIDs {
				if !seen[id] {
					seen[id] = true
					discovered = append(discovered, id)
				}
			}
		}
	}
	return discovered, nil
}

func buildClients(cfg *config.Config) ([]*client.Client, error) {
	if len(cfg.Principals) == 0 {
		return nil, fmt.Errorf("no principals configured")
	}
	clients := make([]*client.Client, 0, len(cfg.Principals))
	for _, p := range cfg.Principals {
		c, err := client.New(cfg.Server.URL, p.Username, p.Password, cfg.Options.Timeout)
		if err != nil {
			return nil, fmt.Errorf("create client for %q: %w", p.Username, err)
		}
		clients = append(clients, c)
	}
	return clients, nil
}

// suiteEnabled reports whether a test belonging to suite should run given the
// enabled suite list. An empty list means run all suites.
func suiteEnabled(suites []string, suite string) bool {
	if len(suites) == 0 {
		return true
	}
	for _, s := range suites {
		if s == suite || strings.HasPrefix(suite, s+"/") {
			return true
		}
	}
	return false
}

// mergeSuites returns a deduplicated union of two suite ID slices, preserving order.
func mergeSuites(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// hasAnyTag reports whether tags contains any element from targets.
func hasAnyTag(tags, targets []string) bool {
	for _, tag := range tags {
		for _, t := range targets {
			if tag == t {
				return true
			}
		}
	}
	return false
}

// containsString reports whether slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// Session holds per-test runtime state: HTTP clients and registered cleanups.
type Session struct {
	// Clients provides one authenticated HTTP client per configured principal.
	// Clients[0] is the primary test principal.
	Clients []*client.Client
	// unauthed is a client with no credentials against the same server.
	unauthed *client.Client
	// ContextPath is the DAV context path (e.g. "/dav/"), either configured
	// explicitly or discovered via the well-known redirect.
	ContextPath string
	// Verbose enables per-test diagnostic output to stderr.
	Verbose  bool
	cleanups []func(ctx context.Context)
}

// Primary returns the first client (primary test principal).
func (s *Session) Primary() *client.Client {
	return s.Clients[0]
}

// Secondary returns the second configured principal's client.
// Panics if fewer than 2 principals are configured.
// Tests should only call this if MinPrincipals >= 2.
func (s *Session) Secondary() *client.Client {
	if len(s.Clients) < 2 {
		panic("davlint: Session.Secondary() called but fewer than 2 principals are configured")
	}
	return s.Clients[1]
}

// Unauthenticated returns a client with no credentials against the same server.
func (s *Session) Unauthenticated() *client.Client {
	return s.unauthed
}

// AddCleanup registers fn to run after the test completes, in LIFO order.
// Use it to delete resources created during the test.
func (s *Session) AddCleanup(fn func(ctx context.Context)) {
	s.cleanups = append(s.cleanups, fn)
}
