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
	// Fn runs the test against the server. Return non-nil to fail.
	Fn func(ctx context.Context, sess *Session) error
}

// Result is the outcome of running a single Test.
type Result struct {
	Test    Test
	Passed  bool
	Skipped bool
	Err     error
	Elapsed time.Duration
}

// Report summarises a complete test run.
type Report struct {
	Results  []Result
	Passed   int
	Failed   int
	Skipped  int
	Duration time.Duration
}

var (
	mu       sync.Mutex
	registry []Test
)

// Register adds a Test to the global registry.
// It is safe to call from init() functions in multiple packages.
func Register(t Test) {
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

// Run executes the given tests against the server described by cfg and returns
// a Report. If there are no tests, it returns immediately without connecting.
func Run(ctx context.Context, cfg *config.Config, tests []Test) *Report {
	start := time.Now()
	report := &Report{}

	skipSet := make(map[string]bool, len(cfg.Skip))
	for _, id := range cfg.Skip {
		skipSet[id] = true
	}

	// Filter to tests whose suites are enabled and that are not skipped.
	var active []Test
	for _, t := range tests {
		if skipSet[t.ID] || !suiteEnabled(cfg.Suites, t.Suite) {
			report.Results = append(report.Results, Result{Test: t, Skipped: true})
			report.Skipped++
			continue
		}
		active = append(active, t)
	}

	if len(active) == 0 {
		report.Duration = time.Since(start)
		return report
	}

	clients, err := buildClients(cfg)
	if err != nil {
		report.Results = append(report.Results, Result{
			Test:   Test{ID: "_connection", Description: "connect to server"},
			Passed: false,
			Err:    fmt.Errorf("build clients: %w", err),
		})
		report.Failed = 1
		report.Duration = time.Since(start)
		return report
	}

	contextPath, err := discoverContextPath(ctx, cfg, clients[0])
	if err != nil {
		report.Results = append(report.Results, Result{
			Test:   Test{ID: "_discovery", Description: "discover CardDAV context path"},
			Passed: false,
			Err:    err,
		})
		report.Failed = 1
		report.Duration = time.Since(start)
		return report
	}

	for _, t := range active {
		sess := &Session{Clients: clients, ContextPath: contextPath}
		tStart := time.Now()
		testErr := t.Fn(ctx, sess)
		elapsed := time.Since(tStart)

		// Run cleanups in LIFO order.
		for i := len(sess.cleanups) - 1; i >= 0; i-- {
			sess.cleanups[i](ctx)
		}

		res := Result{Test: t, Elapsed: elapsed}
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

// discoverContextPath returns the CardDAV context path. If cfg.Server.ContextPath
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

// Session holds per-test runtime state: HTTP clients and registered cleanups.
type Session struct {
	// Clients provides one authenticated HTTP client per configured principal.
	// Clients[0] is the primary test principal.
	Clients []*client.Client
	// ContextPath is the CardDAV context path (e.g. "/dav/"), either configured
	// explicitly or discovered via the /.well-known/carddav redirect.
	ContextPath string
	cleanups    []func(ctx context.Context)
}

// Primary returns the first client (primary test principal).
func (s *Session) Primary() *client.Client {
	return s.Clients[0]
}

// AddCleanup registers fn to run after the test completes, in LIFO order.
// Use it to delete resources created during the test.
func (s *Session) AddCleanup(fn func(ctx context.Context)) {
	s.cleanups = append(s.cleanups, fn)
}
