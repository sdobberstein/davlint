package suite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sdobberstein/davlint/pkg/config"
	"github.com/sdobberstein/davlint/pkg/suite"
)

// minCfg returns a minimal valid Config with no principals and no suite filter.
// Tests that exercise Run with active tests must add principals.
func minCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Server.URL = "http://localhost:8080"
	// Set ContextPath explicitly so Run() skips the /.well-known/carddav
	// network round-trip during unit tests (no real server is running).
	cfg.Server.ContextPath = "/dav/"
	cfg.Severity = "must"
	cfg.Options.Timeout = 5 * time.Second
	return cfg
}

// noopTest returns a Test that always passes.
func noopTest(id, s string) suite.Test {
	return suite.Test{
		ID:       id,
		Suite:    s,
		Severity: suite.Must,
		Fn:       func(_ context.Context, _ *suite.Session) error { return nil },
	}
}

// failTest returns a Test that always returns the given error.
func failTest(id, s string, err error) suite.Test {
	return suite.Test{
		ID:       id,
		Suite:    s,
		Severity: suite.Must,
		Fn:       func(_ context.Context, _ *suite.Session) error { return err },
	}
}

// --- Register / All ---

func TestRegisterAll_RoundTrip(t *testing.T) {
	before := len(suite.All())
	suite.Register(noopTest("test.register.smoke", "smoke"))
	after := suite.All()
	if len(after) != before+1 {
		t.Errorf("All() length: got %d, want %d", len(after), before+1)
	}
}

// --- Run with no tests ---

func TestRun_NoTests(t *testing.T) {
	r := suite.Run(context.Background(), minCfg(), nil)
	if r.Passed != 0 || r.Failed != 0 || r.Skipped != 0 {
		t.Errorf("expected empty report, got %+v", r)
	}
}

// --- Suite filtering ---

func TestRun_SuiteFilter_ExactMatch(t *testing.T) {
	cfg := minCfg()
	cfg.Suites = []string{"rfc4918"}
	tests := []suite.Test{noopTest("a", "rfc4918"), noopTest("b", "rfc6764")}
	r := suite.Run(context.Background(), cfg, tests)
	// "b" should be skipped; "a" passes — but no principals → buildClients error
	// We only care about the skip count here: "b" should be skipped.
	if r.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", r.Skipped)
	}
}

func TestRun_SuiteFilter_SubSuiteIncluded(t *testing.T) {
	// Config enables "rfc4918"; a test with Suite "rfc4918/locking" must also run.
	cfg := minCfg()
	cfg.Suites = []string{"rfc4918"}
	tests := []suite.Test{
		noopTest("lock.test", "rfc4918/locking"),
		noopTest("other.test", "rfc6764"),
	}
	r := suite.Run(context.Background(), cfg, tests)
	// "rfc4918/locking" is active (needs a principal → fails on connect, counted as failed)
	// "rfc6764" is skipped
	if r.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (rfc6764 test skipped)", r.Skipped)
	}
}

func TestRun_SuiteFilter_EmptyMeansAll(t *testing.T) {
	// No suite filter → all tests are active.
	cfg := minCfg()
	// cfg.Suites is nil
	tests := []suite.Test{
		noopTest("a", "rfc4918"),
		noopTest("b", "rfc6764"),
	}
	r := suite.Run(context.Background(), cfg, tests)
	if r.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0 when no suite filter", r.Skipped)
	}
}

func TestRun_SuiteFilter_NarrowSuiteExcludesParent(t *testing.T) {
	// Config enables only "rfc4918/locking"; a test with Suite "rfc4918" must NOT run.
	cfg := minCfg()
	cfg.Suites = []string{"rfc4918/locking"}
	tests := []suite.Test{
		noopTest("core.test", "rfc4918"),
		noopTest("lock.test", "rfc4918/locking"),
	}
	r := suite.Run(context.Background(), cfg, tests)
	if r.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (rfc4918 core test skipped)", r.Skipped)
	}
}

// --- Skip set ---

func TestRun_SkipSet(t *testing.T) {
	cfg := minCfg()
	cfg.Skip = []string{"test.to.skip"}
	tests := []suite.Test{
		noopTest("test.to.skip", "rfc4918"),
		noopTest("test.to.run", "rfc4918"),
	}
	r := suite.Run(context.Background(), cfg, tests)
	if r.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", r.Skipped)
	}
}

// --- Pass / fail ---

func TestRun_PassingTest(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}
	tests := []suite.Test{noopTest("pass.test", "rfc4918")}
	r := suite.Run(context.Background(), cfg, tests)
	if r.Passed != 1 || r.Failed != 0 {
		t.Errorf("Passed=%d Failed=%d, want Passed=1 Failed=0", r.Passed, r.Failed)
	}
}

func TestRun_FailingTest(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}
	sentinel := errors.New("expected failure")
	tests := []suite.Test{failTest("fail.test", "rfc4918", sentinel)}
	r := suite.Run(context.Background(), cfg, tests)
	if r.Failed != 1 || r.Passed != 0 {
		t.Errorf("Passed=%d Failed=%d, want Passed=0 Failed=1", r.Passed, r.Failed)
	}
	if !errors.Is(r.Results[0].Err, sentinel) {
		t.Errorf("result Err = %v, want sentinel", r.Results[0].Err)
	}
}

// --- FailFast ---

func TestRun_FailFast(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}
	cfg.Options.FailFast = true

	ran := 0
	countTest := suite.Test{
		ID:       "failfast.counter",
		Suite:    "rfc4918",
		Severity: suite.Must,
		Fn: func(_ context.Context, _ *suite.Session) error {
			ran++
			return nil
		},
	}
	tests := []suite.Test{
		failTest("failfast.first", "rfc4918", errors.New("boom")),
		countTest,
	}
	r := suite.Run(context.Background(), cfg, tests)
	if ran != 0 {
		t.Errorf("second test ran despite fail_fast, ran=%d", ran)
	}
	if r.Failed != 1 {
		t.Errorf("Failed = %d, want 1", r.Failed)
	}
}

// --- Cleanup ---

func TestRun_CleanupRunsAfterTest(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}

	cleaned := false
	tests := []suite.Test{{
		ID:       "cleanup.test",
		Suite:    "rfc4918",
		Severity: suite.Must,
		Fn: func(_ context.Context, sess *suite.Session) error {
			sess.AddCleanup(func(_ context.Context) { cleaned = true })
			return nil
		},
	}}
	suite.Run(context.Background(), cfg, tests)
	if !cleaned {
		t.Error("cleanup was not called after test")
	}
}

func TestRun_CleanupRunsEvenOnFailure(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}

	cleaned := false
	tests := []suite.Test{{
		ID:       "cleanup.fail.test",
		Suite:    "rfc4918",
		Severity: suite.Must,
		Fn: func(_ context.Context, sess *suite.Session) error {
			sess.AddCleanup(func(_ context.Context) { cleaned = true })
			return errors.New("test error")
		},
	}}
	suite.Run(context.Background(), cfg, tests)
	if !cleaned {
		t.Error("cleanup was not called after failing test")
	}
}

func TestRun_CleanupLIFOOrder(t *testing.T) {
	cfg := minCfg()
	cfg.Principals = []config.Principal{{Username: "u", Password: "p"}}

	var order []int
	tests := []suite.Test{{
		ID:       "cleanup.lifo.test",
		Suite:    "rfc4918",
		Severity: suite.Must,
		Fn: func(_ context.Context, sess *suite.Session) error {
			sess.AddCleanup(func(_ context.Context) { order = append(order, 1) })
			sess.AddCleanup(func(_ context.Context) { order = append(order, 2) })
			sess.AddCleanup(func(_ context.Context) { order = append(order, 3) })
			return nil
		},
	}}
	suite.Run(context.Background(), cfg, tests)
	if len(order) != 3 || order[0] != 3 || order[1] != 2 || order[2] != 1 {
		t.Errorf("cleanup order = %v, want [3 2 1]", order)
	}
}
