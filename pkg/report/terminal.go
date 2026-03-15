// Package report provides output formatters for davlint test results.
package report

import (
	"fmt"
	"io"
	"time"

	"github.com/sdobberstein/davlint/pkg/suite"
)

// Terminal prints a human-readable pass/fail summary to w.
func Terminal(w io.Writer, r *suite.Report) {
	tw := &safeWriter{w: w}
	for i := range r.Results {
		res := &r.Results[i]
		switch {
		case res.Skipped:
			tw.printf("  SKIP  %-55s %s\n", res.Test.ID, skipDetail(res))
		case res.Passed:
			tw.printf("  PASS  %s\n", res.Test.ID)
		default:
			tw.printf("  FAIL  %s — %v\n", res.Test.ID, res.Err)
		}
	}

	// Summary line.
	skipSuffix := ""
	if r.Skipped > 0 {
		var parts []string
		if r.SkippedPrincipals > 0 {
			parts = append(parts, fmt.Sprintf("%d missing principals", r.SkippedPrincipals))
		}
		if r.SkippedTag > 0 {
			parts = append(parts, fmt.Sprintf("%d excluded", r.SkippedTag))
		}
		if r.SkippedMode > 0 {
			parts = append(parts, fmt.Sprintf("%d mode", r.SkippedMode))
		}
		if r.SkippedSeverity > 0 {
			parts = append(parts, fmt.Sprintf("%d severity", r.SkippedSeverity))
		}
		if r.SkippedSuite > 0 {
			parts = append(parts, fmt.Sprintf("%d suite", r.SkippedSuite))
		}
		if r.SkippedConfig > 0 {
			parts = append(parts, fmt.Sprintf("%d config", r.SkippedConfig))
		}
		if len(parts) > 0 {
			skipSuffix = " (" + joinStrings(parts, ", ") + ")"
		}
	}

	tw.printf("\n%d passed  %d failed  %d skipped%s  %s\n",
		r.Passed, r.Failed, r.Skipped, skipSuffix, r.Duration.Round(time.Millisecond))

	if r.SkippedPrincipals > 0 {
		tw.printf("Tip: configure additional principals to run %d more tests (see docs/design/principals.md)\n",
			r.SkippedPrincipals)
	}

	if tw.err != nil {
		// Nothing useful we can do if stdout itself is broken.
		_ = tw.err
	}
}

// skipDetail returns a human-readable explanation for a skipped result.
func skipDetail(res *suite.Result) string {
	switch res.SkipReason {
	case suite.SkipPrincipals:
		return fmt.Sprintf("requires %d principals", res.Test.MinPrincipals)
	case suite.SkipTag:
		return "excluded by tag filter"
	case suite.SkipMode:
		return "conformance-only test"
	case suite.SkipSeverity:
		return "below severity threshold"
	case suite.SkipSuite:
		return "suite not active"
	case suite.SkipConfig:
		return "in skip list"
	default:
		return ""
	}
}

// joinStrings joins a slice of strings with sep.
func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}

// safeWriter accumulates the first write error and suppresses subsequent writes,
// avoiding repeated errcheck violations on fmt.Fprintf calls to terminal output.
type safeWriter struct {
	w   io.Writer
	err error
}

func (s *safeWriter) printf(format string, args ...any) {
	if s.err != nil {
		return
	}
	_, s.err = fmt.Fprintf(s.w, format, args...)
}
