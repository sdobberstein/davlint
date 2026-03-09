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
	for _, res := range r.Results {
		switch {
		case res.Skipped:
			tw.printf("  SKIP  %s\n", res.Test.ID)
		case res.Passed:
			tw.printf("  PASS  %s\n", res.Test.ID)
		default:
			tw.printf("  FAIL  %s — %v\n", res.Test.ID, res.Err)
		}
	}
	tw.printf("\n%d passed, %d failed, %d skipped in %s\n",
		r.Passed, r.Failed, r.Skipped, r.Duration.Round(time.Millisecond))
	if tw.err != nil {
		// Nothing useful we can do if stdout itself is broken.
		_ = tw.err
	}
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
