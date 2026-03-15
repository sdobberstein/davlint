package report

import (
	"fmt"
	"io"
	"time"

	"github.com/sdobberstein/davlint/pkg/suite"
)

// Markdown writes a Markdown table report to w.
func Markdown(w io.Writer, r *suite.Report) error {
	sw := &safeWriter{w: w}

	sw.printf("| Status | Test ID | Severity | Description | Error |\n")
	sw.printf("|--------|---------|----------|-------------|-------|\n")

	for i := range r.Results {
		res := &r.Results[i]
		var status, errStr string
		switch {
		case res.Skipped:
			status = "⏭ SKIP"
			errStr = string(res.SkipReason)
		case res.Passed:
			status = "✅ PASS"
		default:
			status = "❌ FAIL"
			if res.Err != nil {
				errStr = res.Err.Error()
			}
		}
		sw.printf("| %s | `%s` | %s | %s | %s |\n",
			status, res.Test.ID, res.Test.Severity, res.Test.Description, errStr)
	}

	sw.printf("\n**%d passed  %d failed  %d skipped** in %s\n",
		r.Passed, r.Failed, r.Skipped, r.Duration.Round(time.Millisecond))

	return sw.err
}

// markdownEscape escapes pipe characters that would break a Markdown table cell.
func markdownEscape(s string) string {
	out := ""
	for _, c := range s {
		if c == '|' {
			out += `\|`
		} else {
			out += fmt.Sprintf("%c", c)
		}
	}
	return out
}

// ensure markdownEscape is not flagged as unused if callers prefer inline escaping.
var _ = markdownEscape
