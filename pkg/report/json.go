package report

import (
	"encoding/json"
	"io"

	"github.com/sdobberstein/davlint/pkg/suite"
)

// jsonResult is the serialisable form of a single test result.
type jsonResult struct {
	ID          string          `json:"id"`
	Suite       string          `json:"suite"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Tags        []string        `json:"tags,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	References  []suite.RFCRef  `json:"references,omitempty"`
	Status      string          `json:"status"` // "pass" | "fail" | "skip"
	SkipReason  string          `json:"skip_reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	ElapsedMs   int64           `json:"elapsed_ms,omitempty"`
}

// jsonReport is the top-level JSON structure.
type jsonReport struct {
	Passed            int          `json:"passed"`
	Failed            int          `json:"failed"`
	Skipped           int          `json:"skipped"`
	SkippedConfig     int          `json:"skipped_config,omitempty"`
	SkippedSuite      int          `json:"skipped_suite,omitempty"`
	SkippedSeverity   int          `json:"skipped_severity,omitempty"`
	SkippedTag        int          `json:"skipped_tag,omitempty"`
	SkippedMode       int          `json:"skipped_mode,omitempty"`
	SkippedPrincipals int          `json:"skipped_principals,omitempty"`
	DurationMs        int64        `json:"duration_ms"`
	Results           []jsonResult `json:"results"`
}

// JSON writes a structured JSON report to w.
func JSON(w io.Writer, r *suite.Report) error {
	results := make([]jsonResult, 0, len(r.Results))
	for i := range r.Results {
		res := &r.Results[i]
		jr := jsonResult{
			ID:          res.Test.ID,
			Suite:       res.Test.Suite,
			Description: res.Test.Description,
			Severity:    string(res.Test.Severity),
			Tags:        res.Test.Tags,
			Mode:        res.Test.Mode,
			References:  res.Test.References,
			ElapsedMs:   res.Elapsed.Milliseconds(),
		}
		switch {
		case res.Skipped:
			jr.Status = "skip"
			jr.SkipReason = string(res.SkipReason)
		case res.Passed:
			jr.Status = "pass"
		default:
			jr.Status = "fail"
			if res.Err != nil {
				jr.Error = res.Err.Error()
			}
		}
		results = append(results, jr)
	}
	out := jsonReport{
		Passed:            r.Passed,
		Failed:            r.Failed,
		Skipped:           r.Skipped,
		SkippedConfig:     r.SkippedConfig,
		SkippedSuite:      r.SkippedSuite,
		SkippedSeverity:   r.SkippedSeverity,
		SkippedTag:        r.SkippedTag,
		SkippedMode:       r.SkippedMode,
		SkippedPrincipals: r.SkippedPrincipals,
		DurationMs:        r.Duration.Milliseconds(),
		Results:           results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
