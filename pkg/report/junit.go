package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/sdobberstein/davlint/pkg/suite"
)

// JUnit writes a JUnit XML report to w, suitable for CI systems.
func JUnit(w io.Writer, r *suite.Report) error {
	type failure struct {
		XMLName xml.Name `xml:"failure"`
		Message string   `xml:",chardata"`
	}
	type skipped struct {
		XMLName xml.Name `xml:"skipped"`
		Message string   `xml:"message,attr,omitempty"`
	}
	type testCase struct {
		XMLName   xml.Name `xml:"testcase"`
		Classname string   `xml:"classname,attr"`
		Name      string   `xml:"name,attr"`
		Time      string   `xml:"time,attr"`
		Failure   *failure `xml:"failure,omitempty"`
		Skipped   *skipped `xml:"skipped,omitempty"`
	}
	type testSuite struct {
		XMLName   xml.Name   `xml:"testsuite"`
		Name      string     `xml:"name,attr"`
		Tests     int        `xml:"tests,attr"`
		Failures  int        `xml:"failures,attr"`
		Skipped   int        `xml:"skipped,attr"`
		Time      string     `xml:"time,attr"`
		TestCases []testCase `xml:"testcase"`
	}

	cases := make([]testCase, 0, len(r.Results))
	for i := range r.Results {
		res := &r.Results[i]
		tc := testCase{
			Classname: res.Test.Suite,
			Name:      res.Test.ID,
			Time:      fmt.Sprintf("%.3f", res.Elapsed.Seconds()),
		}
		switch {
		case res.Skipped:
			tc.Skipped = &skipped{Message: string(res.SkipReason)}
		case !res.Passed && res.Err != nil:
			tc.Failure = &failure{Message: res.Err.Error()}
		}
		cases = append(cases, tc)
	}

	ts := testSuite{
		Name:      "davlint",
		Tests:     r.Passed + r.Failed + r.Skipped,
		Failures:  r.Failed,
		Skipped:   r.Skipped,
		Time:      fmt.Sprintf("%.3f", r.Duration.Seconds()),
		TestCases: cases,
	}

	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(ts); err != nil {
		return err
	}
	return enc.Flush()
}
