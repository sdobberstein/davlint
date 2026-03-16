// Package main is the entry point for the davlint CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/sdobberstein/davlint/pkg/config"
	"github.com/sdobberstein/davlint/pkg/report"
	"github.com/sdobberstein/davlint/pkg/suite"

	// Register conformance test suites.
	_ "github.com/sdobberstein/davlint/internal/suites/rfc2426"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc4918"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc5689"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc6350"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc6352"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc6578"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc6764"
	_ "github.com/sdobberstein/davlint/internal/suites/rfc7232"
)

const version = "0.1.0-dev"

var (
	configFile string
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:     "davlint",
	Short:   "davlint — CardDAV/WebDAV conformance test tool",
	Version: version,
	Long: `davlint tests a CardDAV/CalDAV/WebDAV server for RFC conformance.

Configure the server URL and test principals in davlint.yaml, then run:

  davlint list          list all available tests
  davlint run           run all enabled test suites`,
}

// list flags
var (
	listProtocol string
	listSuites   []string
	listTags     []string
	listMode     string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available conformance tests",
	RunE: func(cmd *cobra.Command, _ []string) error {
		tests := suite.All()
		w := cmd.OutOrStdout()
		if len(tests) == 0 {
			_, err := fmt.Fprintln(w, "No tests registered.")
			return err
		}
		for _, t := range tests {
			// Apply list filters.
			if listProtocol != "" && !suiteInProtocol(t.Suite, listProtocol) {
				continue
			}
			if len(listSuites) > 0 && !containsString(listSuites, t.Suite) {
				continue
			}
			if len(listTags) > 0 && !hasAnyTag(t.Tags, listTags) {
				continue
			}
			if listMode != "conformance" && t.Mode == "conformance" {
				continue
			}

			tags := strings.Join(t.Tags, ",")
			refs := formatRefs(t.References)
			if _, err := fmt.Fprintf(w, "%-55s [%-6s] [%-12s] %-12s %s%s\n",
				t.ID, t.Severity, t.Mode, tags, t.Description, refs); err != nil {
				return err
			}
		}
		return nil
	},
}

// run flags
var (
	runMode        string
	runProtocol    string
	runSuites      []string
	runTags        []string
	runExcludeTags []string
	runDiscover    bool
	runFailFast    bool
	runFormats     []string
	runOutput      string
)

var runCmd = &cobra.Command{
	Use:   "run [TEST_ID...]",
	Short: "Run conformance tests against a server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(configFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// CLI flags override config.
		if verbose {
			cfg.Options.Verbose = true
		}
		if runMode != "" {
			cfg.Mode = runMode
		}
		if runProtocol != "" {
			cfg.Protocol = runProtocol
		}
		if len(runSuites) > 0 {
			cfg.Suites = append(cfg.Suites, runSuites...)
		}
		if len(runTags) > 0 {
			cfg.Tags = append(cfg.Tags, runTags...)
		}
		if len(runExcludeTags) > 0 {
			cfg.ExcludeTags = append(cfg.ExcludeTags, runExcludeTags...)
		}
		if runDiscover {
			cfg.Options.Discover = true
		}
		if runFailFast {
			cfg.Options.FailFast = true
		}
		if len(runFormats) > 0 {
			cfg.Report.Formats = runFormats
		}
		if runOutput != "" {
			cfg.Report.Output = runOutput
		}

		// Positional args are test ID selectors.
		tests := suite.All()
		if len(args) > 0 {
			tests = filterByID(tests, args)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		r := suite.Run(ctx, cfg, tests)

		if err := writeReports(cmd, cfg, r); err != nil {
			return err
		}

		if r.Failed > 0 {
			os.Exit(1)
		}
		return nil
	},
}

// writeReports dispatches to the configured output formatters.
func writeReports(cmd *cobra.Command, cfg *config.Config, r *suite.Report) error {
	for _, format := range cfg.Report.Formats {
		if err := writeReport(cmd, cfg.Report.Output, r, format); err != nil {
			return err
		}
	}
	return nil
}

// writeReport writes a single format, opening and closing the output file.
func writeReport(cmd *cobra.Command, outputPath string, r *suite.Report, format string) (retErr error) {
	w, closer, err := openOutput(cmd, outputPath, format)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closer(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("close report output: %w", cerr)
		}
	}()
	switch format {
	case "terminal":
		report.Terminal(w, r)
		return nil
	case "json":
		return report.JSON(w, r)
	case "junit":
		return report.JUnit(w, r)
	case "markdown":
		return report.Markdown(w, r)
	default:
		return fmt.Errorf("unknown report format %q", format)
	}
}

// openOutput returns a writer for the given format. Terminal format always
// writes to cmd stdout; other formats write to the output path (if set) or stdout.
// The returned closer must be called to flush/close file writers; for stdout it is a no-op.
func openOutput(cmd *cobra.Command, outputPath, format string) (w interface{ Write([]byte) (int, error) }, closer func() error, err error) {
	noClose := func() error { return nil }
	if format == "terminal" || outputPath == "" {
		return cmd.OutOrStdout(), noClose, nil
	}
	// Derive per-format filename if outputPath has no extension or ends in "/".
	path := outputPath
	if strings.HasSuffix(path, "/") || filepath.Ext(path) == "" {
		ext := map[string]string{
			"json":     ".json",
			"junit":    ".xml",
			"markdown": ".md",
		}[format]
		path = strings.TrimSuffix(path, "/") + "/davlint-report" + ext
	}
	f, err := os.Create(path) // #nosec G304 — user-supplied output path is intentional
	if err != nil {
		return nil, nil, fmt.Errorf("open output %q: %w", path, err)
	}
	return f, f.Close, nil
}

// filterByID returns tests whose IDs match any of the given selectors.
// Selectors may be exact IDs or glob-style patterns (e.g. "rfc6578.*").
func filterByID(tests []suite.Test, selectors []string) []suite.Test {
	var out []suite.Test
	for i := range tests {
		for _, sel := range selectors {
			if matchesSelector(tests[i].ID, sel) {
				out = append(out, tests[i])
				break
			}
		}
	}
	return out
}

// matchesSelector returns true if id matches the selector, which may use "*"
// as a wildcard segment.
func matchesSelector(id, sel string) bool {
	if sel == id {
		return true
	}
	// Simple prefix wildcard: "rfc6578.*" matches "rfc6578.anything".
	if strings.HasSuffix(sel, ".*") {
		prefix := strings.TrimSuffix(sel, ".*")
		return strings.HasPrefix(id, prefix+".")
	}
	return false
}

// suiteInProtocol reports whether the given suite ID belongs to the named protocol bundle.
var protocolBundles = map[string][]string{
	"webdav":  {"rfc4918", "rfc7232"},
	"carddav": {"rfc4918", "rfc6352", "rfc6578", "rfc6764", "rfc2426", "rfc7232"},
	"caldav":  {"rfc4918", "rfc4791", "rfc6578", "rfc6764", "rfc7232"},
}

func suiteInProtocol(suiteID, protocol string) bool {
	for _, s := range protocolBundles[protocol] {
		if s == suiteID {
			return true
		}
	}
	return false
}

// formatRefs formats RFC references as a short string for list output.
func formatRefs(refs []suite.RFCRef) string {
	if len(refs) == 0 {
		return ""
	}
	var parts []string
	for _, r := range refs {
		parts = append(parts, r.RFC+" "+r.Section)
	}
	return " [" + strings.Join(parts, ", ") + "]"
}

// hasAnyTag and containsString are local helpers (mirrors of suite-internal helpers).
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

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "davlint.yaml", "config file path")

	// run flags
	runCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print raw sent/received values for diagnostic output")
	runCmd.Flags().StringVar(&runMode, "mode", "", "override mode: lint or conformance")
	runCmd.Flags().StringVar(&runProtocol, "protocol", "", "activate protocol bundle: carddav, caldav, webdav")
	runCmd.Flags().StringArrayVar(&runSuites, "suite", nil, "add suite to active set (repeatable)")
	runCmd.Flags().StringArrayVar(&runTags, "tag", nil, "include only tests with tag (repeatable)")
	runCmd.Flags().StringArrayVar(&runExcludeTags, "exclude-tag", nil, "exclude tests with tag (repeatable)")
	runCmd.Flags().BoolVar(&runDiscover, "discover", false, "auto-select tests from server DAV header")
	runCmd.Flags().BoolVar(&runFailFast, "fail-fast", false, "stop after first failure")
	runCmd.Flags().StringArrayVar(&runFormats, "format", nil, "output format: terminal, json, junit, markdown (repeatable)")
	runCmd.Flags().StringVar(&runOutput, "output", "", "write non-terminal output to file or directory")

	// list flags
	listCmd.Flags().StringVar(&listProtocol, "protocol", "", "filter by protocol bundle: carddav, caldav, webdav")
	listCmd.Flags().StringArrayVar(&listSuites, "suite", nil, "filter by suite (repeatable)")
	listCmd.Flags().StringArrayVar(&listTags, "tag", nil, "include only tests with tag (repeatable)")
	listCmd.Flags().StringVar(&listMode, "mode", "", "include conformance-only tests (pass --mode conformance)")

	rootCmd.AddCommand(listCmd, runCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
