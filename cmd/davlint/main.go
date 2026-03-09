// Package main is the entry point for the davlint CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/sdobberstein/davlint/pkg/config"
	"github.com/sdobberstein/davlint/pkg/report"
	"github.com/sdobberstein/davlint/pkg/suite"
)

const version = "0.1.0-dev"

var configFile string

var rootCmd = &cobra.Command{
	Use:     "davlint",
	Short:   "davlint — CardDAV/WebDAV conformance test tool",
	Version: version,
	Long: `davlint tests a CardDAV server for RFC conformance.

Configure the server URL and test principals in davlint.yaml, then run:

  davlint list          list all available tests
  davlint run           run all enabled test suites`,
}

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
			if _, err := fmt.Fprintf(w, "%-60s [%-6s] %s\n", t.ID, t.Severity, t.Description); err != nil {
				return err
			}
		}
		return nil
	},
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run conformance tests against a CardDAV server",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(configFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		r := suite.Run(ctx, cfg, suite.All())
		report.Terminal(cmd.OutOrStdout(), r)

		if r.Failed > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "davlint.yaml", "config file path")
	rootCmd.AddCommand(listCmd, runCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
