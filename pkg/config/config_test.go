package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/sdobberstein/davlint/pkg/config"
)

func TestLoad_Valid(t *testing.T) {
	f := writeTempFile(t, `
server:
  url: "http://localhost:8080"
principals:
  - username: alice
    password: secret
severity: should
suites:
  - rfc6764
`)
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.URL != "http://localhost:8080" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "http://localhost:8080")
	}
	if len(cfg.Principals) != 1 || cfg.Principals[0].Username != "alice" || cfg.Principals[0].Password != "secret" {
		t.Errorf("Principals = %v", cfg.Principals)
	}
	if cfg.Severity != "should" {
		t.Errorf("Severity = %q, want %q", cfg.Severity, "should")
	}
	if len(cfg.Suites) != 1 || cfg.Suites[0] != "rfc6764" {
		t.Errorf("Suites = %v", cfg.Suites)
	}
}

func TestLoad_Defaults(t *testing.T) {
	f := writeTempFile(t, `
server:
  url: "http://localhost:8080"
`)
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Severity != "must" {
		t.Errorf("default Severity = %q, want %q", cfg.Severity, "must")
	}
	if cfg.Options.Timeout != 30*time.Second {
		t.Errorf("default Timeout = %v, want 30s", cfg.Options.Timeout)
	}
	if len(cfg.Report.Formats) != 1 || cfg.Report.Formats[0] != "terminal" {
		t.Errorf("default Report.Formats = %v", cfg.Report.Formats)
	}
}

func TestLoad_AllSeverityValues(t *testing.T) {
	for _, sev := range []string{"must", "should", "may"} {
		f := writeTempFile(t, "server:\n  url: \"http://localhost\"\nseverity: "+sev+"\n")
		cfg, err := config.Load(f)
		if err != nil {
			t.Errorf("severity %q: unexpected error: %v", sev, err)
			continue
		}
		if cfg.Severity != sev {
			t.Errorf("severity %q: got %q", sev, cfg.Severity)
		}
	}
}

func TestLoad_MissingServerURL(t *testing.T) {
	f := writeTempFile(t, "severity: must\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for missing server.url")
	}
}

func TestLoad_BadSeverity(t *testing.T) {
	f := writeTempFile(t, "server:\n  url: \"http://localhost\"\nseverity: extreme\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for unrecognised severity")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/no/such/davlint-file.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_BadYAML(t *testing.T) {
	f := writeTempFile(t, "{not: valid: yaml:")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "davlint-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
