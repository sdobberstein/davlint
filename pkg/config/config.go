// Package config loads and validates the davlint YAML configuration file.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the full davlint configuration.
type Config struct {
	Server struct {
		URL string `yaml:"url"`
		// ContextPath is the CardDAV/CalDAV/WebDAV context path (e.g. "/dav/").
		// If empty, it is discovered by following the /.well-known/carddav redirect.
		ContextPath string `yaml:"context_path"`
	} `yaml:"server"`
	Principals  []Principal `yaml:"principals"`
	Protocol    string      `yaml:"protocol"`      // carddav | caldav | webdav
	Mode        string      `yaml:"mode"`          // lint | conformance (default: lint)
	Suites      []string    `yaml:"suites"`
	Tags        []string    `yaml:"tags"`          // include only tests with these tags
	ExcludeTags []string    `yaml:"exclude_tags"`  // exclude tests with these tags
	Skip        []string    `yaml:"skip"`
	Severity    string      `yaml:"severity"`
	Report      struct {
		Formats []string `yaml:"formats"`
		Output  string   `yaml:"output"`
	} `yaml:"report"`
	Options struct {
		Cleanup  bool          `yaml:"cleanup"`
		Timeout  time.Duration `yaml:"timeout"`
		FailFast bool          `yaml:"fail_fast"`
		Verbose  bool          `yaml:"verbose"`
		Discover bool          `yaml:"discover"`
	} `yaml:"options"`
}

// Principal is a test account credential pair.
type Principal struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Load reads and parses the YAML config file at path, applying defaults for
// any omitted fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- user-supplied config file path is intentional
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Severity == "" {
		c.Severity = "must"
	}
	if c.Mode == "" {
		c.Mode = "lint"
	}
	if c.Options.Timeout == 0 {
		c.Options.Timeout = 30 * time.Second
	}
	if len(c.Report.Formats) == 0 {
		c.Report.Formats = []string{"terminal"}
	}
}

func (c *Config) validate() error {
	if c.Server.URL == "" {
		return fmt.Errorf("server.url is required")
	}
	switch c.Severity {
	case "must", "should", "may":
	default:
		return fmt.Errorf("severity must be one of: must, should, may")
	}
	switch c.Mode {
	case "lint", "conformance":
	default:
		return fmt.Errorf("mode must be one of: lint, conformance")
	}
	switch c.Protocol {
	case "", "webdav", "carddav", "caldav":
	default:
		return fmt.Errorf("protocol must be one of: webdav, carddav, caldav")
	}
	return nil
}
