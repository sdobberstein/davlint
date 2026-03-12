# CLI Design

## Subcommands

```
davlint run    Run tests against a server
davlint list   List available tests (with filtering)
```

## Run Flags

### Mode

```
--mode lint           (default) One representative test per requirement. Fast, low noise.
--mode conformance    Exhaustive — all method/resource/depth variants. Full RFC certification.
```

### Protocol Bundles

```
--protocol carddav    Run all suites required for a CardDAV server
--protocol caldav     Run all suites required for a CalDAV server (future)
--protocol webdav     Run core WebDAV suites only
```

Protocol bundles select the right combination of RFC suites automatically. A user building a CardDAV server should not need to know that CardDAV requires RFC 4918, RFC 6352, RFC 6578, RFC 6764, and RFC 2426.

Multiple `--protocol` flags may be combined. Protocol selection and explicit suite selection (`--suite`) may also be combined.

### Suite Selection

```
--suite rfc6578                   Run a specific RFC suite
--suite rfc6578 --suite rfc6352   Run multiple suites
```

### Tag Filtering

`--tag` is additive — include only tests with this tag. `--exclude-tag` is reductive — remove tests with this tag from the active set. Both override protocol bundle defaults.

```
--tag locking                      Opt in to locking tests (excluded from bundles by default)
--tag sync --tag conditional       Run only tests tagged "sync" or "conditional"
--exclude-tag sync                 Remove sync tests from the active set
--exclude-tag locking --exclude-tag acl
```

Optional features (`locking`, `acl`, `quota`) are excluded from protocol bundle runs by default — the bundle knows they are optional. Users do not need to manually exclude them. `--tag locking` explicitly opts back in.

### Discovery Mode

```
--discover    Query the server's OPTIONS/DAV header and auto-select applicable tests
```

Discovery mode queries the target server before running any tests and selects test suites based on the DAV compliance tokens the server advertises. It combines naturally with `--mode`:

```
davlint run --discover --mode conformance
```

### Individual Test Targeting

```
davlint run rfc6578.if-header-stale-token        Run a single test by ID
davlint run rfc6578.if-header-*                  Glob matching on test IDs
```

This is the primary workflow during active development of a specific feature.

### Output

```
--format terminal    (default) Human-readable colored output
--format json        Machine-readable structured output
--format junit       JUnit XML for CI systems
--format markdown    Markdown table (for PR comments, README badges)
--output FILE        Write non-terminal output to FILE (default: stdout)
```

Multiple `--format` flags may be combined. Terminal output always goes to stdout; file formats go to `--output` or stdout if not specified.

### Other Flags

```
--config FILE        Config file path (default: davlint.yaml)
--verbose / -v       Print raw sent/received values for diagnostic output
--fail-fast          Stop after first failure
```

## Config File

The config file is the primary interface for persistent settings. CLI flags override config file values.

```yaml
server:
  url: https://carddav.example.com
  context_path: /dav/          # optional; discovered via well-known if omitted

principals:
  - username: testuser
    password: secret

# Protocol bundle (equivalent to --protocol carddav)
protocol: carddav

# Mode (equivalent to --mode conformance)
mode: conformance

# Tag exclusions (equivalent to --exclude-tag locking)
exclude_tags:
  - locking

# Skip specific tests by ID
skip:
  - rfc6578.client-limit

# Severity filter — only run must-level tests
severity: must

report:
  formats:
    - terminal
    - json
  output: ./results/davlint.json

options:
  timeout: 30s
  fail_fast: false
  verbose: false
```

## List Command

```
davlint list                          List all tests
davlint list --protocol carddav       List tests in a protocol bundle
davlint list --tag sync               List tests with a given tag
davlint list --mode conformance       Include conformance-only tests in the list
```

Output columns: test ID, severity, mode, tags, RFC references, description.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All tests passed |
| `1` | One or more tests failed |
| `2` | Configuration or connection error |

Exit code `2` allows scripts to distinguish "server is unreachable" from "server is reachable but non-conformant."
