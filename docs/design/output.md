# Output Formats

## Formats

### terminal (default)

Human-readable, colored. Intended for interactive use. Not stable for parsing.

```
PASS rfc6578.sync-token-property       0.12s
PASS rfc6578.initial-sync              0.34s
FAIL rfc6578.if-header-stale-token     0.21s
     PROPFIND with stale sync-token in If header must return 412 Precondition Failed
     got 200, want 412
     See: RFC 6578 §5  https://www.rfc-editor.org/rfc/rfc6578#section-5
          RFC 4918 §10.4  https://www.rfc-editor.org/rfc/rfc4918#section-10.4

────────────────────────────────────
23 passed  1 failed  4 skipped  1.4s
```

### json

Machine-readable. Full fidelity. Intended for tooling, dashboards, badge services, and result diffing.

**Schema:**

```json
{
  "version": "1",
  "summary": {
    "passed": 23,
    "failed": 1,
    "skipped": 4,
    "duration_ms": 1402,
    "mode": "lint",
    "protocol": "carddav"
  },
  "results": [
    {
      "id": "rfc6578.if-header-stale-token",
      "suite": "rfc6578",
      "description": "PROPFIND with stale sync-token in If header must return 412 Precondition Failed",
      "severity": "must",
      "mode": "lint",
      "tags": ["conditional", "sync"],
      "protocols": ["carddav", "caldav"],
      "references": [
        {
          "rfc": "RFC 6578",
          "section": "§5",
          "url": "https://www.rfc-editor.org/rfc/rfc6578#section-5"
        },
        {
          "rfc": "RFC 4918",
          "section": "§10.4",
          "url": "https://www.rfc-editor.org/rfc/rfc4918#section-10.4"
        }
      ],
      "passed": false,
      "skipped": false,
      "error": "got 200, want 412",
      "duration_ms": 210
    }
  ]
}
```

The `summary` block is designed for trivial parsing by badge services and dashboards. The `results` array contains full detail per test.

### junit

JUnit XML. CI systems (GitHub Actions, Jenkins, GitLab CI) natively consume this format for test result visualization and trend tracking. No extra configuration required in most CI environments.

### markdown

Markdown table. Useful for posting results in GitHub PR comments or embedding a results snapshot in a README.

```markdown
| Test | Severity | Result | Duration |
|------|----------|--------|----------|
| rfc6578.sync-token-property | must | ✅ pass | 0.12s |
| rfc6578.if-header-stale-token | must | ❌ fail | 0.21s |
```

## Multiple Simultaneous Formats

Multiple formats may be specified. Terminal output always goes to stdout. File formats go to `--output` or stdout if not specified.

```
davlint run --format terminal --format json --output results/davlint.json
```

In config:

```yaml
report:
  formats:
    - terminal
    - json
    - junit
  output: ./results/davlint.json
```

When multiple non-terminal formats are specified with a single `--output`, each format is written to `{output}.{ext}` (e.g., `davlint.json`, `davlint.xml`).

## RFC References in Output

Every test failure in terminal and JSON output includes links to the relevant RFC sections. rfc-editor.org uses stable `#section-N` anchors, so URLs can be generated programmatically from the RFC number and section rather than being hardcoded per test.

This is intentional: the primary audience is server developers who need to understand *why* something is required, not just *what* failed.
