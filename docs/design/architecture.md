# Architecture

## Goal

davlint is a conformance testing tool for CardDAV, CalDAV, and WebDAV servers. It is aimed at developers building new servers who want fast, actionable feedback during development and a path to full RFC conformance before shipping.

## Two Modes of Operation

The tool operates in one of two modes, selected via `--mode`:

### Lint mode (default)

One representative test per RFC requirement. A pass means "no obvious conformance issues found." This is fast, low-noise, and suitable for CI and daily development iteration. It does not guarantee full correctness.

### Conformance mode (`--mode conformance`)

Exhaustive coverage — all HTTP method variants, resource types, Depth values, and edge cases that the RFC specifies. A pass is a meaningful claim of correctness. This is intended for pre-ship validation.

**Example:** `rfc6578.if-header-stale-token` in lint mode tests only PROPFIND. In conformance mode it also tests PUT, DELETE, and MKCOL with a stale token in the `If` header.

## Protocol Bundles

Users think in protocols, not RFCs. The `--protocol` flag selects a curated bundle of RFC suites appropriate for a given protocol:

| Protocol | RFC Suites Included | Tags excluded by default |
|----------|-------------------|--------------------------|
| `webdav` | rfc4918 | `locking`, `acl`, `quota` |
| `carddav` | rfc4918, rfc6352, rfc6578, rfc6764, rfc2426 | `locking`, `acl`, `quota` |
| `caldav` | rfc4918, rfc4791, rfc6578, rfc6764 *(future)* | `locking`, `acl`, `quota` |

A server developer building a CardDAV server runs `--protocol carddav` and gets all the relevant suites automatically, without needing to know which RFCs apply.

**The bundle owns default exclusions.** Optional features (locking, ACL, quota) are excluded from protocol bundle runs by default because not every server implements them — a server can be fully conformant without supporting locking. The bundle author knows which features are optional; the user shouldn't have to.

Default exclusions can be overridden explicitly on the CLI:

```
davlint run --protocol carddav --tag locking   # opt in to locking tests
```

Discovery mode bypasses bundle exclusions entirely — if the server advertises `2` in the DAV header, locking tests run regardless of what the bundle excludes. If the server claims support, it gets held accountable.

## Tags

Tests are tagged with cross-cutting feature labels. Tags allow filtering independent of protocol bundle or RFC suite.

Common tags (planned):

- `discovery` — service discovery and bootstrapping (RFC 6764)
- `sync` — collection synchronization (RFC 6578)
- `conditional` — conditional requests using `If`, `If-Match`, `If-None-Match`
- `locking` — WebDAV locking (RFC 4918 §6–7); excluded from protocol bundles by default
- `acl` — access control (RFC 3744); excluded from protocol bundles by default
- `quota` — quota and size limits (RFC 4331); excluded from protocol bundles by default
- `vcard` — vCard format validation (RFC 2426, RFC 6350)

`--tag` is additive (include only tests with this tag). `--exclude-tag` is reductive (remove tests with this tag from the active set). Both override bundle defaults:

```
davlint run --protocol carddav --tag locking       # adds locking tests back in
davlint run --protocol carddav --exclude-tag sync  # removes sync tests
davlint run --tag sync --tag conditional           # run only these tags, no bundle
```

## Discovery Mode

`--discover` queries the server's `OPTIONS` response, reads the `DAV:` header, and selects tests automatically based on what the server advertises support for.

| DAV token | Tests activated |
|-----------|----------------|
| `1` | RFC 4918 core |
| `2` | RFC 4918 locking |
| `access-control` | RFC 3744 |
| `addressbook` | RFC 6352, RFC 2426 |
| `calendar-access` | RFC 4791 *(future)* |
| `sync-collection` | RFC 6578 |

This mode is most useful for "I just built something, find everything wrong with it." It holds the server accountable only for what it claims to support.

## Test Struct

Current:

```go
type Test struct {
    ID          string
    Suite       string
    Description string
    Severity    Severity   // must | should | may
    Fn          func(ctx context.Context, sess *Session) error
}
```

Planned additions:

```go
type Test struct {
    ID          string
    Suite       string
    Description string
    Severity    Severity     // must | should | may
    Protocols   []string     // e.g. ["carddav", "caldav"]
    Tags        []string     // e.g. ["sync", "conditional"]
    Mode        string       // "lint" (default) or "conformance"
    References  []RFCRef     // one or more RFC section citations
    Fn          func(ctx context.Context, sess *Session) error
}

type RFCRef struct {
    RFC     string // e.g. "RFC 6578"
    Section string // e.g. "§5"
    URL     string // e.g. "https://www.rfc-editor.org/rfc/rfc6578#section-5"
}
```

`Mode: "conformance"` tests are skipped in lint mode. All lint-mode tests also run in conformance mode.

A single requirement may cite multiple RFCs — for example, `If`-header token handling cites both RFC 4918 §10.4 (conditional requests) and RFC 6578 §5 (sync-token as state token).

## Coverage Taxonomy

Per-RFC coverage docs (in `docs/coverage/`) use four statuses:

| Status | Meaning |
|--------|---------|
| `lint ✓` | Representative test exists; runs in lint mode |
| `conformance ✓` | All variations covered; runs in both modes |
| `lint only` | Lint test exists; conformance variants are missing |
| `not covered` | No test exists |
| `deferred` | Intentionally out of scope — reason documented |

## Future Protocols

CalDAV (RFC 4791) is the primary planned addition. The architecture is protocol-agnostic — adding CalDAV means registering new test suites and adding `"caldav"` to the relevant `Protocols` fields.

## Open Questions

### Default behavior when no `--protocol` is specified

Three options under consideration:

1. **Run everything** — all registered tests across all suites. Simple, but potentially overwhelming and misleading (a CardDAV-only server would get CalDAV failures).
2. **Require `--protocol`** — fail with a helpful error. Clean but adds friction.
3. **Auto-discover (preferred candidate)** — if no `--protocol` is given, run `--discover` automatically and let the server's `OPTIONS`/DAV header determine what to test. Zero-configuration path: `davlint run` just works.

Decision pending. Leaning toward option 3 but needs validation against real-world usage.

## Future Work

The following areas need design decisions and documentation before implementation, but are not blocking current work:

- **Contributing / test writing guide** — conventions for adding new tests: lint vs conformance, tag assignment, RFC citation format, error message style, cleanup requirements
- **Stability guarantees** — define what is considered stable API surface (test IDs, JSON output schema, exit codes) and what is subject to change
- **Skip category differentiation** — terminal and JSON output should distinguish between three skip reasons: missing principals (actionable), `skip:` config (intentional), `--exclude-tag` (feature opt-out)
- **Test isolation conventions** — document expectations: every test is independent, creates its own resources, cleans up regardless of outcome, no cross-test dependencies
- **Concurrency** — decide whether tests should ever run in parallel; document constraints to prevent contributors from accidentally introducing cross-test dependencies
- **CalDAV roadmap** — which RFCs make up the CalDAV bundle (RFC 4791, RFC 4790, RFC 6638, etc.) and what the suite structure would look like
