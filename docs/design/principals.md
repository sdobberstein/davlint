# Principals

## Overview

Some tests require multiple authenticated user accounts to exercise multi-user behavior — locking conflicts, ACL enforcement, sync visibility, CalDAV scheduling, etc. davlint supports configuring multiple principals as an ordered list.

## Configuration

Principals are configured as an ordered list. Order matters and should not be changed once configured. The first principal is the main actor in all tests.

```yaml
principals:
  - username: alice
    password: secret
  - username: bob
    password: secret
  - username: charlie
    password: secret
```

No roles or names are assigned — position is the convention.

## Session Accessors

```go
sess.Primary()     // Clients[0] — main actor, always present
sess.Secondary()   // Clients[1] — second authenticated user, optional
sess.Clients[2]    // third authenticated user, used for ACL outsider tests
sess.Unauthenticated() // no credentials — built-in, never needs configuration
```

`Primary()` and `Secondary()` are named accessors for the two most common cases. For the rare third-principal case (ACL tests requiring an authenticated but unauthorized user), `Clients[2]` is used directly.

## Minimum Principals

Tests declare the minimum number of principals they require:

```go
suite.Test{
    ID:            "rfc4918.lock-conflict",
    MinPrincipals: 2,
    ...
}
```

If fewer principals are configured than a test requires, the test is **skipped** — not failed. A misconfigured account count is not a server conformance issue.

## Skip Behavior and Output

Skipped-due-to-principals tests are surfaced distinctly from intentionally skipped tests.

**Terminal output:**

```
SKIP rfc4918.lock-conflict        requires 2 principals, 1 configured
SKIP rfc3744.acl-read-denied      requires 3 principals, 1 configured
```

**End-of-run summary:**

```
23 passed  1 failed  4 skipped (2 missing principals, 2 excluded)  1.4s
```

The distinction matters: "missing principals" skips are actionable — the user should add accounts to their config to get full coverage. They should feel like a nudge, not noise.

**`davlint list` output** includes a `principals` column so users can see requirements before running:

```
rfc4918.lock-conflict    must    2    locking    RFC 4918 §6    ...
```

## Multi-User Test Patterns

### Locking (RFC 4918)
- `Primary` acquires a lock
- `Secondary` attempts to write to the locked resource → expects 423

### Sync visibility (RFC 6578)
- `Primary` creates/modifies resources
- `Secondary` observes changes via sync-collection REPORT

### ACL (RFC 3744)
- `Primary` creates a resource and controls permissions
- `Secondary` is granted access by primary
- `Clients[2]` is a valid authenticated user that primary has not granted access to

### CalDAV scheduling (future)
- `Primary` is the organizer
- `Secondary` is the attendee

## Unauthenticated Access

`sess.Unauthenticated()` returns a client with no credentials, derived from the configured server URL. It is always available regardless of how many principals are configured and does not count toward `MinPrincipals`. Tests that only need unauthenticated access (e.g. `rfc6352.unauthenticated-access-denied`) require only 1 principal.
