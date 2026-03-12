# RFC Requirements Extraction

Extract all testable requirements from an RFC and produce a coverage doc for the davlint project.

## Usage

```
/rfc-extract <RFC number>
```

Example: `/rfc-extract 4791`

## What this does

1. Fetches the RFC from `https://www.rfc-editor.org/rfc/rfc<number>`
2. Extracts every MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY requirement
3. Maps each requirement against existing tests in `internal/suites/rfc<number>/`
4. Writes a coverage doc to `docs/coverage/rfc<number>.md`

## Instructions

When invoked with an RFC number $ARGUMENTS:

**Step 1 — Fetch and extract**

Fetch `https://www.rfc-editor.org/rfc/rfc$ARGUMENTS` and extract every normative requirement. For each requirement record:
- Section number
- Requirement level (MUST / MUST NOT / SHOULD / SHOULD NOT / MAY)
- The feature or mechanism it applies to
- A concise summary of the requirement
- Whether it is testable from a black-box HTTP client perspective, or untestable (client-side rule, DNS-level, implementation-internal, TLS-level)
- If untestable, the reason

Focus on sections that describe server behavior observable via HTTP requests and responses. Skip purely informational sections, examples, IANA considerations, and acknowledgements.

**Step 2 — Read existing tests**

Read `internal/suites/rfc$ARGUMENTS/rfc$ARGUMENTS.go` if it exists. Note every registered test: its ID, description, and what requirement(s) it exercises.

**Step 3 — Map coverage**

For each extracted requirement, determine coverage status using this taxonomy:

| Status | Meaning |
|--------|---------|
| `conformance ✓` | All meaningful variations tested (methods, resource types, depth values, etc.) |
| `lint only` | Representative test exists but conformance variants are missing |
| `not covered` | No test exists |
| `deferred` | Intentionally out of scope — reason must be documented |

A test is `lint only` if it covers one representative case (e.g. PROPFIND only) when the requirement applies to multiple methods or contexts. A test is `conformance ✓` only if all meaningful variations are covered.

**Step 4 — Identify gaps**

For every `lint only` requirement, list the specific missing conformance test variants with proposed test IDs.

For every `not covered` requirement, list it as a missing test with a proposed test ID and brief description.

**Step 5 — Write the coverage doc**

Write the result to `docs/coverage/rfc$ARGUMENTS.md` using this structure:

```markdown
# RFC <number> — <title>

**Test file:** `internal/suites/rfc<number>/rfc<number>.go`
**Tests registered:** <count>
**Requirements extracted:** ~<count> (~<count> directly HTTP-testable)

Coverage statuses:
- `conformance ✓` — all meaningful variations tested
- `lint only` — representative test exists; conformance variants missing
- `not covered` — no test exists
- `deferred` — intentionally out of scope with reason

---

## §<N> — <Section Title>

| Req | Requirement | Current Test | Status |
|-----|-------------|--------------|--------|
...

**Missing tests:**
- `rfc<number>.<id>` — description

---

## Deferred

| Req | Requirement | Reason |
...

---

## Test Rename Candidates

| Current ID | Proposed ID | Reason |
...

---

## Coverage Summary

| Status | Count |
...
```

**Important considerations:**

- Tests are `lint only` not just when one method is tested — also when one resource type, one depth value, or one error condition is tested out of several that the RFC requires
- A requirement that applies to COPY and MOVE as well as PUT needs all three covered for `conformance ✓`
- Locking requirements should be noted as `deferred` with reason "tagged `locking` — excluded from protocol bundle runs by default; runs when `--tag locking` is specified or discovery sees `2` in DAV header"
- ACL requirements: `deferred` with reason "tagged `acl` — excluded from protocol bundle runs by default"
- Client-side rules are always `deferred` with reason "client-side rule; not a server conformance test"
- DNS-level requirements are always `deferred` with reason "DNS-level; not testable via HTTP"
- TLS requirements are always `deferred` with reason "TLS-level; requires certificate inspection outside HTTP black-box testing"
- If no test file exists yet, all requirements are `not covered` and the doc serves as the implementation roadmap
