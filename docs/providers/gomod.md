# Go modules provider

Parses `go.mod` (Go's module manifest) and probes for the sibling
`go.sum` (integrity manifest) on disk. Text-only static analysis,
no `go mod tidy`, no module-proxy access, no toolchain required.
Mirrors the npm / PyPI / Maven / NuGet pack shape.

## Producer workflow

```bash
# --gomod-path auto-detects ./go.mod when present.
pipeline_check --pipeline gomod
pipeline_check --pipeline gomod --gomod-path ./go.mod
pipeline_check --pipeline gomod --gomod-path ./services/api/
```

## Supported file formats

| File | Parse shape |
|------|-------------|
| `go.mod` | `module` / `go` / `toolchain` / `require` / `replace` / `exclude` directives |
| `go.sum` | Presence probe only (the load-bearing signal for `GOMOD-001`) |

`vendor/` and `.git/` directories are skipped.

## What it covers

6 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GOMOD-001](#gomod-001) | go.mod present without sibling go.sum integrity manifest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-002](#gomod-002) | go.mod replace directive points to a local filesystem path | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-003](#gomod-003) | go.mod replace directive substitutes a different module | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-004](#gomod-004) | Direct require pinned to a +incompatible version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GOMOD-005](#gomod-005) | go.mod does not declare a minimum Go toolchain version | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GOMOD-006](#gomod-006) | go.mod requires a known-compromised module version | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GOMOD-001: go.mod present without sibling go.sum integrity manifest { #gomod-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when the ``go.mod`` file's directory has no ``go.sum`` sibling at scan time. The check is a presence probe only, the hash payloads themselves are not audited (``go mod verify`` is the canonical verifier and runs against a live module cache). Catches the common misconfiguration where ``go.sum`` is added to ``.gitignore`` (a stale dev habit imported from the pre-modules ``dep`` / ``glide`` era when vendoring made lockfiles redundant).

Skipped when the module's ``require`` block is empty (an experimental / placeholder module with no third-party deps); the absent sum file is a no-op there since there's nothing to verify.

**Known false-positive modes**

- A first-commit go.mod with no requires legitimately ships without a go.sum, the rule already exempts that case. Some monorepo migration scripts also temporarily strip go.sum during a rebase; suppress per-file with a one-line rationale if your migration tooling requires it.

**Seen in the wild**

- Long-running pattern of go.sum exclusions in dev / staging Go projects that hit production CI before a contributor regenerates it. The Go toolchain's checksum-database fallback masks the missing file under normal network conditions; offline builds, airgapped CI runners, and GOSUMDB=off configurations land directly on the unprotected path.

<div class="pg-rule__rec" markdown>

**Recommended action**

Commit the generated ``go.sum`` alongside ``go.mod``. The sum file records ``h1:<base64-sha256>`` hashes for every module zip and ``go.mod`` referenced by the build; without it the Go toolchain falls back to consulting the public checksum database (``sum.golang.org``) at build time, which is fine in normal operation but doesn't survive an offline / hermetic build, and is silently bypassed when ``GOFLAGS=-insecure``, ``GONOSUMCHECK=1``, or ``GOSUMDB=off`` is set in the build environment. Generate the file once with ``go mod tidy`` and check it in; from that point ``go build`` will refuse to proceed if any module zip's hash drifts from the recorded value.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GOMOD-002: go.mod replace directive points to a local filesystem path { #gomod-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any ``replace`` directive whose right-hand side resolves to a filesystem path: starts with ``./``, ``../``, ``/``, or a Windows drive letter (``C:\``). Module-to-module replacements (``replace foo => bar v1.2.3``) are a separate concern handled by GOMOD-003. Local-path replacements in a committed go.mod are a common artifact of a contributor's dev loop that was never reverted before merging.

A local-path replacement breaks reproducibility (every runner needs the path to exist), bypasses the module proxy (the replacement isn't fetched through GOPROXY), and bypasses the checksum database (``go mod verify`` skips local-path replacements). All three failure modes stack so a local-path replace is effectively an unauditable supply-chain blank check.

**Known false-positive modes**

- Vendored monorepo subprojects sometimes legitimately use ``replace ./vendored/<pkg>`` to pin a fork inside the repo. The modern equivalent is a ``go.work`` file or a module-to-module replace at a tagged fork; suppress per directive if the vendored layout predates go.work (introduced in Go 1.18).

**Seen in the wild**

- Common contributor-laptop leakage: ``replace github.com/myorg/mylib => ../mylib-fork`` lands in a PR because the local dev loop pointed at a sibling clone, the test suite passed on the contributor's machine, and CI's lenient module resolution swallowed the missing path. Production builds end up running the prior version of mylib (the one cached in the module proxy) while the contributor believed they were testing against their fork.

<div class="pg-rule__rec" markdown>

**Recommended action**

Local-path replacements (``replace foo/bar => ../local/copy``) are a dev-loop convenience: they bypass the module proxy + checksum database and pull the dependency from the working tree instead. Shipping one into a committed ``go.mod`` means CI builds either fail (the path doesn't exist on the runner) or — worse — silently use whatever directory tree happens to live at that path inside the runner image. Either remove the directive entirely (the normal go-proxy fetch will reach the real upstream), or split the local path into a separate ``go.work`` file (the Go workspace mechanism designed for multi-module dev checkouts) that you do NOT commit. ``go.work`` overrides ``go.mod`` replaces locally without leaking into the committed manifest.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GOMOD-003: go.mod replace directive substitutes a different module { #gomod-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``replace orig => new ver`` directives whose ``orig`` and ``new`` module paths differ. Same-module version-pin replaces (``replace foo => foo v1.2.4``) pass since they're an auditable version override, not a supply-chain swap. Local-path replacements are GOMOD-002's surface (different failure mode, different fix); this rule only fires on module-to-module substitutions.

The check operates on the static go.mod text, not on whether the replacement upstream is actually compromised (that would require a live registry lookup). The premise: any cross-module substitution warrants explicit operator review at audit time.

**Known false-positive modes**

- Forked / patched dependencies maintained at a different module path (``replace upstream/lib => myorg/lib-patched v1.2.3``) trip this rule deliberately. The right operator response is to either fold the patch upstream or suppress per directive with a one-line rationale naming the fork's maintainer and rotation policy.

**Seen in the wild**

- Long-running pattern in Go monorepos where a one-line replace directive added during an emergency hotfix is never reverted; downstream consumers continue building against the temporary fork for years. The rule surfaces the deviation at every scan so the operator can decide whether the fork is still load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Module-to-module replacements (``replace foo/bar => baz/quux v1.2.3``) substitute a completely different upstream for the requested one. The substitution is transparent to downstream code (imports of ``foo/bar`` succeed and link against ``baz/quux``'s implementation), which is exactly the affordance an attacker who lands one well-placed replace exploits: ship a malicious fork at ``attacker/fork``, replace a widely-imported upstream with it, and every consumer's build inherits the swap without an import-site code change.

If the goal is to pin a security patch from a friendly fork, prefer the same-module replace form (``replace foo/bar => foo/bar v1.2.3-mybranch.0``) so the rule doesn't fire and the substitution is auditable as a version-pin override rather than an upstream swap. If a true upstream change is intentional (e.g. forked + maintained internally), suppress per directive with a rationale naming both the original and replacement modules.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GOMOD-004: Direct require pinned to a +incompatible version { #gomod-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Fires on any direct require whose version ends in ``+incompatible``. Indirect requires are exempt; they rolled up from a transitive dep's tagging policy and the consumer can't directly fix them without changing the transitive dep itself. The rule is informational-leaning MEDIUM rather than HIGH: ``+incompatible`` is a posture / maintenance signal, not a direct exploit primitive, but modules that have shipped ``v2.0.0`` without a module-path bump are statistically over-represented among unmaintained or single-maintainer projects, which is its own supply-chain exposure.

**Known false-positive modes**

- A small set of canonical infra modules (``github.com/Sirupsen/logrus`` historically, before it moved to ``github.com/sirupsen/logrus``; some etcd client lineages) shipped at ``+incompatible`` versions on purpose because the maintainer chose not to bump the module path. Suppress per directive when the upstream policy is known and stable.

**Seen in the wild**

- Pattern of long-stuck +incompatible deps in Go monorepos where the upstream maintainer abandoned the project at the v2.0.0+ tag. Consumers stay on the +incompatible version indefinitely; no patches roll out because the module is effectively read-only. The rule surfaces the drift class so an audit cycle can plan migration off the unmaintained dependency.

<div class="pg-rule__rec" markdown>

**Recommended action**

The ``+incompatible`` suffix is a Go-module-system backward-compatibility band-aid: it lets a module tagged ``v2.0.0`` (or higher) be imported without the standard ``/v2`` module-path suffix that semantic import versioning requires. The module gets pulled, but several of the guarantees the module system normally enforces (major-version isolation, automatic-upgrade safety, the ability to depend on multiple major versions simultaneously) are turned off for it.

Migrate the consumer to a real ``/v2``-suffixed import path when the upstream maintainer ships one (most active Go projects have done this for years; a stuck ``+incompatible`` usually means the dep is unmaintained or the consumer hasn't been updated). Where the upstream genuinely refuses to add the suffix (some infrastructure-y projects deliberately stay on ``+incompatible``), accept the limitation explicitly via a suppression rationale that names the upstream policy.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GOMOD-005: go.mod does not declare a minimum Go toolchain version { #gomod-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Fires when the ``go`` directive is absent from the manifest. Single-rule LOW: a missing ``go`` line is a posture / maintenance issue, not an exploit primitive, but it removes the operator's ability to reason about which language semantics the build relies on. Often co-occurs with the no-CI / no-CODEOWNERS pattern in low-maintenance internal projects, so the rule doubles as a maintenance indicator.

**Known false-positive modes**

- Some module templates (cookiecutter / generator-go) deliberately omit the directive on the first commit to let the consumer pick a version. The rule still fires; suppress per-file with a one-line rationale referencing the template policy, or — better — bump the template to emit ``go 1.22`` by default.

**Seen in the wild**

- Posture-drift class commonly surfaced in internal-tool audits of long-lived Go projects: no ``go`` directive, CI runner pinned to Go 1.17, several CVEs in the stdlib net/http (e.g. CVE-2023-39325) silently in scope. Updating the directive to ``go 1.22`` forces the runner image bump or a hard build failure — the audit signal the rule is meant to surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``go <version>`` directive at the top of ``go.mod`` naming the minimum supported toolchain (e.g. ``go 1.22``). The directive tells the Go toolchain which language features are enabled, which standard-library API guarantees hold, and which security-relevant compiler defaults (memory model, race-detector behavior, panic handling) apply. Without the directive, the build succeeds under whatever toolchain happens to be installed, which on a long-lived CI runner often means an older release that lacks recent security fixes. Pair with a ``toolchain go<X.Y.Z>`` directive to pin an exact compiler version when reproducibility is a concern.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GOMOD-006: go.mod requires a known-compromised module version { #gomod-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the curated registry under ``pipeline_check.core.checks.gomod._compromised_modules`` (table of ``(module_path, malicious_versions, advisory)`` entries) and fires when any require — direct or indirect — matches an entry. The registry is hand-curated and append-only; adding a new entry is a one-line table edit plus the citing advisory in the commit message.

Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005: the rule fires on exact version equality (with optional regex-fallback patterns shared via ``_primitives/compromised.py``). Coverage is necessarily incomplete; the value is the audit-trail-locked post-incident detection of a published advisory, complementing the live OSV-advisory rule that would land alongside any future ``--resolve-remote`` extension.

**Known false-positive modes**

- Patched fork-and-pin remediation paths sometimes legitimately leave the original module name pinned at an affected version (with a same-module replace pointing at the fork). The rule still fires on the require line; suppress per directive with a one-line rationale naming the replace fork and the advisory the patch covers.

**Seen in the wild**

- CVE-2025-22869 (GHSA-v778-237x-gjrc): golang.org/x/crypto ScalarMult vulnerability in pre-0.32.0 patch versions. Future entries follow the same shape: append the (module_path, version, advisory) row to _compromised_modules.py and cite the GHSA in the commit message.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the offending require to a patched version (named in the cited advisory) and run ``go mod tidy`` to refresh the integrity manifest. If the advisory has no patched release, pin to the last known-good version and add a follow-up TODO so the dependency is replaced or removed the next maintenance cycle. After the bump, re-run the scan, GOMOD-006 should clear; if the rule still fires, an indirect require somewhere is pulling the bad version back in. Use ``go mod why -m <module>@<version>`` to find the path.

</div>

</div>

---

## Adding a new Go modules check

1. Create a new module at
   `pipeline_check/core/checks/gomod/rules/gomodNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pom: GoModFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``GoModFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/gomod/GOMOD-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py gomod
   ```
