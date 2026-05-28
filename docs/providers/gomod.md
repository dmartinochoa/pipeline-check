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

10 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GOMOD-001](#gomod-001) | go.mod present without sibling go.sum integrity manifest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-002](#gomod-002) | go.mod replace directive points to a local filesystem path | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-003](#gomod-003) | go.mod replace directive substitutes a different module | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-004](#gomod-004) | Direct require pinned to a +incompatible version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GOMOD-005](#gomod-005) | go.mod does not declare a minimum Go toolchain version | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GOMOD-006](#gomod-006) | go.mod requires a known-compromised module version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-007](#gomod-007) | vendor/modules.txt missing or stale relative to go.mod | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GOMOD-008](#gomod-008) | go.mod replace directive points to a module without a version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GOMOD-009](#gomod-009) | Direct require uses a pre-release version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GOMOD-010](#gomod-010) | go.mod exclude directive masks an upstream version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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

<div class="pg-rule pg-rule--high" markdown>

## GOMOD-007: vendor/modules.txt missing or stale relative to go.mod { #gomod-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when the ``go.mod`` file's directory has a ``vendor/`` sibling without a ``vendor/modules.txt`` file, OR when ``vendor/modules.txt`` declares fewer direct requires than ``go.mod`` does (best-effort staleness detection — a full diff against every require would require parsing modules.txt's nested format).

Projects that don't ship a ``vendor/`` directory pass the rule silently. ``go.mod`` projects use vendor mode selectively, the rule's value is catching the case where vendor mode is in use but its manifest has drifted.

**Known false-positive modes**

- Pre-Go-1.14 projects that vendored without a ``vendor/modules.txt`` (the file became required at Go 1.14) trip this rule. The right fix is to run ``go mod vendor`` once under a modern toolchain to regenerate the manifest; suppress per file if the legacy vendor layout is intentional.

**Seen in the wild**

- Pattern in long-lived Go monorepos where a vendor/ directory carries pre-modules-era dependencies but the modules.txt manifest was never generated. Builds succeed under both ``-mod=mod`` (fetches fresh, ignores vendor) and ``-mod=vendor`` (uses vendor, ignores go.mod), but the resulting binaries can diverge.

<div class="pg-rule__rec" markdown>

**Recommended action**

Run ``go mod vendor`` to regenerate ``vendor/modules.txt`` and ``vendor/`` from the current ``go.mod`` / ``go.sum``. Commit the result. The file is the manifest the Go toolchain consults when ``-mod=vendor`` is set: it pins every direct + indirect dep to the version checked into ``vendor/``. A stale ``vendor/modules.txt`` (older require set than ``go.mod`` declares, or absent entirely while ``vendor/`` is populated) means the build uses different versions depending on whether ``GOFLAGS=-mod=vendor`` is set in the build environment, and a contributor who edits ``go.mod`` without re-running ``go mod vendor`` ships an unreviewed mismatch between the manifest and the vendored content.

Add ``go mod verify`` to CI to catch drift at build time; the verification fails when the vendored content doesn't match the checksums in ``go.sum``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GOMOD-008: go.mod replace directive points to a module without a version pin { #gomod-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on ``replace`` directives where the right side names a module path (``github.com/...``) but omits the version. Local-path replacements (``=> ../local``) are GOMOD-002's surface and are skipped here; module-to-module replacements with a version pin (``=> foo v1.2.3``) pass this rule.

The check exists because Go's module resolution treats a versionless replace as ``go get`` does — it fetches the default branch's tip. Force-pushes to that branch redirect every consumer's build, mirroring the tag-following pattern CARGO-002 catches for cargo dependencies.

**Known false-positive modes**

- Some vendoring tools (older versions of ``dep`` migrating to modules) emit versionless replaces during a conversion pass. The fix is to run ``go mod tidy`` against a modern toolchain, which resolves the replacement to a concrete version. Suppress per directive while the migration is in flight.

**Seen in the wild**

- Pattern of versionless replaces shipping in commits from contributors using older Go toolchains; ``go mod tidy`` rewrites them once the project upgrades to 1.21+, but the unmigrated form lives in repo history until then.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an explicit version on the right side of every ``replace`` directive that targets a module path. The fully-qualified form is ``replace <orig> => <new> <version>``. Without the trailing version, ``go mod tidy`` resolves the replacement to whatever the default branch of the replacement module currently points at, which mirrors the mutable-ref class of risk GOMOD-002 catches for local-path replacements but at the module-coordinate layer.

Example:

    # Vulnerable
    replace github.com/foo/bar => github.com/myorg/bar
    # Safe
    replace github.com/foo/bar => github.com/myorg/bar v1.2.3

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GOMOD-009: Direct require uses a pre-release version { #gomod-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Matches the standard semver pre-release suffix shape on direct requires: ``-rc``, ``-alpha``, ``-beta``, ``-pre``, ``-dev`` (case-insensitive) anywhere after the ``vX.Y.Z`` head. Pseudo-versions (``v0.0.0-YYYYMMDDHHMMSS-commitsha``) are excluded — they're Go's canonical mechanism for pinning to a commit when the upstream has no tagged release yet, and the rule would FP on the most common form of intentional pre-release usage.

Indirect requires (``// indirect``) are exempt; the consumer doesn't directly control the version and auditing them dilutes the rule's signal.

**Known false-positive modes**

- Libraries that exclusively ship pre-release tags (some experimental projects use ``v0.x``-style major zero versioning forever) trip this rule by design. Suppress per dependency with a one-line rationale naming the upstream's stabilization policy.

**Seen in the wild**

- Pattern in early-stage Go projects where a contributor pulls in an upstream's release-candidate during development, the project ships, and the dependency stays at ``-rc`` for years past the upstream's GA release. Security advisories typically don't cover pre-release tags, so the consumer remains exposed to fixed-in-stable vulnerabilities indefinitely.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every production direct dependency to a stable release. Pre-release versions (``v1.0.0-rc.1``, ``v2.0.0-alpha.3``, ``v0.9.0-beta``) signal that the upstream maintainer hasn't committed to API or behavioral stability for the tag — a patch may revert or rewrite the suffix, and security advisories specifically scope to released versions, so a stuck pre-release ships with no patched-version migration path.

If the project legitimately needs the pre-release (awaiting an upstream stable that ships a critical fix), document the dependency with a follow-up TODO pointing at the upstream's stabilization issue and revisit on every scan.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GOMOD-010: go.mod exclude directive masks an upstream version { #gomod-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any ``exclude`` directive in go.mod. The rule is informational-leaning MEDIUM: excludes are not themselves a vulnerability, they're a posture / hygiene signal. Long-lived excludes without comments often outlive the upstream issue that prompted them, and their continued presence in the manifest creates audit-trail noise around the dependency graph.

Distinct from GOMOD-006 (known-compromised version) and GOMOD-004 (+incompatible version): those rules audit *what's used*, this one audits *what's deliberately blocked* and surfaces the staleness class.

**Known false-positive modes**

- Excludes pinned to a specific known-broken upstream release that's still in the module graph's transitive set are legitimate and load-bearing. The rule fires anyway because the cleanup decision requires context the manifest doesn't carry. Suppress per directive with a one-line rationale naming the upstream issue.

**Seen in the wild**

- Pattern in long-lived Go monorepos: an exclude from 2019 blocks a then-broken patch release; the upstream has since rolled forward and the block is irrelevant, but no audit cycle has touched the directive. Cleanup of stale excludes during dep-update sprints is a common posture-hygiene exercise.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit every ``exclude`` directive and remove the ones that aren't load-bearing. ``exclude <path> <version>`` tells Go's module graph resolver to skip the named version — useful for blocking a known-broken release from a transitive resolution, but often left over from a long-ago dependency conflict that's since been patched upstream.

The two failure modes:

1. The excluded version is no longer relevant (upstream fixed the issue in a later release). Remove the exclude.
2. The excluded version carries a security advisory (``exclude`` hides it from the resolver, but a deliberate ``require`` at the same version still pulls it). Replace the exclude with an explicit patched-version require so future audits see the intent.

Pair every kept exclude with a comment naming the incident or upstream issue that justified it. Excludes without rationale are a code-rot signal.

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
