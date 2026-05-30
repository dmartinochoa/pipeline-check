# Cargo (Rust) provider

Parses `Cargo.toml` (Cargo manifest) and probes for the sibling
`Cargo.lock` on disk. Text-only static analysis via the TOML
stdlib parser, no `cargo update`, no registry access, no
toolchain required. Mirrors the npm / PyPI / Maven / NuGet / Go
modules pack shape.

## Producer workflow

```bash
# --cargo-path auto-detects ./Cargo.toml when present.
pipeline_check --pipeline cargo
pipeline_check --pipeline cargo --cargo-path ./Cargo.toml
pipeline_check --pipeline cargo --cargo-path ./crates/my-crate/
```

## Dependency tables audited

| Section | Notes |
|---------|-------|
| `[dependencies]` | Runtime dependencies |
| `[dev-dependencies]` | Test / bench dependencies |
| `[build-dependencies]` | Build-script dependencies |
| `[target.<target>.dependencies]` | Target-specific entries |
| `[workspace.dependencies]` | Workspace-root inheritance |

`target/` and `.git/` directories are skipped.

## What it covers

14 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CARGO-001](#cargo-001) | Cargo.toml dependency uses a floating version spec | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-002](#cargo-002) | Cargo.toml git dependency uses a mutable ref (no rev) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-003](#cargo-003) | Cargo.toml present without a sibling Cargo.lock | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-004](#cargo-004) | Cargo.toml dependency is a local-path entry | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-005](#cargo-005) | Cargo.toml dependency sourced from an alternate registry | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-006](#cargo-006) | Cargo.toml requires a known-compromised crate version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-007](#cargo-007) | [build-dependencies] entry uses a floating version spec | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-008](#cargo-008) | Cargo.toml [patch.crates-io] substitutes a different crate | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-009](#cargo-009) | [workspace.dependencies] entry uses a floating version spec | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-010](#cargo-010) | Cargo.toml lacks an explicit rust-version field | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CARGO-011](#cargo-011) | build.rs runs network or process calls at compile time | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-012](#cargo-012) | .cargo/config.toml overrides the registry source or injects build flags | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-013](#cargo-013) | Cargo.lock package sourced off crates.io | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-014](#cargo-014) | No supply-chain audit-gate config (cargo-deny / cargo-vet / cargo-audit) | <span class="pg-sev pg-sev--low">LOW</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## CARGO-001: Cargo.toml dependency uses a floating version spec { #cargo-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any ``[dependencies]`` / ``[dev-dependencies]`` / ``[build-dependencies]`` / ``[target.<...>.dependencies]`` entry whose version specifier evaluates as floating per Cargo's semver grammar (any leading ``^`` / ``~`` / ``>=`` / ``<`` / ``*``, or bare versions which Cargo interprets as caret-equivalent). Exact pins (``=N.M.P``) pass. Entries without a version (``git`` / ``path``) are handled by CARGO-002 / CARGO-004 respectively, not here.

**Known false-positive modes**

- Library crates published to crates.io legitimately use loose specifiers so downstream consumers can deduplicate transitive deps; the pin-the-manifest guidance applies primarily to *binary* / *application* crates. Suppress per crate when the crate is itself a published library.

**Seen in the wild**

- Long-running pattern in Rust application crates that publish a wildcard caret spec for an HTTP client. A patch-version compromise upstream is picked up at the next build; the ``Cargo.toml`` doesn't change, so a diff-based review misses it. The committed lockfile is the load-bearing control, but the manifest pin makes the intent legible at audit time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace floating version specifiers (caret-equivalent ``"1.2"``, explicit caret ``"^1.2"``, tilde ``"~1.2"``, wildcard ``"1.*"``, comparison ``">=1.2, <2"``) with an exact pin ``"=1.2.3"``. Cargo's default specifier is caret-equivalent: a bare ``"1.2.3"`` matches any version >= 1.2.3 and < 2.0.0. A compromised patch release upstream is silently picked up on the next ``cargo build`` unless a committed ``Cargo.lock`` (CARGO-003) holds the line.

Pin the manifest *and* commit the lockfile, both belt and suspenders. The lockfile alone leaves a window between ``cargo update`` runs; the manifest alone leaves a window before the first build refreshes the lockfile.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-002: Cargo.toml git dependency uses a mutable ref (no rev) { #cargo-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any dependency entry that sets ``git = "..."`` without a ``rev`` key, regardless of whether ``branch`` / ``tag`` is set. Cargo treats ``tag``-pinned entries as mutable because git tags can be reassigned without rewriting history (Cargo notes the tag's resolved commit in the lockfile, but the manifest still doesn't bind to it). ``rev`` is the only specifier that pins to immutable content.

**Known false-positive modes**

- Some workspaces use git ``tag`` with a strict release-tag-immutability policy (signed tags, no force-move). The rule still fires because the manifest can't express that policy. Suppress per dep with a one-line rationale naming the upstream's tag-immutability guarantee.

**Seen in the wild**

- Tag-following pattern in Rust application crates: a popular utility crate's maintainer account is compromised, force-moves the ``v1.2.3`` tag to a malicious commit. Every downstream consumer's next ``cargo build`` with the tag-pinned entry pulls the rewritten commit; rev-pinned consumers are unaffected because their lockfile and manifest both reference the original commit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every git dependency to an exact commit SHA via ``rev = "<40-char-sha>"``. Cargo's other git-source selectors all carry mutable semantics: ``branch = "main"`` resolves the branch head on every fetch, ``tag = "v1"`` follows the tag if it's force-moved, and an unspecified selector means ``branch = "HEAD"``. None of those survive a force-push or maintainer-account compromise.

Example safe form:

    foo = { git = "https://github.com/example/foo", rev = "a1b2c3d4e5f6..." }

If the upstream genuinely needs to track a moving target (an internal fork still on its own branch), vendor the code into the repo or run a private crate registry where you control the publish event.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-003: Cargo.toml present without a sibling Cargo.lock { #cargo-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires when the manifest's directory has no ``Cargo.lock`` sibling and the workspace root one directory up has no ``Cargo.lock`` either. Workspace-root manifests (``[workspace]``-only, no ``[package]``) are skipped — the lockfile lives at the workspace root for the whole workspace, so each per-crate sub-manifest legitimately lacks one. Crates that legitimately publish without a lockfile (library crates) need a per-file suppression with a one-line rationale.

**Known false-positive modes**

- Library crates published to crates.io intentionally omit Cargo.lock from version control so downstream applications can deduplicate transitive deps; this rule fires on those, suppress per crate with a one-line rationale naming the crate-as-library posture. Workspace-root manifests are skipped automatically.

**Seen in the wild**

- Long-running pattern of internal Rust applications that ignore Cargo.lock in .gitignore (a habit imported from library development). CI builds use a fresh lockfile every run; a transient registry-side bad patch release lands on the build the moment it's published, then disappears on the next run, leaving no audit trail and no reproducer.

<div class="pg-rule__rec" markdown>

**Recommended action**

For binary / application crates, commit ``Cargo.lock`` to the repository. The lockfile records exact resolved versions for every transitive dependency in the graph, so every build (locally and in CI) installs the same crates. Without it, ``cargo build`` re-resolves the manifest each time and is free to pick the latest matching patch under any floating spec (CARGO-001). 

For library crates published to crates.io, Cargo's guidance is the opposite — leave Cargo.lock uncommitted so downstream consumers can deduplicate. This rule still fires on those manifests; suppress per crate when the crate is a published library. The default posture (Cargo.lock committed) is correct for applications, build tools, CLI utilities, and internal services.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CARGO-004: Cargo.toml dependency is a local-path entry { #cargo-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any dependency entry that sets ``path = "..."``. Workspace-root manifests aren't audited for path entries since the ``[workspace.dependencies]`` table is the normal place to centralize workspace-member references.

**Known false-positive modes**

- Multi-crate dev repos that pre-date Cargo workspaces (Rust 2018) sometimes still use per-dep ``path =`` instead of ``[workspace.members]``. The right fix is the workspace migration; suppress per dep if the migration is tracked as separate technical debt.

**Seen in the wild**

- Common contributor-laptop leakage in Rust monorepos: ``foo = { path = "../foo-fork" }`` lands in a PR because the local dev loop pointed at a sibling clone, tests passed on the contributor's machine, CI's lenient resolution swallowed the missing path. Production builds either fail or — worse — pick up whatever sibling directory happens to live next to the runner's working tree.

<div class="pg-rule__rec" markdown>

**Recommended action**

Local-path entries (``path = "../local"``) bypass the Cargo registry and the lockfile's content-hash gate. They exist for two legitimate use cases — workspace members (handled by Cargo's workspace mechanism, which uses ``[workspace]`` not per-dep paths) and active dev loops where a contributor is editing two crates side-by-side. Neither belongs in a committed manifest that runs on CI.

Three remediation patterns:

* If the dependency is a sibling workspace member, declare the workspace at the root (``[workspace.members = ...]``) and let Cargo resolve siblings automatically — no per-dep ``path =`` needed.
* If the dependency is a local fork being actively patched, publish the fork to a private crate registry and pin to it from the manifest.
* If the path entry is a dev-loop leftover that should never have been committed, remove it and add the upstream back to the regular ``[dependencies]`` table.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-005: Cargo.toml dependency sourced from an alternate registry { #cargo-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any dependency entry that sets ``registry = "..."``. The rule operates on the manifest text only — it doesn't fetch the configured ``[registries.<name>]`` URL from ``.cargo/config.toml`` to verify it's well-formed or HTTPS. Operators wanting URL-level checks should audit the config file separately; this rule's value is surfacing the fact that an alternate registry is in use, leaving the URL audit to the operator.

**Known false-positive modes**

- Internal-registry setups where every crate is intentionally sourced from a private feed trip this rule by design. The right operator response is a project-level suppression (``pipelinecheckignore``) for the specific registry name, with a one-line rationale naming the registry's owner.

**Seen in the wild**

- Crate-name-collision pattern: a private registry hosts a crate ``foo``, the public crates.io also has a ``foo``. A contributor edits ``.cargo/config.toml`` to remove the registry override (intentionally or via merge conflict), the next build pulls the public ``foo`` and links against it. This rule surfaces the alternate-registry dependency so the operator can decide whether the override is still load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Alternate-registry dependencies (``registry = "my-internal"``) bypass crates.io and resolve against whatever URL is configured under ``[registries.my-internal]`` in ``.cargo/config.toml``. The substitution is fine when the alternate is a well-known internal registry that the operator controls; it's a supply-chain risk when the registry name is ambiguous (collides with a public registry name) or when the configured URL is committed alongside the manifest without an explicit allowlist.

Audit each alternate-registry entry: confirm that the registry URL is well-known to the team, that it's served over HTTPS, and that pushes to the registry are gated by the same review process that gates the source repo. If the dependency is also available on crates.io at the same version, prefer the default registry — fewer moving parts, and the public crates.io trust signals (download counts, yanked-version tracking) are not available against private registries.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-006: Cargo.toml requires a known-compromised crate version { #cargo-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the curated registry under ``pipeline_check.core.checks.cargo._compromised_crates`` (table of ``(crate, malicious_versions, advisory)`` entries) and fires when any dependency — direct or workspace-inherited — matches an entry. The registry is hand-curated and append-only; adding a new entry is a one-line table edit plus the citing advisory in the commit message.

Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / GOMOD-006 and shares the version-matching primitive (``_primitives.compromised.match_version``). The version literal compared is whatever the manifest declares (``"1.2.3"``, ``"=1.2.3"``, ``"^1.2"``); operators wanting *resolved* version coverage should also commit Cargo.lock (CARGO-003), at which point the lockfile-side audit can lift the rule's matching from manifest to resolved-graph.

**Known false-positive modes**

- A manifest may legitimately pin a known-bad version because the consumer has applied a downstream patch or sandbox (``unsafe`` removal, panic-handler change). The rule still fires; suppress per dep with a one-line rationale naming the patch.

**Seen in the wild**

- RUSTSEC-2024-0388: rustls vulnerability surfaced via RUSTSEC-2024-0388. Future entries follow the same shape: append ``(crate, version, advisory)`` to _compromised_crates.py with the citing advisory in the commit message.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the offending dep to a patched version (named in the cited advisory) and refresh Cargo.lock with ``cargo update -p <crate>``. If the advisory has no patched release, pin to the last known-good version and add a follow-up TODO to replace or remove the dependency. After the bump, re-run the scan; if CARGO-006 still fires, an indirect dependency is pulling the bad version back in — use ``cargo tree -i <crate>@<version>`` to find the path.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-007: [build-dependencies] entry uses a floating version spec { #cargo-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks ``[build-dependencies]`` and ``[target.<target>.build-dependencies]`` entries on each ``Cargo.toml`` and fires when the version spec is floating per Cargo's semver model (bare numeric / caret / tilde / wildcard / range). Exact pins (``=X.Y.Z``) pass. Workspace-inherited entries (``workspace = true``) are skipped — the workspace root's audit is the right surface for those, and CARGO-009 covers that table specifically.

**Known false-positive modes**

- Library crates published to crates.io legitimately use loose build-dep specifiers so downstream consumers can deduplicate at integration time. The application/binary distinction applies the same way as for CARGO-001: app crates should pin, library crates may suppress with a published-library rationale.

**Seen in the wild**

- Build-time supply-chain pattern: a popular build-dep crate (a code-generator, a protobuf compiler wrapper, a static linker helper) ships a poisoned patch release with a malicious build.rs hook. Every downstream consumer with a floating build-dep spec picks up the bad version on the next ``cargo build``; the hook runs in the build environment and inherits CI runner privileges before any test sandbox executes.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``[build-dependencies]`` entry to an exact version (``=1.2.3``). Build-dependencies are crates used exclusively at compile time by ``build.rs`` (the Rust-side analog of npm install scripts or Python setup.py): they run arbitrary Rust code in the build environment before the consuming crate's own source ever compiles. A poisoned patch release of a build dependency executes in the build environment with the same privileges any other build code would have, and runs on every developer's machine and every CI runner.

Distinct from CARGO-001 (regular runtime ``[dependencies]``): runtime deps execute at *app* runtime, build deps execute at *build* time, before any test or runtime sandbox is in place. The xz-utils-style build-step backdoor is directly applicable to any build-dependency that ships a build.rs hook.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-008: Cargo.toml [patch.crates-io] substitutes a different crate { #cargo-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Re-parses ``Cargo.toml`` and walks ``[patch.crates-io]``. Fires for every entry — patches are silent substitutions and warrant explicit audit-trail review regardless of the source. Entries with ``path = "..."`` (local-fork patches) are particularly important to surface because the patch lives outside the registry's integrity chain.

Parallels GOMOD-003 (Go module replace directive) and PYPI-013 (pyproject dynamic dependencies): substitution primitives that operate below the import layer deserve dedicated audit surfaces.

**Known false-positive modes**

- Active upstream-fix patches with a documented stabilization timeline trip this rule by design. Suppress per entry with a one-line rationale naming the upstream issue and the expected stabilization release. Long-stuck patches without rationale are code-rot signals.

**Seen in the wild**

- Pattern in Rust monorepos that consume a vendored fork of a popular crate via ``[patch.crates-io]``: the patch entry lands during an emergency hotfix, is never reverted, and downstream consumers continue building against the temporary fork for years. The rule surfaces the deviation at every scan so the operator can decide whether the fork is still load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit every entry under ``[patch.crates-io]``. The section overrides crates.io's resolution for the named crate, replacing it with a different source (a git repo, a local path, or another registry). Any consumer of the patched crate — including transitive deps — silently links against the replacement, with no import-site code change to flag at review.

Three remediation patterns:

* If the patch is a security fix awaiting upstream, document it with a comment naming the upstream issue and revisit on every audit cycle.
* If the patch is a permanent fork, publish the fork to a private registry and depend on it directly under its own crate name (drop the [patch.crates-io] form).
* If the patch is a stale workaround from a long-ago compatibility issue, remove it and pull from crates.io directly.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CARGO-009: [workspace.dependencies] entry uses a floating version spec { #cargo-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Walks ``[workspace.dependencies]`` table entries on each ``Cargo.toml`` (workspace roots typically declare this) and fires on the same floating shapes CARGO-001 catches for per-crate dependencies. Git / path / workspace-inherited entries are skipped — they're handled by CARGO-002 / CARGO-004 / the workspace root audit itself.

Distinct from CARGO-001 because the scope is wider: a single floating workspace-deps entry cascades to every member crate that uses ``workspace = true``, which on a multi-member workspace amplifies the risk surface significantly compared to a per-crate floating spec.

**Known false-positive modes**

- Library-style workspaces published as a cohesive crate family may deliberately use loose specifiers at the workspace root so all members participate in version-resolution dedup. Application/binary workspaces should pin.

**Seen in the wild**

- Pattern in Rust workspace consumers: a single floating workspace-deps spec for a popular crate (``serde``, ``tokio``) cascades a poisoned patch to every member on the next build, multiplying the blast radius compared to a per-crate dep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every entry in ``[workspace.dependencies]`` to an exact version (``=1.2.3``). Workspace-level dependencies act as the single source of truth for every workspace-member crate that opts into them via ``workspace = true``; a floating spec at the workspace root cascades to every member, so a poisoned patch release upstream rolls across the entire workspace on the next ``cargo build``.

Pair the exact pin with a committed ``Cargo.lock`` at the workspace root (CARGO-003) so lockfile-based audits work across all members.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CARGO-010: Cargo.toml lacks an explicit rust-version field { #cargo-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Reads ``[package].rust-version`` and fires when the field is missing on a non-workspace-root manifest. Workspace roots are skipped — they declare ``[workspace.package].rust-version`` instead, and the member crates inherit it via ``rust-version.workspace = true``.

Single-rule LOW: a missing rust-version isn't a vulnerability, it's a posture / maintenance signal. Parallels GOMOD-005 (missing Go toolchain directive).

**Known false-positive modes**

- Some chart-generation / scaffolding templates emit a Cargo.toml without ``rust-version`` to defer the decision to the consumer. The rule still fires; suppress per file with a one-line rationale, or — better — add the explicit field once the project's compatibility surface stabilizes.

**Seen in the wild**

- Posture-drift class commonly surfaced in internal-tool audits of long-lived Rust projects: no ``rust-version`` field, CI runner pinned to a Rust release from years ago, several CVEs in the standard library quietly in scope. Adding the explicit field forces the runner-image bump or a hard build failure.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``rust-version`` field to ``[package]`` naming the minimum supported Rust toolchain:

    [package]
    name = "my-crate"
    version = "0.1.0"
    rust-version = "1.75"

The field tells cargo to error early if the consumer's toolchain is older than the named version, which catches the silent-incompatibility class of bug where a new language feature lands in a recent compiler but the consumer's CI image hasn't been updated. The field also documents the project's compatibility posture so downstream consumers can audit the toolchain matrix.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-011: build.rs runs network or process calls at compile time { #cargo-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the sibling ``build.rs`` and flags compile-time egress / exec idioms: network access (``std::net``, ``reqwest``, ``ureq``, ``isahc``, ``curl``, ``hyper``, ``tokio::net``), process spawning (``std::process::Command`` / ``Command::new``), and ``include!`` / ``include_str!`` / ``include_bytes!`` of a path.

The Rust analog of an npm install script (NPM lifecycle), a Maven build-time plugin (MVN-015), or a Go ``tool`` directive (GOMOD-011): code that runs during the build, not at application runtime. A build script with no flagged idiom (or no ``build.rs`` at all) passes.

**Known false-positive modes**

- Many legitimate ``build.rs`` files shell out to ``pkg-config`` / ``cc`` (via ``std::process::Command``) to locate or compile native libraries, and some ``include!`` a checked-in generated file. Those are normal; the rule surfaces the compile-time-execution surface so a reviewer can confirm the command / path / endpoint is constant and trusted. Suppress per crate with a rationale once verified. Network idioms in a build script are rarely legitimate and deserve the closest look.

**Seen in the wild**

- Compile-time / build-step code execution is the class behind the xz-utils backdoor (the payload ran from the build step, not the shipped library). A Rust ``build.rs`` that fetches or execs at compile time is the same primitive expressed in the Cargo build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit the ``build.rs`` egress / exec idioms this rule flags. A build script runs as native code during ``cargo build`` with the build's full privileges (CI runner write access, any mounted credentials), before any test or sandbox, so a network call can fetch and run an attacker-controlled payload and an ``include!`` of a non-constant path can pull arbitrary source into the compile. Remove network access from the build script (do any fetching ahead of time, into a checked-in, reviewed artifact), ``include!`` only constant, in-repo paths, and keep any process calls limited to constant, well-known build tools (``pkg-config`` / ``cc``). Where a build script isn't strictly needed, drop it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CARGO-012: .cargo/config.toml overrides the registry source or injects build flags { #cargo-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Parses the nearest ``.cargo/config.toml`` (walked up from the manifest to the scan root) and fires on two shapes: (1) any ``[source.<name>]`` table with a ``replace-with`` key, the source-substitution knob CARGO-005's ``docs_note`` calls out, which reroutes resolution without a Cargo.toml edit; (2) a ``[build]`` or ``[target.<cfg>]`` ``rustflags`` that sets a custom linker (``-C linker=`` / ``-Clinker=``) or a ``link-arg`` / ``link-args``, which can execute a binary at link time.

Distinct from CARGO-008 (``[patch]`` / ``[replace]`` in ``Cargo.toml``) and CARGO-005 (a per-dependency ``registry`` key): this rule audits the separate ``.cargo/config.toml`` file, which the manifest rules never read.

**Known false-positive modes**

- A ``replace-with`` pointing at a trusted, access-controlled internal mirror is a legitimate vendoring pattern, and a constant ``link-arg`` is sometimes genuinely required for a native build. Suppress per repo with a rationale once the replacement source and any linker flags are confirmed trusted.

**Seen in the wild**

- Source-replacement / dependency-confusion class: a ``replace-with`` silently rerouting the whole crate graph to an attacker-influenced registry, invisible to anyone reading only ``Cargo.toml``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit ``.cargo/config.toml`` source-replacement and build-flag keys. A ``[source.crates-io] replace-with`` reroutes the entire dependency graph to another source without touching a single ``Cargo.toml`` line, so a compromised or attacker-controlled replacement registry serves every crate the build pulls. A linker / link-arg injected through ``[build] rustflags`` (or ``[target.<cfg>] rustflags``) can run an arbitrary binary at link time. Remove the source replacement (or point it at a trusted, access-controlled internal mirror that you audit), and drop any ``rustflags`` that set a custom linker or ``link-arg`` unless it's a reviewed, constant value the build genuinely needs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CARGO-013: Cargo.lock package sourced off crates.io { #cargo-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Parses the committed ``Cargo.lock`` body and flags any ``[[package]]`` whose ``source`` is a ``git+`` URL or an alternate registry (a ``registry+`` / ``sparse+`` source that is not the canonical crates.io index). Packages with no ``source`` (local path / workspace members) are skipped.

Catches transitive source substitution the manifest rules can't reach: CARGO-002 (git dep mutable ref), CARGO-005 (alternate registry), and CARGO-008 (``[patch]`` / ``[replace]``) all read ``Cargo.toml`` direct declarations, while a substituted source can enter the graph transitively and only appears in the lockfile.

**Known false-positive modes**

- Workspaces that legitimately depend on a git fork (pending an upstream release) or pull internal crates from a trusted alternate registry will fire. Suppress per repo with a rationale once each off-crates.io source is confirmed; pin git sources to a ``rev`` SHA so the resolved commit is immutable.

**Seen in the wild**

- Transitive source-substitution class: a dependency-of-a-dependency silently resolved from a git fork or alternate registry rather than the audited crates.io release, invisible to anyone reading only the top-level manifest.

<div class="pg-rule__rec" markdown>

**Recommended action**

Confirm every off-crates.io ``source`` in ``Cargo.lock`` is intentional and trusted. A ``[[package]]`` whose ``source`` is a ``git+`` URL or an alternate registry (``registry+`` / ``sparse+`` pointing somewhere other than crates.io) is resolved outside the crates.io index and its checksum, so a transitive dependency can be substituted without any change to your ``Cargo.toml``. Prefer crates.io releases; where a git / alternate source is genuinely needed, pin it (``rev`` SHA for git, a trusted internal registry for alternates) and review what pulled it in. The manifest rules (CARGO-002 / CARGO-005 / CARGO-008) only see your direct declarations; the lockfile is where transitive substitution shows up.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CARGO-014: No supply-chain audit-gate config (cargo-deny / cargo-vet / cargo-audit) { #cargo-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Fires when a manifest declares dependencies but no committed audit-gate config is found at or above the manifest directory (bounded by the scan root): cargo-deny's ``deny.toml``, cargo-vet's ``supply-chain/config.toml``, or cargo-audit's ``audit.toml`` / ``.cargo/audit.toml``. A dependency-free manifest passes (nothing to gate).

LOW severity, below the default gate: it's a completeness / posture nudge, not a finding about a specific bad dependency (CARGO-006 / CARGO-013 cover those).

**Known false-positive modes**

- A repo that runs ``cargo audit`` purely as a CI step with no committed config file leaves nothing on disk for this rule to detect, so it fires as a false positive. Suppress per repo with a rationale naming the CI gate, or commit a minimal ``deny.toml`` / ``audit.toml`` so the gate is visible in the tree.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a committed supply-chain audit gate so dependency advisories, license drift, and untrusted sources fail the build instead of going unnoticed. Pick one (or more) and wire it into CI:

* cargo-deny: a ``deny.toml`` (advisory DB, license allowlist, banned crates, source allowlist), run with ``cargo deny check``.
* cargo-vet: a ``supply-chain/`` directory (``config.toml`` + ``audits.toml``) recording who reviewed each dependency, run with ``cargo vet``.
* cargo-audit: ``cargo audit`` against the RustSec advisory DB (optionally an ``audit.toml`` to tune it).

This is a posture signal (LOW): it doesn't prove a vulnerable dependency exists, only that the repo carries no committed gate to catch one. Parallel to CARGO-010 (missing ``rust-version``).

</div>

</div>

---

## Adding a new Cargo check

1. Create a new module at
   `pipeline_check/core/checks/cargo/rules/cargoNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pom: CargoFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``CargoFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/cargo/CARGO-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py cargo
   ```
