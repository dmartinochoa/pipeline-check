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

6 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CARGO-001](#cargo-001) | Cargo.toml dependency uses a floating version spec | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-002](#cargo-002) | Cargo.toml git dependency uses a mutable ref (no rev) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-003](#cargo-003) | Cargo.toml present without a sibling Cargo.lock | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-004](#cargo-004) | Cargo.toml dependency is a local-path entry | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CARGO-005](#cargo-005) | Cargo.toml dependency sourced from an alternate registry | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CARGO-006](#cargo-006) | Cargo.toml requires a known-compromised crate version | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
