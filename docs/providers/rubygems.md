# RubyGems (Bundler) provider

Parses `Gemfile` (Bundler manifest, Ruby DSL) and probes for the
sibling `Gemfile.lock` on disk. Text-only static analysis via a
regex extractor over the canonical Bundler idioms, no
`bundle install`, no rubygems.org access, no Ruby runtime
required. Mirrors the npm / PyPI / Maven / NuGet / Go modules /
Cargo / Composer pack shape.

## Producer workflow

```bash
# --rubygems-path auto-detects ./Gemfile when present.
pipeline_check --pipeline rubygems
pipeline_check --pipeline rubygems --rubygems-path ./Gemfile
pipeline_check --pipeline rubygems --rubygems-path ./services/api/
```

## Manifest entries audited

| Entry | Notes |
|-------|-------|
| `source "..."` | Top-level and scoped `source "..." do ... end` |
| `gem "name", "..."` | Version constraints, option-hash form |
| `gem "x", git: ..., ref: ...` | Git source pin / mutable detection |
| `gem "x", github: "owner/repo"` | GitHub shorthand source |
| `gem "x", path: "..."` | Local path source |
| `group :dev do ... end` | Group scoping for dev/test entries |

`.git/`, `vendor/`, and `node_modules/` directories are skipped.

The parser is regex-driven rather than a true Ruby parser, so
genuinely dynamic Gemfiles (`Dir.glob` over `gem` calls, `eval`
of a generated string) are treated as opaque - the rule pack
reports what it can extract and otherwise passes through.

## What it covers

8 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GEM-001](#gem-001) | Gemfile present without a sibling Gemfile.lock | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GEM-002](#gem-002) | Gemfile gem entry uses a floating version constraint | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GEM-003](#gem-003) | Gemfile source declared over plain HTTP | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GEM-004](#gem-004) | Gemfile source URL embeds plaintext credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GEM-005](#gem-005) | Gemfile gem with git: / github: source missing a ref SHA pin | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GEM-006](#gem-006) | Gemfile requires a known-compromised gem version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GEM-007](#gem-007) | Gemfile declares multiple top-level sources without scoping | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GEM-008](#gem-008) | Gemfile gem declared with a path: source | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GEM-001: Gemfile present without a sibling Gemfile.lock { #gem-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires when the Gemfile's directory has no ``Gemfile.lock`` sibling. Libraries that legitimately publish without a lockfile need a per-file suppression with a one-line rationale naming the library posture.

**Known false-positive modes**

- Library gems published to rubygems.org intentionally omit Gemfile.lock from version control so downstream applications can deduplicate transitive deps. Suppress per gem with a one-line rationale.

**Seen in the wild**

- Long-running pattern of Ruby applications that ignore Gemfile.lock in .gitignore (a habit imported from gem development). CI builds resolve a fresh dependency graph every run; a transient rubygems.org-side bad patch release lands on the build the moment it's published. The 2019 rest-client maintainer compromise (CVE-2019-15224) was time-bounded; only consumers without a committed Gemfile.lock had any chance of pulling the bad patch.

<div class="pg-rule__rec" markdown>

**Recommended action**

Commit ``Gemfile.lock`` to the repository. Bundler resolves the dependency graph once at ``bundle install`` time and records the exact resolved versions for every transitive gem in the lockfile; every subsequent ``bundle install`` reads from the lockfile, so every build (locally and in CI) installs the same gem versions. Without it, Bundler re-resolves the manifest on every run and is free to pick the latest matching patch under any floating spec (GEM-002).

For libraries packaged as a ``.gemspec`` published to rubygems.org, the convention is to leave Gemfile.lock out of version control so downstream applications can deduplicate. This rule still fires on those, suppress per gem with a one-line rationale naming the gem-as-library posture. The default posture (Gemfile.lock committed) is correct for Rails / Sinatra / Hanami apps, internal services, CLI utilities, and anything that runs ``bundle install`` in CI.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GEM-002: Gemfile gem entry uses a floating version constraint { #gem-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when any ``gem`` entry's first version constraint is anything other than an exact triple (``X.Y.Z``). Tilde-arrow (``~> 7.0``), comparison (``>= 7``, ``< 8``), no version at all, and ranges all trip the rule. The right operator response is either an exact pin or a committed Gemfile.lock (GEM-001).

**Known false-positive modes**

- Rails, Rack, and a few core gems publish patches frequently and a strict exact-pin posture is operationally painful. Suppress per gem with a one-line rationale (``# pipeline_check:ignore GEM-002 - follows-rails-minor-track``) once the team has committed Gemfile.lock.

**Seen in the wild**

- Repeated supply-chain pattern: ``gem "rest-client"`` (no version) in a CI image without Gemfile.lock pulls the latest release on every build. The 2019 rest-client compromise (CVE-2019-15224) propagated exactly this way for the time window before the gem was yanked.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the floating constraint with an exact pin (``gem "rails", "7.0.4"``). A committed Gemfile.lock pins resolved versions at install time and is the primary defense; tightening the manifest constraint is the secondary defense (makes the tolerated upgrade window in ``bundle update`` explicit). The tilde-arrow operator (``~>``), no-version-at-all (``gem "rails"``), and comparison operators (``>=``, ``< 8``, ``!=``) let ``bundle update`` pull in any release matching the range — including a poisoned patch release published moments before the build. Bundler's ``~>`` is also tighter than people remember (``"~> 7.0"`` is ``>= 7.0, < 8.0``, not ``>= 7.0, < 7.1``).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GEM-003: Gemfile source declared over plain HTTP { #gem-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on any ``source "http://..."`` declaration (top-level or scoped ``source ... do … end`` block). Companion to NPM-004 / PYPI-004 / MVN-004 / NUGET-004 / GOMOD-004 / COMPOSER-003 — same risk model.

**Known false-positive modes**

- Air-gapped internal mirrors that can't terminate TLS may legitimately serve plain HTTP within a trusted network segment. Suppress per repo with a one-line rationale naming the network boundary; better still, front the mirror with a TLS-terminating reverse proxy.

**Seen in the wild**

- Classic dependency-confusion / MITM surface: an HTTP gem mirror serving an attacker-injected payload to a CI runner whose network path is shared with a compromised peer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch the source URL to ``https://``. Bundler 1.7+ issues a deprecation warning for plain-HTTP sources and later versions reject them outright; pinning to a non-HTTPS rubygems / internal mirror is a MITM attack surface that Bundler's defaults already try to close. The mirror you point at must serve TLS; if it doesn't, the deployment is broken in more places than this rule.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GEM-004: Gemfile source URL embeds plaintext credentials { #gem-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires when a ``source`` URL parses to a userinfo segment (``https://user:pass@host/...``) and the password segment is not a Bundler / shell-expansion placeholder (``$ENV_VAR`` / ``#{ENV[...]}``). Common case: copy-pasted setup script from internal docs that embedded the token literally.

**Known false-positive modes**

- URLs that embed only a username (``https://deploy@host/``) for OAuth-style flows without a literal secret. The rule allows usernames; only user:password pairs trip it.

**Seen in the wild**

- Standing-up a private gem mirror and copy-pasting the bootstrap URL straight into the Gemfile is a well-trodden footgun; the credential lands in git history and is exposed to anyone who can read the repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential out of the Gemfile and into ``bundle config set --global``: ``bundle config set https://gems.corp/ user:token``. Bundler stores those credentials in ``~/.bundle/config`` (per-user, git-ignored by Bundler convention), and ``$BUNDLE_<HOSTNAME>`` reads from the environment so the CI runner can mount the secret out-of-band. The URL in the Gemfile should be just the host and path with no userinfo. After scrubbing the manifest, rotate the credential — anything that was committed to git is compromised.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GEM-005: Gemfile gem with git: / github: source missing a ref SHA pin { #gem-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when a ``gem`` entry has a ``git:`` URL or ``github:`` shorthand and the entry doesn't carry a ``ref:`` option. ``branch:`` / ``tag:`` are treated as mutable refs (which they are). The lockfile pins the resolved SHA at install time, so the immediate risk is lower than the un-locked manifest case, but anyone running ``bundle update`` after a hostile force-push ingests the attacker's commit.

**Known false-positive modes**

- Internal monorepos where the ``git:`` source is a trusted internal repo with branch-protection rules in place may accept the lower assurance of a branch / tag pin. Suppress with a one-line rationale naming the branch-protection guarantee.

**Seen in the wild**

- Maintainer-account-compromise on a public repo lets the attacker force-push the named branch. The ``ref: "<sha>"`` pin is the one assurance that survives a compromise of the upstream account.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``branch:`` / ``tag:`` / no-ref-at-all with ``ref: "<40-char SHA>"``. A branch head can be force-pushed; a tag can be deleted and re-created pointing at a different commit; ``master`` / ``main`` (the default when no ref is given) is the most mutable of all. Only a commit SHA is content-addressable. After the bump, ``bundle update <gemname>`` to refresh the lockfile so the Gemfile.lock revision agrees with the Gemfile pin.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GEM-006: Gemfile requires a known-compromised gem version { #gem-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the curated registry under ``pipeline_check.core.checks.rubygems._compromised_gems`` (table of ``(gem, malicious_versions, advisory)`` entries) and fires when any ``gem`` entry — direct Gemfile dependency — matches. The registry is hand-curated and append-only; adding a new entry is a one-line table edit plus the citing advisory in the commit message.

Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / GOMOD-006 / CARGO-006 / COMPOSER-007 and shares the version-matching primitive (``_primitives.compromised.match_version``). The version literal compared is whatever the manifest declares; operators wanting *resolved* version coverage should also commit Gemfile.lock (GEM-001), at which point the lockfile-side audit can lift the matching from manifest to resolved-graph.

**Known false-positive modes**

- A manifest may legitimately pin a known-bad version because the consumer has applied a downstream patch or sandbox. The rule still fires; suppress per gem with a one-line rationale naming the patch.

**Seen in the wild**

- rest-client 1.6.10-1.6.13 (CVE-2019-15224): maintainer-token compromise published gems that exfiltrated env vars and opened a remote shell. strong_password 0.0.7 (CVE-2019-13354): backdoored release ran eval(open(...).read) on a remote Pastebin payload at boot. Future entries follow the same shape: append ``(gem, version, advisory)`` to _compromised_gems.py with the citing advisory in the commit message.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the offending gem to a patched version (named in the cited advisory) and refresh Gemfile.lock with ``bundle update <gemname>``. If the advisory has no patched release, pin to the last known-good version and add a follow-up TODO to replace or remove the gem. After the bump, re-run the scan; if GEM-006 still fires, an indirect dependency is pulling the bad version back in — use ``bundle why <gemname>`` (Bundler 3.0+) or ``bundle viz`` to find the path.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GEM-007: Gemfile declares multiple top-level sources without scoping { #gem-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when the Gemfile has two or more top-level ``source "..."`` declarations and at least one is not the public rubygems.org. Scoped ``source ... do … end`` blocks are not counted toward the top-level total. Companion to NUGET-007 (packageSourceMapping missing) and NPM-009 (scope-without-registry).

**Known false-positive modes**

- Legacy Gemfiles that have intentionally documented the dependency-confusion risk and accepted it (rare). Suppress at the Gemfile level with a one-line rationale.

**Seen in the wild**

- Bundler's own gem-source documentation walks through the dependency-confusion scenario in detail: a private gem name registered first by an attacker on the public rubygems.org will resolve before the private mirror when both sources are top-level.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the second top-level ``source`` with a scoped block: ``source "https://gems.corp/private" do … end``. Bundler 1.13+ warns on multiple top-level sources because the gem resolver can't tell which source a given name should come from — and an attacker publishing the same private gem name on rubygems.org first wins the lookup (the classic dependency-confusion vector). Pin private gems explicitly to the private source via a scoped block and leave only rubygems.org as the top-level default.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GEM-008: Gemfile gem declared with a path: source { #gem-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any ``gem "x", path: "..."`` entry that is not scoped to ``group :development`` / ``group :test`` only. Development-group-only path entries pass since they're explicitly excluded from production bundles. Mirrors CARGO-004 (path Cargo dep) and GOMOD-002 (local replace directive).

**Known false-positive modes**

- Development-group path entries are explicitly allowed. If a path entry legitimately needs to ship to production (rare — usually means the dependency should be properly published as a real gem) suppress with a one-line rationale.

**Seen in the wild**

- Cache-poisoning vector: an attacker who can write to the ``path:`` directory (parallel job sharing a workspace, a compromised CI cache, a writable ``actions/cache`` key) substitutes a malicious version of the local gem and the next ``bundle install`` ingests it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the ``path:`` source with a published, version-pinned dependency. A ``path:`` entry installs the gem from a local directory on the build runner, which:

1. bypasses the registry-side audit trail entirely (no version, no checksum, no advisory check),
2. is reproducible only if the local directory layout is reproducible (and CI runners rarely have one),
3. can be subverted by anything that can write to that directory before ``bundle install`` runs (cache poisoning, parallel job, ``actions/cache`` race).

If the dependency is genuinely a local development convenience, gate it behind ``group :development`` so it never runs in CI / production. If it has to ship, publish it as a real gem and pin the version.

</div>

</div>

---

## Adding a new RubyGems check

1. Create a new module at
   `pipeline_check/core/checks/rubygems/rules/gemNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pom: GemFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``GemFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/rubygems/GEM-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py rubygems
   ```
