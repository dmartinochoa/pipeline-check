# Composer (PHP) provider

Parses `composer.json` (Composer manifest) and probes for the
sibling `composer.lock` on disk. Text-only static analysis via
the JSON stdlib parser, no `composer install`, no Packagist
access, no PHP runtime required. Mirrors the npm / PyPI / Maven
/ NuGet / Go modules / Cargo pack shape.

## Producer workflow

```bash
# --composer-path auto-detects ./composer.json when present.
pipeline_check --pipeline composer
pipeline_check --pipeline composer --composer-path ./composer.json
pipeline_check --pipeline composer --composer-path ./packages/api/
```

## Manifest sections audited

| Section | Notes |
|---------|-------|
| `require` | Runtime dependencies |
| `require-dev` | Test / build-time dependencies |
| `repositories` | Extra package sources (Composer, VCS, etc.) |
| `scripts` | Install / update lifecycle hooks |
| `config.allow-plugins` | Plugin permission map |
| `minimum-stability` | Pre-release floor |

`vendor/`, `.git/`, and `node_modules/` directories are skipped.

## What it covers

8 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [COMPOSER-001](#composer-001) | composer.json present without a sibling composer.lock | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-002](#composer-002) | composer.json require uses a floating version constraint | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [COMPOSER-003](#composer-003) | composer.json repository declared over plain HTTP | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-004](#composer-004) | composer.json repository URL embeds plaintext credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-005](#composer-005) | composer.json minimum-stability accepts unstable releases | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [COMPOSER-006](#composer-006) | composer.json scripts hook pipes a remote download to a shell | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-007](#composer-007) | composer.json requires a known-compromised package version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-008](#composer-008) | composer.json allow-plugins permits any plugin to execute | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-001: composer.json present without a sibling composer.lock { #composer-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires when the manifest's directory has no ``composer.lock`` sibling. Libraries that legitimately publish without a lockfile need a per-file suppression with a one-line rationale naming the library-as-published posture.

**Known false-positive modes**

- Library packages published to Packagist intentionally omit composer.lock from version control so downstream applications can deduplicate transitive deps; this rule fires on those, suppress per package with a one-line rationale.

**Seen in the wild**

- Long-running pattern of PHP applications that ignore composer.lock in .gitignore (a habit imported from library development). CI builds resolve a fresh graph every run; a transient registry-side bad patch release lands on the build the moment it's published, then disappears on the next run, leaving no audit trail and no reproducer.

<div class="pg-rule__rec" markdown>

**Recommended action**

For applications, commit ``composer.lock`` to the repository. The lockfile records the exact resolved version of every transitive dependency, so every ``composer install`` (locally and in CI) installs the same code. Without it, ``composer install`` resolves the manifest fresh each time and is free to pick the latest matching patch under any floating constraint (COMPOSER-002). 

For libraries published to Packagist, Composer's guidance is the opposite — leave composer.lock uncommitted so downstream consumers can resolve. The default posture (composer.lock committed) is correct for applications, internal services, CLI tools, and Symfony / Laravel / WordPress projects.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## COMPOSER-002: composer.json require uses a floating version constraint { #composer-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when any ``require`` or ``require-dev`` entry's value is anything other than an exact triple (``X.Y.Z``) or 40-char commit hash. Caret-prefix (``^1.2``), tilde (``~1.2``), wildcard (``1.2.*`` / ``*``), comparison ranges (``>=1.2,<2``), and dev-branch aliases (``dev-master``, ``X.Y.x-dev``) all trip the rule. The right operator response is either an exact pin or a committed composer.lock (COMPOSER-001).

**Known false-positive modes**

- Some Symfony / Doctrine / Laravel packages publish patches frequently and a strict exact-pin posture is operationally painful. Suppress per dep with a one-line rationale (``# composer:ignore COMPOSER-002 - follows-symfony-minor-track``) once the team has committed composer.lock.

**Seen in the wild**

- Repeated supply-chain pattern: ``"vendor/package": "^1.0"`` in a CI image without composer.lock pulls the latest 1.x release on every build. Affected hours from upstream-publish to CI-pull is whatever your build cadence is.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the floating constraint with an exact pin (``"vendor/package": "1.2.3"``). A committed composer.lock pins resolved versions at install time and is the primary defense; tightening the manifest constraint is the secondary defense (makes the tolerated upgrade window in ``composer update`` explicit). Floating ranges (``^1.2``, ``~1.2``, ``1.2.*``, ``*``, ``dev-master``) let ``composer update`` pull in any release matching the range, including a poisoned patch release published moments before the build.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-003: composer.json repository declared over plain HTTP { #composer-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on any ``repositories`` entry whose ``url`` starts with ``http://``. Covers Composer, VCS, Artifact, and Path repository types alike. ``path://`` and ``file://`` entries are skipped (local-only). Companion to NPM-004 / PYPI-004 / MVN-004 / NUGET-004 / GOMOD-004 — same risk model.

**Known false-positive modes**

- Air-gapped internal mirrors that cannot terminate TLS may legitimately serve plain HTTP within a trusted network segment. Suppress per repo with a one-line rationale naming the network boundary; better still, front the mirror with a TLS-terminating reverse proxy.

**Seen in the wild**

- Classic dependency-confusion / MITM surface: an HTTP registry mirror serving an attacker-injected payload to a CI runner whose network path is shared with a compromised peer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch the repository URL to ``https://``. Composer since 1.8 ships with ``config.secure-http: true`` by default, which rejects any HTTP source; downgrading that flag (or running an older Composer) re-enables the MITM attack surface. The mirror you point at must serve TLS; if it doesn't, the deployment is broken in more places than this rule. Once on HTTPS, also pin the upstream certificate or registry signing key if the project supports it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-004: composer.json repository URL embeds plaintext credentials { #composer-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires when a repository ``url`` value parses to a userinfo segment (``https://user:pass@host/...``) and the password segment is not a Composer / shell-expansion placeholder (``${COMPOSER_AUTH_TOKEN}`` / ``%env(...)%``). Common case: copy-pasted setup script from a tutorial that embedded the token literally.

**Known false-positive modes**

- URLs that embed only a username (``https://deploy@host/...``) for OAuth-style flows without a literal secret. The rule allows usernames; only user:password pairs trip it.

**Seen in the wild**

- Standing-up a private Composer mirror and copy-pasting the bootstrap URL straight into composer.json is a well-trodden footgun; the credential lands in git history and is then exposed to anyone who can read the repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move credentials out of ``composer.json`` and into ``auth.json`` (or the equivalent environment variables: ``COMPOSER_AUTH``). ``auth.json`` is git-ignored by Composer convention; ``COMPOSER_AUTH`` reads JSON from the environment so the runner can mount the secret out-of-band. The URL in composer.json should be just the host and path with no userinfo. After scrubbing the manifest, rotate the credential — anything that was committed to git is compromised.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## COMPOSER-005: composer.json minimum-stability accepts unstable releases { #composer-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when ``minimum-stability`` is set to ``dev``, ``alpha``, ``beta``, or ``RC``. The default value is ``stable``, so the rule only trips on an explicit lowering. Composer evaluates this floor across the entire transitive graph: setting it to ``dev`` allows any dependency's dev-branch alias to satisfy a constraint, dramatically widening the attack surface (branch heads on packagist can be force-pushed).

**Known false-positive modes**

- Some teams legitimately run on pre-release Symfony / Doctrine versions during the release-candidate window. Suppress with a one-line rationale naming the RC track and a TODO to revert when the GA ships.

**Seen in the wild**

- Maintainer compromise risk multiplies on dev branch aliases — a force-push to ``master`` propagates to every consumer on ``dev-master`` the moment Composer re-resolves. The combined floor (this rule) plus dev-branch aliases (COMPOSER-002) is the high-blast case.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``"minimum-stability": "stable"`` in composer.json (or leave the key unset; Composer's default *is* ``stable``). When a specific dependency genuinely needs a pre-release, pin it with the per-dep stability flag instead: ``"vendor/pkg": "1.0.0-RC1@RC"``. That way the manifest declares one explicit exception rather than lowering the floor for the whole graph.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-006: composer.json scripts hook pipes a remote download to a shell { #composer-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when any ``scripts`` entry's command body contains ``curl ... | sh`` / ``wget ... | bash`` / ``curl ... | php`` style patterns. The match is conservative: it requires both a download token (``curl`` / ``wget`` / ``iwr`` / ``Invoke-WebRequest`` / ``fetch``) and a pipe to an interpreter (``sh`` / ``bash`` / ``zsh`` / ``php`` / ``python`` / ``node``). Patterns that download then verify with ``sha256sum -c`` are explicitly allowed by checking for a ``sha256`` token in the same command line.

**Known false-positive modes**

- An install hook that downloads to a temp file and then verifies via ``sha256sum --check`` is treated as safe. If the verification step is in a *separate* script entry (different array element), the rule may still trip — combine them into one line so the verification is visible.

**Seen in the wild**

- Standard supply-chain attack vector: install scripts that fetch and run upstream code at install time give the package author RCE on every consumer's CI runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Stop piping ``curl`` / ``wget`` / ``Invoke-WebRequest`` output directly into a shell from a Composer lifecycle hook. Download the artifact to a temp file, verify a pinned SHA-256 / signature, then execute. Better still, move the install step out of the manifest entirely — ship the dependency as a versioned Composer package, or fetch it in a Dockerfile / CI step where the verification chain is auditable per-build.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-007: composer.json requires a known-compromised package version { #composer-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the curated registry under ``pipeline_check.core.checks.composer._compromised_packages`` (table of ``(package, malicious_versions, advisory)`` entries) and fires when any dependency — direct ``require`` or ``require-dev`` — matches an entry. The registry is hand-curated and append-only; adding a new entry is a one-line table edit plus the citing advisory in the commit message.

Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / GOMOD-006 / CARGO-006 and shares the version-matching primitive (``_primitives.compromised.match_version``). The version literal compared is whatever the manifest declares; operators wanting *resolved* version coverage should also commit composer.lock (COMPOSER-001), at which point the lockfile-side audit can lift the rule's matching from manifest to resolved-graph.

**Known false-positive modes**

- A manifest may legitimately pin a known-bad version because the consumer has applied a downstream patch or sandbox. The rule still fires; suppress per dep with a one-line rationale naming the patch.

**Seen in the wild**

- Composer ecosystem has had a steady stream of maintainer-account compromises (PHP-FIG / Symfony supply-chain incidents in 2023-2024). Future entries follow the same shape: append ``(package, version, advisory)`` to _compromised_packages.py with the citing advisory in the commit message.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the offending dep to a patched version (named in the cited advisory) and refresh composer.lock with ``composer update vendor/package``. If the advisory has no patched release, pin to the last known-good version and add a follow-up TODO to replace or remove the dependency. After the bump, re-run the scan; if COMPOSER-007 still fires, an indirect dependency is pulling the bad version back in — use ``composer why vendor/package`` to find the path.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-008: composer.json allow-plugins permits any plugin to execute { #composer-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Fires when ``config.allow-plugins`` is set to the boolean ``true``. The legitimate shapes are: omit the key (Composer defaults to ``false`` / empty map and prompts), set it to ``false`` (block all), or set it to a map of plugin names with boolean values. Setting any individual entry to ``true`` is a per-plugin allowlist, which the rule allows; only the wildcard boolean trips the rule.

**Known false-positive modes**

- Some bootstrap / scaffolding tools (Symfony Flex, Laravel Installer) need plugin execution to run scaffolds. Allowlist them by name instead: ``{"symfony/flex": true}``. The rule fires only on the wildcard form so a per-plugin allowlist of any size passes.

**Seen in the wild**

- Composer 2.2 introduced ``allow-plugins`` after a spate of supply-chain incidents where a transitive dep shipped a plugin that exfiltrated the env at ``composer install`` time. The gate works only when the operator explicitly allowlists; setting the wildcard restores the pre-2.2 attack surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``"allow-plugins": true`` with an explicit per-plugin map: ``"allow-plugins": {"vendor/known-plugin": true, ...}``. Composer plugins run arbitrary PHP at install time — including from transitive deps — so the allowlist is one of Composer's primary security boundaries. The wildcard (``true``) defeats the gate entirely. Composer 2.2+ ships the default value as ``{}`` and prompts before running any plugin in interactive mode; CI is non-interactive, so the prompt is silently bypassed and every plugin in the graph runs.

</div>

</div>

---

## Adding a new Composer check

1. Create a new module at
   `pipeline_check/core/checks/composer/rules/composerNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pom: ComposerFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``ComposerFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/composer/COMPOSER-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py composer
   ```
