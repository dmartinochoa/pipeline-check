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

14 checks · 0 have an autofix patch (``--fix``).

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
| [COMPOSER-009](#composer-009) | auth.json committed alongside composer.json with literal credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-010](#composer-010) | composer.json config.secure-http: false disables HTTPS enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [COMPOSER-011](#composer-011) | composer.json repository re-points a package to an external VCS source | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-012](#composer-012) | composer.json disables Packagist or marks a custom repo canonical | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-013](#composer-013) | composer.json config.disable-tls turns off certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [COMPOSER-014](#composer-014) | composer.json minimum-stability lowered without prefer-stable | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-009: auth.json committed alongside composer.json with literal credentials { #composer-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Fires when the manifest's directory has a sibling ``auth.json`` file and that file's JSON body has at least one entry under ``http-basic`` / ``bearer`` / ``github-oauth`` / ``gitlab-oauth`` / ``gitlab-token`` / ``bitbucket-oauth`` with a literal credential. Placeholder values (``${ENV}`` / ``${COMPOSER_AUTH_TOKEN}``) are ignored. An empty / malformed auth.json passes silently.

**Known false-positive modes**

- Some monorepos use a per-project auth.json that intentionally pins to a low-privilege read-only token scoped to a single private mirror. The rule still fires — suppress per file with a one-line rationale naming the read-only-scope guarantee. Better: move the credential to a runner-side mount.

**Seen in the wild**

- Recurring pattern across PHP shops: a developer copy-pastes ``composer config http-basic …`` from internal docs without running ``composer config --global``, leaving the credential in the project's ``auth.json`` instead of the user's home dir. The credential then lands in the next commit and is exposed to every reader of the repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``auth.json`` from version control and add it to ``.gitignore``. Composer reads credentials from ``auth.json`` out of band of ``composer.json`` for exactly the reason that the credential should never live in the same git history as the manifest — the manifest is meant for the team, ``auth.json`` is meant for the runner. On CI, export the credential through ``$COMPOSER_AUTH`` (Composer reads JSON-shaped env at install time) so the runner mounts the secret out-of-band and no committed file ever holds it.

After removing the file from the working tree, rotate every credential the file ever contained. ``git filter-repo`` (or ``git rebase -i`` for a recent commit) can remove the file from history, but rotation is the irrevocable step — anyone who cloned the repo while the file was tracked has the credential.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## COMPOSER-010: composer.json config.secure-http: false disables HTTPS enforcement { #composer-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Fires when ``config.secure-http`` is explicitly set to the boolean ``false`` in ``composer.json``. The default value (``true``) is the safe posture, so the rule only trips on an explicit downgrade. Companion to COMPOSER-003 (per-repository HTTP URL): COMPOSER-003 catches one offending URL; COMPOSER-010 catches the project-wide flag that lets *any* URL be plain HTTP without complaint.

**Known false-positive modes**

- Air-gapped internal mirrors that absolutely can't terminate TLS may legitimately need this flag. Suppress with a one-line rationale naming the network boundary; revisit when the network team brings up a TLS proxy.

**Seen in the wild**

- Composer 1.8.0 release notes mark ``secure-http`` as ``true`` by default because plain-HTTP package fetches were the most reliable MITM surface in the ecosystem. Explicit ``false`` re-opens that surface for every install run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``config.secure-http: false`` entry from ``composer.json`` (or set it back to ``true``). Composer's default has been ``secure-http: true`` since 1.8; the explicit ``false`` is a deliberate downgrade that lets the project pull packages from plain-HTTP sources without complaint. That defeats the same defense that COMPOSER-003 protects on the individual ``repositories`` URL — a plain-HTTP mirror, a typosquatted public source, anything the package resolver finds is now eligible for fetch.

If the deployment legitimately needs to talk to an internal mirror that can't terminate TLS, front the mirror with a TLS-terminating reverse proxy. The ``secure-http: false`` escape hatch is a project-wide weakening that almost always outlives the local constraint that motivated it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-011: composer.json repository re-points a package to an external VCS source { #composer-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any ``repositories`` entry of type ``vcs``, ``git``, ``package``, or ``composer``. These types re-point package resolution to an arbitrary source, and because custom repos win over Packagist, a malicious entry is a dependency-confusion vector. ``path`` and ``artifact`` types are local-only and don't trip the rule. Companion to COMPOSER-012 (Packagist disabled / custom repo canonical).

**Known false-positive modes**

- Private organizations legitimately host internal packages on a custom Composer / VCS repository. Suppress with a one-line rationale confirming the URL is owned by your team; pair it with namespaced package names so the custom source can't shadow a public coordinate.

**Seen in the wild**

- Composer resolves custom ``repositories`` before Packagist, the same priority order that makes dependency-confusion attacks work across npm / PyPI / NuGet. A custom ``vcs`` entry that names a public coordinate serves the attacker's fork on the next install.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the custom ``repositories`` entry, or pin the package to a trusted source you control. Composer resolves custom repositories ahead of Packagist, so a ``vcs`` / ``git`` / ``package`` / ``composer`` entry can quietly override a well-known coordinate with an attacker-controlled fork. This is the Composer shape of dependency confusion: the coordinate still reads like the real package, but resolution now points at the custom source first.

If the project genuinely needs an internal package source, keep it but confirm the URL is owned by your team and that the names it serves are namespaced so they can't shadow public packages.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-012: composer.json disables Packagist or marks a custom repo canonical { #composer-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on two exact shapes inside ``repositories``: a Packagist disable (``{"packagist.org": false}`` or ``{"packagist": false}``), or a custom repo with ``"canonical": true``. Both hand package resolution to a non-default source for the names it provides. Exact key / value reads keep this the lowest-false-positive rule of the repository set. Companion to COMPOSER-011 (custom vcs / package repo).

**Seen in the wild**

- Disabling Packagist or marking a mirror canonical is the documented Composer way to force every dependency through one source. When that source is attacker-owned, the whole graph resolves through it, the worst-case version of dependency confusion.

<div class="pg-rule__rec" markdown>

**Recommended action**

Keep Packagist enabled and avoid marking a custom repository canonical unless you fully trust it for every coordinate it can serve. Disabling Packagist with ``{"packagist.org": false}`` (or the legacy ``"packagist": false``), or setting ``"canonical": true`` on a custom repo, lets that single source answer for any package name, including ones it should not own. That is the broadest form of the dependency-confusion surface COMPOSER-011 catches per entry.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## COMPOSER-013: composer.json config.disable-tls turns off certificate verification { #composer-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires when ``config.disable-tls`` is explicitly set to the boolean ``true`` in ``composer.json``. The default (``false``) is the safe posture, so the rule only trips on an explicit downgrade. Mirrors the one-key config lookup of COMPOSER-008 (allow-plugins) and COMPOSER-010 (secure-http).

**Seen in the wild**

- Composer documents ``disable-tls`` as a last-resort escape hatch precisely because it removes the only integrity guarantee on package downloads. A persistent ``true`` in a committed manifest re-opens the MITM surface on every CI install run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``config.disable-tls: true`` entry from ``composer.json`` (or set it back to ``false``). With TLS disabled, Composer skips certificate verification on every HTTPS request, so a man-in-the-middle can present a forged certificate and serve tampered packages without a warning. This is strictly worse than ``secure-http: false`` (COMPOSER-010): that one allows plain HTTP, this one keeps the ``https://`` scheme but stops validating who is on the other end.

If a certificate error pushed someone to set this flag, fix the trust chain (install the corporate CA, renew the expired cert) rather than turning verification off globally.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## COMPOSER-014: composer.json minimum-stability lowered without prefer-stable { #composer-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when top-level ``minimum-stability`` is one of ``dev``, ``alpha``, ``beta``, or ``RC`` and top-level ``prefer-stable`` is not ``true``. Reads both top-level keys. Where COMPOSER-005 fires on any lowered floor, COMPOSER-014 is the subset where ``prefer-stable`` does not soften it, so the two overlap by design (005 is the broad signal, 014 the sharper one).

**Known false-positive modes**

- Projects that intentionally track dev dependencies may accept the lowered floor. Adding ``prefer-stable: true`` keeps the wider range while preferring stable where available, which clears this rule without giving up the pre-release access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``"prefer-stable": true`` alongside a lowered ``minimum-stability``, or raise ``minimum-stability`` back to ``stable``. With ``prefer-stable`` off, Composer is free to resolve every dependency to a dev / alpha / beta / RC release even when a stable version exists, pulling unreviewed code across the whole tree. ``prefer-stable: true`` keeps the wider floor (needed for a few genuine pre-release deps) while still preferring stable wherever it can.

COMPOSER-005 flags the lowered floor on its own; this rule narrows to the higher-risk combination where nothing pulls resolution back toward stable.

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
