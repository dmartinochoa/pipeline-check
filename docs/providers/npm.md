# npm provider

Parses ``package.json`` / ``package-lock.json`` /
``npm-shrinkwrap.json`` documents on disk for supply-chain hygiene.
Text-only static analysis, no ``npm install``, no registry pull, no
daemon access. Rule modules see either an ``NpmManifest`` (the
parsed ``package.json``) or an ``NpmLock`` (the parsed lockfile) and
flag the patterns that turned the Shai-Hulud / TanStack / PyTorch-
``torchtriton`` class of incidents into mass-propagation events.

## Producer workflow

```bash
# --npm-path is auto-detected when package.json / package-lock.json
# exist at cwd; the CLI announces the pick on stderr.
pipeline_check --pipeline npm

# …or pass it explicitly.
pipeline_check --pipeline npm --npm-path path/to/package.json

# Recursively scan a monorepo: every package.json / package-lock.json
# outside node_modules/ is picked up.
pipeline_check --pipeline npm --npm-path packages/
```

The loader skips anything under ``node_modules/`` so transitive
manifests don't dilute the signal; only the manifests + lockfiles you
authored are evaluated.

## Scope

* ``package.json`` (root manifest, ``dependencies`` /
  ``devDependencies`` / ``optionalDependencies`` /
  ``peerDependencies`` / ``scripts``)
* ``package-lock.json`` / ``npm-shrinkwrap.json`` (npm 6 v1 and npm
  7+ v2 / v3 schemas)

``yarn.lock`` and ``pnpm-lock.yaml`` are out of scope for the
initial pack; both formats are distinct enough to warrant their own
parsers and are queued for a follow-up.

## What it covers

20 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [NPM-001](#npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NPM-002](#npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-003](#npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-004](#npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-005](#npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-006](#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [NPM-007](#npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-008](#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-009](#npm-009) | New transitive dependency added since the base ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-010](#npm-010) | npm package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [NPM-011](#npm-011) | package.json files field includes secret-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-012](#npm-012) | .npmrc publish token lacks IP or readonly restriction | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-013](#npm-013) | package.json files field uses an overly broad pattern | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-014](#npm-014) | Direct dependency relies on a single npm publisher | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [NPM-015](#npm-015) | Direct dependency published without build provenance | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [NPM-016](#npm-016) | Direct dependency has a low OpenSSF Scorecard | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [NPM-017](#npm-017) | Direct dependency provenance built from a non-release ref | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [NPM-018](#npm-018) | Direct dependency's latest release published by a new npm account | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NPM-019](#npm-019) | package.json overrides / resolutions rewrites a dependency to a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-020](#npm-020) | .npmrc repoints the default or a scoped registry to a non-canonical host | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## NPM-001: package.json dependency uses a floating version range { #npm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on every entry in ``dependencies`` / ``devDependencies`` / ``optionalDependencies`` / ``peerDependencies`` whose value starts with ``^``, ``~``, ``*``, ``>``, ``<``, ``||``, carries a wildcard token (``1.x``, ``1.2.X``, ``x``), or is the dist-tag ``latest`` / ``next`` / ``beta`` / ``alpha`` / ``canary`` / ``dev``. ``workspace:*`` (Yarn / pnpm workspace protocol), ``file:`` / ``link:`` (local checkouts), ``git+`` / ``http(s)://`` (URL deps), and ``npm:`` (alias) are not version ranges and are routed to other rules. Complements NPM-002, which catches lockfile entries missing integrity hashes; NPM-001 is the manifest-side hygiene.

**Known false-positive modes**

- Monorepo packages that pin every dep to a workspace-internal version often use ``workspace:*``; those are skipped by the rule. Library packages (``private: false``, ``main`` set) intentionally use ranges in ``peerDependencies`` so consumers can satisfy them flexibly; suppress with a one-line rationale for libraries you publish to npm.

**Seen in the wild**

- TanStack / Mistral npm compromise (May 2026): 84 versions across 42 packages published in minutes, each carrying a credential-stealing ``postinstall``. Consumers with floating ranges (``^x.y.z``) installed the poisoned versions on the next install; pinned exact-version repos were spared until they manually bumped.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace floating range specifiers (``^``, ``~``, ``*``, ``>=``, ``latest``) with an exact version pin (``"lodash": "4.17.21"``). The floating form lets npm install any later version that matches the range, so a compromised patch release (TanStack, axios, debug, Shai-Hulud) reaches the build without a code change. Pair the pinned manifest with a committed ``package-lock.json`` (NPM-002 / NPM-003 guard the lockfile content).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-002: package-lock.json entry missing integrity hash { #npm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Walks every entry under ``packages`` (npm 7+ schema ``lockfileVersion: 2`` / ``3``) or ``dependencies`` (npm 6 schema ``lockfileVersion: 1``) and flags records missing an ``integrity`` field that has a ``resolved`` URL (a fetched tarball without integrity is the unsafe case). Skips link entries (``link: true``) and workspace entries, which have no tarball to hash. Local file dependencies (``file:`` specs) are caught by NPM-003. Complements NPM-003 (non-registry source URL); NPM-002 is the case where the source URL exists but the verification anchor doesn't.

**Known false-positive modes**

- Lockfiles produced by old npm versions (npm < 5) wrote ``sha1-...`` integrity strings that some downstream tools regenerate as missing. The fix is the same in both cases: regenerate with a current npm version against a hash-providing registry.

<div class="pg-rule__rec" markdown>

**Recommended action**

Regenerate the lockfile with ``npm install`` against a registry that returns SRI integrity hashes (the default ``https://registry.npmjs.org``). Every entry should carry an ``integrity`` field like ``sha512-...`` keyed off the tarball contents. A missing hash means npm has nothing to compare against at install time, so a registry that swaps the tarball mid-flight (cache poisoning, MITM, malicious mirror) ships arbitrary code without detection.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-003: package-lock.json entry resolves from a non-registry source { #npm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when a lockfile entry's ``resolved`` URL points at anything other than an HTTPS registry. Detected shapes:

* ``git+ssh://`` / ``ssh://`` — opaque, unreviewable
* ``git+http://`` / ``git://`` / ``http://`` — unencrypted transport, MITM surface
* ``file:`` referencing anything outside the project tree — host-specific install

Standard ``https://registry.npmjs.org`` and other registered registries (GitHub Packages, Verdaccio, internal proxies) pass. A ``git+https://`` URL with a 40-character SHA also passes — that's the documented escape hatch for forks not yet published to a registry. Complements NPM-002 (missing integrity hash); NPM-003 catches the *source* shape, NPM-002 catches the *verification* shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the dependency to a hash-verifiable registry source. If you genuinely need a fork that's not on npm, pin it via ``git+https://host/owner/repo.git#<40-char-sha>`` (exact commit, not a branch or tag) and document the audit trail. ``git+ssh://`` URLs are unreviewable by anyone without access to the same private SSH endpoint; ``http://`` URLs are MITM-able; bare ``file:`` paths bind the build to a developer-machine layout. The default-safe shape is ``https://registry.npmjs.org/...`` with ``integrity: sha512-...``, anything else needs a one-line rationale.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-004: package.json declares an install-time lifecycle script { #npm-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when ``package.json`` ``scripts`` declares any of:

* ``preinstall`` — runs before dependencies install
* ``install`` — the canonical install hook (rarely needed; node-gyp triggers this automatically when ``binding.gyp`` exists, no script needed)
* ``postinstall`` — runs after dependencies install; the Shai-Hulud worm primitive
* ``prepare`` — runs on ``npm install`` (no args) and on ``npm publish``; effectively a postinstall for consumers

This rule guards the *package you're publishing*. To stop *consumed* dependencies from running their install scripts during your build, use ``npm ci --ignore-scripts`` (DF-024 in the Dockerfile pack). Together they cover both sides of the lifecycle-script attack surface.

**Known false-positive modes**

- Packages that wrap a binary release (``esbuild``, ``swc``) use ``postinstall`` to download the platform-specific binary. Suppress with a one-line rationale that names the binary source URL and the integrity check the script performs. If the script has neither, the package is the anti-pattern, not the rule.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the postinstall in compromised packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, used the stolen tokens to publish more compromised packages and push malicious workflow files into victim repos. Removing the install-time script primitive on the *publisher* side is the structural fix.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the work out of ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` and into an explicit script (``"build": "..."``) invoked at a controlled point in your pipeline. Install-time scripts run on every consumer's machine the moment they ``npm install`` your package, with the consumer's environment (``GH_TOKEN``, ``NPM_TOKEN``, AWS env, SSH keys). They're also the propagation primitive the Shai-Hulud worm used to spread across the npm ecosystem in 2026. If your package legitimately needs native-module compilation, document it in the README and expose the build via ``"build": "node-gyp rebuild"`` so consumers opt in by calling ``npm run build`` rather than being opted in by ``npm install``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-005: package.json git dependency uses a mutable ref { #npm-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires on dependency specs of the shapes:

* ``git+https://host/owner/repo.git#<ref>`` where ``<ref>`` is not a 40-character SHA
* ``github:owner/repo#<ref>`` (shorthand) with non-SHA ``<ref>``
* ``git+ssh://...``, ``git://...`` (these are also caught by NPM-003 on the lockfile side; flagging here gives users the manifest-side signal too)
* A bare ``github:owner/repo`` with no ``#`` ref at all (resolves to ``HEAD`` of the default branch — fully mutable)

Skips entries already routed elsewhere: registry specs (NPM-001), ``file:`` / ``link:`` / ``workspace:`` (NPM-003).

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the git dependency to a 40-character commit SHA: ``"foo": "git+https://github.com/owner/repo.git#<sha>"``. Branch refs (``#main``, ``#master``) and tag refs (``#v1.2.3``) are mutable, anyone with push access to the upstream repo can swap the contents of what your build pulls without changing the dependency string. A commit SHA is immutable; a tampered upstream cannot redirect ``#<sha>`` to different content. If the upstream isn't yours, vendor the fork into a registry you control (GitHub Packages, internal Verdaccio) and pin via registry version instead.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## NPM-006: package-lock.json pins a known-compromised package version { #npm-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Walks every entry in the lockfile (npm 7+ ``packages`` map and npm 6 ``dependencies`` tree) against the curated compromised-package registry in ``pipeline_check.core.checks.npm._compromised_packages``. Match is case-insensitive on package name and exact on version literal (with optional regex fallback for advisories that span a range). Lockfile coverage means both direct dependencies *and* transitive ones are caught — the more common attack shape, where ``axios -> plain-crypto-js`` (March 2026) pulled in a backdoored transitive that the direct ``package.json`` declaration never mentioned. Registry is hand-curated and append-only; refresh by PR with the citing CVE / GHSA / vendor advisory in the commit message.

**Known false-positive modes**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing advisory exists. For broader coverage, run ``npm audit`` or ``osv-scanner`` alongside pipeline-check; NPM-006 is the curated supply-chain anchor, not a vulnerability database.

**Seen in the wild**

- event-stream 3.3.6 (Nov 2018): canonical npm maintainer-takeover. The hijacked publisher added a malicious ``flatmap-stream`` transitive that targeted Copay wallet builds. https://github.com/dominictarr/event-stream/issues/116
- ua-parser-js compromise ([CVE-2021-43547](https://nvd.nist.gov/vuln/detail/CVE-2021-43547), Oct 2021): hijacked maintainer account; the malicious versions ran a crypto miner + password stealer via postinstall on every consumer.
- coa + rc compromise ([GHSA-73qr-pfmq-6rp8](https://github.com/advisories/GHSA-73qr-pfmq-6rp8), Nov 2021): coordinated maintainer-account-takeover campaign hitting two widely-used CLI helpers within hours of each other.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate every secret reachable to any process that ran ``npm install`` against this lockfile during the window the compromised version was installed. Bump the affected dependency to a post-incident clean version published by the upstream maintainer (announced in the citing advisory), regenerate the lockfile, and audit CI build logs for the exfiltration shape the advisory documents. Pair with NPM-004 (install-time lifecycle scripts) so the postinstall primitive most npm compromises rely on is disabled at the publisher side, and DF-024 (``--ignore-scripts``) so the image build can't re-enable it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-007: .npmrc does not disable install-time lifecycle scripts { #npm-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when a ``.npmrc`` exists but does NOT declare ``ignore-scripts=true``. Two failure shapes are flagged:

* Explicit re-enable: ``ignore-scripts=false`` — someone   deliberately turned off the protection.
* Implicit default: ``ignore-scripts`` not set — npm's   built-in default is to RUN scripts.

The rule does NOT fire when no ``.npmrc`` exists in the scan path; that case is too broad to flag without generating noise on every JavaScript repo (the npm pack's DF-024 rule catches the same primitive in the image-build path, which most production deployments use). To enforce the rule globally, ship a ``.npmrc`` that declares ``ignore-scripts=true`` and the rule's contract becomes a ratchet: future commits cannot silently re-enable scripts without tripping this check.

Complements NPM-004 (``package.json`` declares its own install-time hook on the publisher side) and DF-024 (``RUN npm install`` without ``--ignore-scripts`` at image-build time). NPM-004 protects consumers of *your* package; NPM-007 protects *you* from compromised transitive dependencies on the next install.

**Known false-positive modes**

- Repos that build native modules via ``node-gyp`` (``better-sqlite3``, ``sharp``, ``canvas``, …) need the lifecycle scripts to compile bindings. The right pattern is to keep ``ignore-scripts=true`` at the top-level install and per-package ``npm rebuild <name>`` after, scoped to the audited native-module set. Suppress only with a one-line rationale that names the specific binding packages.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the postinstall in compromised packages scraped credentials and pushed propagation workflow files. ``ignore-scripts=true`` neutralizes the postinstall primitive at install time — the worm cannot execute its first stage if scripts are disabled.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``ignore-scripts=true`` to the repo's ``.npmrc``. The setting tells npm / pnpm / Yarn 1 to skip every ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` hook on every transitive dependency, including the ones added in a future ``npm install``. This is the file-side complement to DF-024 (which catches the same primitive at ``docker build`` time) — DF-024 protects the image, NPM-007 protects the developer laptop and any unattended CI step running ``npm install`` outside a container. If a specific package legitimately needs its build script (a native module like ``better-sqlite3``), allow-list it after the install: ``npm rebuild better-sqlite3``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-008: Direct dependency was published within the cooldown window { #npm-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to populate the per-package publish timestamps from ``registry.npmjs.org``. Walks every direct dependency in ``dependencies`` / ``devDependencies`` / ``peerDependencies`` / ``optionalDependencies`` (transitive packages aren't covered, the cooldown applies to what *you* chose to bump). Lockfile entries are out of scope, the rule reasons about the manifest's pinned spec since that's what changes when a maintainer bumps a dep. When ``--resolve-remote`` is off or the registry can't be reached, the rule passes silently so the absence of the network path doesn't trip CI.

**Known false-positive modes**

- Pre-release versions (``foo@1.0.0-rc.1``) are often freshly published; the cooldown applies to them too because pre-release tags have been used as carriers in real compromises (see the @ctrl/* / nx campaigns). Suppress per-resource via ``--ignore-file`` when a release-train workflow legitimately bumps to a same-day RC.
- Same-day patch upgrades from a maintainer the team directly trusts (e.g. a vendored fork the team owns) are flagged. Suppress per-resource, the cooldown is a default-safe gate, not a hard rule.

**Seen in the wild**

- Shai-Hulud-class npm worm (Sep 2025): malicious versions published, detected, and yanked within 48h on multiple packages. Consumers who held a 7-day cooldown caught the takedown before the version hit their lockfile.
- @ctrl/tinycolor maintainer-account takeover (May 2024): the malicious versions stayed live for ~36 hours before GitHub Advisory and npm coordinated removal. Cooldown of any meaningful length would have skipped them.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either skip the just-published version (pin to the last release older than the cooldown window) or wait until the cooldown has elapsed before bumping the lockfile. Most publisher-account compromises (Shai-Hulud / TanStack / axios -> plain-crypto-js) are detected and yanked from the registry within hours-to-days of publication; holding back N days converts a publisher-compromise window into a vulnerability-disclosure window where either the publisher rotates the malicious version off the registry or the security community files an advisory you can match against NPM-006. Tune the cooldown via ``--npm-cooldown-days`` (default 7).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-009: New transitive dependency added since the base ref { #npm-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Needs ``--npm-base-ref <ref>`` to materialize each lockfile's contents at the base ref via ``git show``. Compares the set of package names in the current vs. base lockfile and subtracts top-level direct dependencies (those are NPM-008's territory). Fires HIGH per lockfile when any name appears in the current set that isn't in the base set, after the direct-dep subtraction. Silent-passes when ``--npm-base-ref`` isn't set, the base ref can't be resolved by git, or the lockfile is brand new to this branch (no base counterpart). Diffs by package *name* only — version bumps of an existing transitive are out of scope (NPM-006 covers known-bad version pins; NPM-008 covers fresh-publication windows). Both ``package-lock.json`` (npm 7+) and ``pnpm-lock.yaml`` / ``yarn.lock`` are covered through the shared lockfile-shape synthesizers, which carry each package's declared dependency edges. Every new transitive is annotated with the direct dependency that pulled it in (``<name> (via <parent>)``), traced through the edge graph to the nearest manifest dependency, so reviewers know whose changelog to read. A deep transitive with no resolvable manifest ancestor falls back to its immediate declaring parent.

**Known false-positive modes**

- A legitimate maintainer bump can introduce new transitives by design (a library splitting an internal helper into a separate package, an upstream switching from a vendored copy to a published dep). Suppress per-resource via ``--ignore-file`` once a human audits the new transitive and confirms it's expected.
- Branches that delete a direct dep also delete its transitives from the lockfile; re-adding the direct dep later resurrects the transitives. The rule fires on the re-add because the names are 'new' relative to the base ref. Review by reading the diff, then suppress.

**Seen in the wild**

- axios -> plain-crypto-js (March 2026): a malicious transitive was added in a patch release of axios. Consumers who diffed transitives against their previous lockfile saw the new package land before ``npm install`` executed the payload.
- ua-parser-js (October 2021): a maintainer-account takeover published versions that quietly pulled in new transitives carrying a coinminer and credential stealer. Lockfile-pinning consumers who diffed transitives spotted the unexpected new packages before install.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit the new transitive dependency before letting it land. Confirm the maintainer of the parent direct dependency intentionally added it (read the changelog of the patch / minor bump that introduced it). The axios -> plain-crypto-js backdoor (March 2026) was a single new transitive sneaked into a patch release; lockfile pinning alone is no defense when the new transient *is* the malicious payload. If the new transitive is unexpected, pin the parent dep to the previous version, file a registry advisory, and rotate any secret a CI build with the lockfile had access to. Pair with NPM-006 (known-compromised package) and NPM-008 (cooldown gate) so the catch isn't reliant on a single signal.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## NPM-010: npm package has a known OSV advisory { #npm-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Network-dependent: needs ``--resolve-remote`` to query the OSV advisory database (``api.osv.dev``). Passes silently when the flag is off. Complements NPM-006 (curated offline registry) with the full OSV/GHSA long-tail.

<div class="pg-rule__rec" markdown>

**Recommended action**

Upgrade to a patched version or remove the affected package. Consult the advisory URL for remediation guidance.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-011: package.json files field includes secret-shaped paths { #npm-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-538</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Fires when ``package.json`` declares a ``files`` field (positive-list of paths npm includes in the published tarball) and at least one entry matches a secret-shaped pattern:

* ``.env`` / ``.env.*`` (env files, AWS keys / DB   passwords)
* ``.npmrc`` (npm auth tokens — `_authToken` lines)
* ``*.pem`` / ``*.key`` / ``*.crt`` / ``*.p12`` /   ``*.pfx`` (TLS / signing keys)
* ``id_rsa`` / ``id_dsa`` / ``id_ecdsa`` / ``id_ed25519``   (SSH private keys)
* ``credentials`` / ``credentials.json`` /   ``.aws/credentials`` (AWS-style credential blobs)
* ``.ssh/`` / ``.gnupg/`` (entire credential directories)

Wildcard-broad entries (``*``, ``**``, ``./``) are NOT currently flagged — they're too common to triage at this layer, and the right defense is ``npm pack --dry-run`` review. NPM-011 is the file-name detector; the broad-include surface is a separate rule. The ``.env.example`` template form is a documented known FP — name it ``env.example`` (no leading dot, no ``.env`` prefix) to dodge the heuristic.

**Known false-positive modes**

- Packages that intentionally ship template / example secret files (``dotenv-cli``, security-tooling packages) may legitimately include a ``.env.example``. Rename to ``env.example`` to dodge the regex, or suppress on this specific rule + module name with a one-line rationale.

**Seen in the wild**

- Long-running pattern of npm publishes leaking secrets via the ``files`` field: published packages containing ``.npmrc`` with auth tokens, AWS credentials in ``.env``, SSH private keys in dotfiles. Socket.dev and ReversingLabs research catalogs document hundreds of such incidents across the npm registry.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the secret-shaped entry from ``package.json`` ``files``. If the entry is intentional (e.g., a ``.env.example`` template that ships intentionally),  rename it to a clearly-not-a-secret form (``env.example``) before shipping. Then run ``npm pack --dry-run`` and inspect the printed contents before the next ``npm publish``; the dry-run output is the ground truth for what the registry will receive. Any tarball that includes ``.env``, ``.npmrc`` with an ``_authToken`` line, an SSH private key, or an AWS credentials file effectively publishes those credentials to every consumer of the package.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-012: .npmrc publish token lacks IP or readonly restriction { #npm-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Fires when a ``.npmrc`` contains an ``_authToken`` entry (the standard npm registry auth mechanism) without any accompanying restriction. The rule checks for two indicators of restriction:

1. An ``_authToken`` value that begins with ``npm_`` (granular access token, which carries server-side scope restrictions) vs. a legacy token (UUID-shaped or opaque hex, which has no scope boundary).
2. Absence of a ``_password`` or ``always-auth`` key for the same registry scope (which would indicate a different auth mechanism).

The rule cannot verify IP restrictions client-side (those are stored server-side on npmjs.com). It uses the token format as a proxy: granular tokens (``npm_`` prefix) support IP restrictions; legacy tokens do not.

Complements NPM-011 (secret-shaped paths in ``files`` field) and the DF-025 rule (registry token baked into a Docker image layer).

**Known false-positive modes**

- Some organizations use a private registry (Verdaccio, GitHub Packages, GitLab Packages) whose tokens don't follow the npmjs.com format. The rule fires on any non-``npm_`` token, which may be a legitimate private-registry token. Suppress with a rationale naming the registry.

**Seen in the wild**

- ESLint 2018: a maintainer's stolen npm token was used to publish ``eslint-scope@3.7.2`` and ``eslint-config-eslint@5.0.2`` containing credential-harvesting code. Granular tokens with publish-only scope on specific packages and IP restrictions would have blocked the attacker's publish from outside the maintainer's network.
- ua-parser-js 2021: a hijacked npm token published three backdoored versions (0.7.29, 0.8.0, 1.0.0) in a single session. A restricted token would have limited the damage to the specific package and IP range.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict every npm auth token to the minimum required scope. For tokens used only in CI publish workflows:

1. Generate an **automation** token (npmjs.com > Access Tokens > Generate New Token > Granular Access Token) with only the ``publish`` permission on the specific packages it needs to publish.
2. Enable **IP address CIDR allowlisting** on the token to restrict usage to known CI runner IP ranges.
3. For read-only CI installs (``npm ci``), use a **read-only** token that cannot publish at all.

A leaked unrestricted publish token enables full package hijack: an attacker publishes a backdoored version under your package name.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-013: package.json files field uses an overly broad pattern { #npm-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-538</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Fires when ``package.json`` declares a ``files`` field whose list includes any of these broad-include literals:

* ``"*"`` — npm interprets a lone ``*`` as 'every file in   the package root' (it does NOT mean 'every direct child'   the way a shell glob does)
* ``"**"`` / ``"**/*"`` / ``"*/**"`` — every file in   every subdirectory
* ``"."`` / ``"./"`` — explicit current-directory   include

When the broad entry is the only entry, the tarball is effectively the repo tree minus whatever ``.npmignore`` / ``.gitignore`` happens to block. Hand-maintained ignore files routinely miss new dotfiles (``.env.local``, ``.aws/``, ``.terraform/``), so the failure mode is silent credential leakage at the next ``npm publish``. The right fix is the explicit positive-list shape NPM-011 already scans; NPM-013 catches the case where there's no list to scan because everything is in.

Skipped: a ``files`` field that omits broad-include entries (the safe positive-list shape), a manifest with no ``files`` field (different surface — npm falls back to ``.npmignore`` / ``.gitignore`` semantics, which has its own pitfalls but is out of scope here), and any entry that narrows the include with a subdirectory prefix (``dist/**``, ``src/**/*.js``).

**Known false-positive modes**

- A package that is genuinely meant to ship every file in a tightly-controlled subtree (e.g. a single-file documentation package whose entire repo IS the publishable content) may legitimately use ``"*"`` paired with a comprehensive, audited ``.npmignore``. Suppress with a rationale that names the ``.npmignore`` file and the audit cadence; otherwise rewrite the field as a positive list.

**Seen in the wild**

- Socket.dev and ReversingLabs research catalogs document a long tail of npm publishes leaking ``.env`` / ``.aws/`` / ``.git/`` content via permissive ``files`` patterns paired with incomplete ``.npmignore`` files. The pattern is the single most common credential-leak vector at ``npm publish`` time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the broad-include entry (``*``, ``**``, ``./``, ``.``, ``**/*``, ``*/**``) with an explicit positive-list of the paths the package ships: typically ``dist/**`` plus ``README.md`` / ``LICENSE``. ``npm`` interprets a single ``*`` or ``**`` as 'include everything not blocked by an ignore file', which silently ships every dotfile, env file, build artifact, and CI script the repo carries unless a complete ``.npmignore`` exists. Run ``npm pack --dry-run`` after tightening the list, inspect the printed contents, and only then ``npm publish``. NPM-011 catches a small set of secret-shaped *names*; NPM-013 catches the much larger surface where the pattern itself is the leak.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## NPM-014: Direct dependency relies on a single npm publisher { #npm-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Network-dependent: needs ``--resolve-remote`` to read each direct dependency's publisher list from ``registry.npmjs.org`` (the same packument fetch NPM-008 uses, so it adds no extra requests). Flags a package whose top-level ``maintainers`` array (the npm accounts with publish access, not the repo's contributor list) has exactly one entry. Scoped to direct dependencies in ``dependencies`` / ``devDependencies`` / ``optionalDependencies`` / ``peerDependencies``; transitive packages are out of scope. LOW severity by design: a single publisher is extremely common across the registry and is a posture signal, not an active vulnerability, so it stays below the default ``--fail-on`` gate while still surfacing in a report. When ``--resolve-remote`` is off or the registry can't be reached, the rule passes silently.

**Known false-positive modes**

- A single-publisher package maintained by a trusted org behind 2FA and provenance is far lower risk than the bare count implies; the rule can't see the account's hardening from the manifest. Suppress per-resource for dependencies the team has vetted.

**Seen in the wild**

- axios maintainer-account takeover (March 30, 2026): a single publisher account compromise let an attacker push a malicious release to roughly 99M weekly downloads before detection.
- @ctrl/tinycolor account takeover (May 2024): single-publisher package; malicious versions stayed live for ~36 hours before coordinated removal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat a single-publisher dependency as a single point of compromise: if that one npm account is phished or its token leaks, every consumer pulls malicious code on the next install (the axios / chalk / lodash class of risk). For dependencies you pull in directly, prefer packages whose publish access is shared across maintainers or an org team, pin to a reviewed version, and pair with NPM-008 (cooldown) so a compromised release has a window to be caught before it reaches your lockfile.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## NPM-015: Direct dependency published without build provenance { #npm-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to read each direct dependency's latest-version `dist.attestations` from ``registry.npmjs.org`` (the same packument fetch NPM-008 and NPM-014 use, so it adds no extra requests). Flags a package whose latest version carries no build-provenance attestation. Scoped to direct dependencies; transitive packages are out of scope. LOW severity by design: provenance adoption across the registry is still low, so the absence is common and this is an informational posture signal that stays below the default ``--fail-on`` gate. When ``--resolve-remote`` is off or the registry can't be reached, the rule passes silently.

**Known false-positive modes**

- A package can be securely published without npm provenance (e.g. via a different attestation framework, or simply because it predates provenance support). The absence is a weaker signal than a present-but-invalid attestation would be. Suppress per-resource for dependencies whose supply chain the team has otherwise vetted.

**Seen in the wild**

- SLSA provenance / npm `--provenance` (GA 2023): publishing with provenance produces a signed link from the registry artifact to the exact source commit and CI run, the property an attacker who republishes a tampered tarball cannot forge.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build provenance ties a published package back to the source commit and CI build that produced it (SLSA / npm `--provenance`), the same guarantee this project ships on its own wheel. A dependency without it can't be cryptographically traced to its source, so a registry-side tamper or a look-alike republish is harder to detect. Prefer dependencies that publish with provenance where a maintained alternative exists, and ask upstreams you rely on to adopt it (it is a one-line change to a GitHub Actions publish job). This is a posture signal, not a defect in the dependency.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## NPM-016: Direct dependency has a low OpenSSF Scorecard { #npm-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Network-dependent: needs ``--resolve-remote``. The dependency's GitHub repo comes from its packument (the same fetch NPM-008 / NPM-014 / NPM-015 use), then each repo is looked up against the OpenSSF Scorecard API (``api.securityscorecards.dev``), which is the one extra network surface this rule adds beyond the registry. Fires when the aggregate score is below 5/10 OR the Dangerous-Workflow check failed (an exploitable workflow pattern in the dependency's own repo). Scoped to direct dependencies with a resolvable GitHub repo; packages with no GitHub repo or not indexed by Scorecard are skipped. LOW severity by design: it's an advisory upstream posture signal that stays below the default ``--fail-on`` gate. Passes silently when ``--resolve-remote`` is off or the Scorecard API can't be reached.

**Known false-positive modes**

- Scorecard penalizes practices that don't always apply (e.g. a single-maintainer library that doesn't use code review by policy) and its data can lag a repo's current state. A low score is a prompt to look, not proof of risk. Suppress per-resource for dependencies the team has vetted directly.

**Seen in the wild**

- OpenSSF Scorecard: an automated assessment of a repo's security practices (branch protection, pinned dependencies, dangerous workflows, code review, maintenance). Low-scoring upstreams are over-represented in supply-chain incident post-mortems.

<div class="pg-rule__rec" markdown>

**Recommended action**

A low OpenSSF Scorecard (or a failed Dangerous-Workflow check) on a direct dependency's own repository is a weak-link signal: the project lacks the maintenance and CI-hardening practices (branch protection, pinned actions, no `pull_request_target` script injection, code review) that make a compromise less likely and more detectable. Weigh a better-scored alternative where one exists, pin to a reviewed version, and for the ones you keep, watch them more closely (cooldown, provenance). This is an upstream-posture signal, not a defect you can fix in your own repo.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## NPM-017: Direct dependency provenance built from a non-release ref { #npm-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote``. Reads each direct dependency's latest-version attestation bundle from ``registry.npmjs.org/-/npm/v1/attestations`` and parses the SLSA provenance source ref (``predicate.buildDefinition.externalParameters.workflow.ref``). Flags a ref that is a branch other than ``refs/heads/main`` / ``refs/heads/master``; a tag (``refs/tags/...``) or a default branch passes. Skips (does not flag) a package whose latest version has no provenance (NPM-015's concern), whose attestation can't be fetched or parsed, or whose ref is an unrecognized shape. Scoped to direct dependencies. Default-branch detection assumes ``main`` / ``master``; a repo whose default branch is named otherwise can be flagged (see known_fp). LOW severity / MEDIUM confidence: a posture signal below the default ``--fail-on`` gate. Passes silently offline.

**Known false-positive modes**

- A project whose default branch is not ``main`` / ``master`` (``develop``, ``trunk``, a ``release/*`` branch) publishes legitimately from that branch; this rule treats only ``main`` / ``master`` as the trusted default, so other branch refs are flagged. Suppress per-resource when the upstream's release branch is known-good. A monorepo or non-standard SLSA layout that doesn't expose the ref at the parsed path is skipped, not flagged.

**Seen in the wild**

- Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, Untrusted Branch', 2026): 30+ packages shipped valid SLSA provenance recording a throwaway ``refs/heads/oidc-*`` branch. The provenance ref is the only install-side signal that would have distinguished them: https://labs.boostsecurity.io/articles/trusted-publishing-untrusted-branch-red-hat-npm/

<div class="pg-rule__rec" markdown>

**Recommended action**

A package's build provenance records the git ref the release was built from. A latest release built from a throwaway branch (``refs/heads/oidc-...``) rather than a tag or the default branch is the 'untrusted branch' signal: valid provenance, attacker ref. Confirm the upstream cuts releases only from a tag or a protected branch, and pin to a known-good version if its latest provenance ref looks unexpected. If the dependency's real default branch is not ``main`` / ``master`` (e.g. ``develop``), this is a false positive: suppress it per-resource.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## NPM-018: Direct dependency's latest release published by a new npm account { #npm-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Network-dependent: needs ``--resolve-remote`` to read each direct dependency's per-version publisher (the packument's ``_npmUser`` account that ran ``npm publish`` for each version, from the same fetch NPM-008 / NPM-014 use, so it adds no extra requests). Flags a package whose ``dist-tags.latest`` version was published by an account that published none of its prior versions. Requires at least three prior versions with a known publisher, so a brand-new package (one or two releases, where a "new publisher" is meaningless and NPM-008's cooldown already covers the fresh-carrier risk) is skipped. Scoped to direct dependencies in ``dependencies`` / ``devDependencies`` / ``optionalDependencies`` / ``peerDependencies``; transitive packages are out of scope. MEDIUM confidence: a legitimate new co-maintainer's first publish trips it too, so the finding is a review prompt rather than proof of compromise. When ``--resolve-remote`` is off, the registry can't be reached, or the packument doesn't expose ``_npmUser``, the rule passes silently.

**Known false-positive modes**

- A legitimate maintainer hand-off or a newly added co-maintainer publishing their first release flags identically to a takeover (the per-version publisher is the only static signal; intent isn't visible). When the change is verified and expected, suppress per-resource for that dependency.

**Seen in the wild**

- axios maintainer-account takeover (March 30, 2026): a compromised publisher account pushed a malicious release to ~99M weekly downloads, the new-publisher-on-an-established-package shape this rule surfaces.
- @ctrl/tinycolor account takeover (May 2024): a hijacked account published malicious versions that stayed live for ~36 hours.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat a publisher change as the live account-takeover signal it is: the latest release of this dependency was published by an npm account that published none of its earlier versions. That is exactly the shape of a stolen-credential or freshly-added-account compromise (the axios / @ctrl/tinycolor / chalk class), where an attacker pushes one malicious release that every consumer pulls on the next install. Before upgrading into the new release: confirm the maintainer change is legitimate (a documented hand-off, a new co-maintainer the project announced), pin to the last release from the known publisher until you have, and pair with NPM-008 (cooldown) so a hijacked release has a window to be caught before it reaches your lockfile. NPM-014 (single publisher) is the standing blast-radius; this is the moment that blast radius fires.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-019: package.json overrides / resolutions rewrites a dependency to a non-registry source { #npm-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when an ``overrides`` / ``resolutions`` / ``pnpm.overrides`` entry (walked recursively, so nested npm overrides are covered) resolves a package to a non-registry source: a git spec (``git+...`` / ``github:`` / ``gitlab:`` / ``bitbucket:``), an ``http(s)://`` tarball, a ``file:`` / ``link:`` / ``portal:`` local path, or an ``npm:<other>`` alias that redirects the name to a different package. A plain version / range override (the common, legitimate use, pinning a transitive to a patched version) passes. Distinct from NPM-001 / NPM-005, which only walk the ``*dependencies`` blocks via ``iter_manifest_dependencies`` and never read the override map.

<div class="pg-rule__rec" markdown>

**Recommended action**

Keep ``overrides`` (npm), ``resolutions`` (Yarn), and ``pnpm.overrides`` to exact registry versions. A git / URL / ``file:`` / ``npm:``-alias target in an override force-replaces the resolved source of a package anywhere in the tree, including deep transitives, ahead of the lockfile and without touching any ``dependencies`` line a reviewer reads. If you must override to a fork, pin it to a 40-character commit SHA and vendor it into a registry you control; if you must alias a name (``npm:``), confirm the target package is one you trust, since the alias silently redirects a trusted name to a different package.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NPM-020: .npmrc repoints the default or a scoped registry to a non-canonical host { #npm-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when a ``.npmrc`` sets ``registry=`` or ``@scope:registry=`` to a host other than ``registry.npmjs.org`` (``registry.yarnpkg.com`` is also accepted as canonical), or to a plaintext ``http://`` registry of any host. The default-registry repoint is the substitutive dependency-confusion vector (the npm config-layer analog of PYPI-016 / COMPOSER-012 / CARGO-012); a scoped repoint is how an internal ``@company`` scope gets hijacked to a public / attacker host. NPM-007 reads the same ``.npmrc`` but only the ``ignore-scripts`` key; NPM-003 treats any HTTPS registry host as safe, so neither sees this. Leans on suppression for legitimate internal mirrors.

**Known false-positive modes**

- Many organizations set ``registry=`` to an internal proxy (Artifactory / Verdaccio / GitHub Packages) that mirrors npm, and route a private ``@scope`` to it. That is a legitimate, recommended setup; the rule can't tell a vetted internal mirror from an attacker host. Suppress with ``--ignore-file`` and a one-line note naming the registry once you've confirmed it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Point ``registry=`` (and any ``@scope:registry=``) at canonical npm (``https://registry.npmjs.org/``) or a vetted internal mirror that proxies it. ``registry=`` replaces the default index outright, so every package, direct and transitive, is fetched from that host; a ``@scope:registry=`` line silently routes one scope elsewhere. An attacker who lands a committed ``.npmrc`` repoint serves backdoored tarballs under the real names. If the host is a legitimate internal registry, suppress with a one-line rationale that names it.

</div>

</div>

---

## Adding a new npm check

1. Create a new module at
   `pipeline_check/core/checks/npm/rules/npmNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(manifest: NpmManifest) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``NpmManifest`` or ``NpmLock`` (chosen by annotation).
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/npm/NPM-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py npm
   ```
