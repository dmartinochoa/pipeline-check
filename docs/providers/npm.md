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

7 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [NPM-001](#npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NPM-002](#npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-003](#npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-004](#npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-005](#npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NPM-006](#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [NPM-007](#npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## NPM-001: package.json dependency uses a floating version range { #npm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on every entry in ``dependencies`` / ``devDependencies`` / ``optionalDependencies`` / ``peerDependencies`` whose value starts with ``^``, ``~``, ``*``, ``>``, ``<``, ``||``, or is the dist-tag ``latest`` / ``next`` / ``beta`` / ``alpha`` / ``canary`` / ``dev``. ``workspace:*`` (Yarn / pnpm workspace protocol), ``file:`` / ``link:`` (local checkouts), ``git+`` / ``http(s)://`` (URL deps), and ``npm:`` (alias) are not version ranges and are routed to other rules. Complements NPM-002, which catches lockfile entries missing integrity hashes; NPM-001 is the manifest-side hygiene.

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
