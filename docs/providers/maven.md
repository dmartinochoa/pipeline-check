# maven provider

Parses Maven `pom.xml` project descriptors and per-user / per-CI
`settings.xml` files on disk. Text-only static analysis, no
`mvn install`, no Maven Central API access, no resolver run. Rule
modules see a parsed `PomFile` (dependencies, repositories,
properties, mirrors) and flag the patterns that produced the
Log4Shell (Dec 2021), Spring4Shell (March 2022), and Text4Shell (Oct
2022) historical incidents.

## Producer workflow

```bash
# --maven-path is auto-detected when pom.xml exists at cwd.
pipeline_check --pipeline maven

# …or pass it explicitly.
pipeline_check --pipeline maven --maven-path pom.xml

# Recursively scan a multi-module reactor: every pom.xml under the
# path (excluding ``target/`` and ``.m2/``) is picked up.
pipeline_check --pipeline maven --maven-path .
```

## Scope

* `pom.xml` (project descriptor, both top-level and submodule)
* `settings.xml` (per-user / per-CI Maven config, scanned for
  `<mirrors>` posture)
* `<dependencyManagement>` entries are surfaced separately from real
  dependencies so version-management blocks don't trigger consumption-
  side rules.

`gradle.lockfile`, `build.gradle`, and `build.gradle.kts` are out of
scope for the initial pack; a separate `gradle` provider is queued
for a follow-up. The Maven half covers Maven Central and any
Maven-compatible registry (Nexus, Artifactory, GitHub Packages) the
project resolves through `pom.xml`.

## Property resolution

Single-level `${prop}` substitution against the POM's `<properties>`
block is performed before each rule evaluates a version literal, so a
property pointing at a floating range or a known-compromised version
still trips the relevant rule. Nested substitution is intentionally
left unresolved; deeply-recursive property graphs are rare in
real-world POMs and out of scope for static analysis.

## What it covers

9 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [MVN-001](#mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-002](#mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-003](#mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-004](#mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-005](#mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-006](#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [MVN-007](#mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-008](#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-009](#mvn-009) | Maven artifact has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## MVN-001: pom.xml dependency uses a floating version range { #mvn-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any ``<version>`` value that matches the Maven range grammar: bracket-or-paren-delimited intervals (``[1.0,2.0)``, ``(,3.0]``), open ranges (``[1.0,)``), or the legacy floating tokens ``LATEST`` / ``RELEASE``. Property references (``${spring.version}``) are resolved against the POM's ``<properties>`` block before the check runs, so a property pointing at a range still fires.

Managed entries in ``<dependencyManagement>`` are NOT evaluated by this rule (that's MVN-004's surface) because the version-management section's purpose is to centralize version literals, not consume them at install time.

**Known false-positive modes**

- Multi-module reactor builds sometimes legitimately use ``${project.version}`` (the reactor's own version) which resolves to a plain string from the parent POM. The rule honors property substitution so this passes; if it does fire on a deliberate range (e.g. a build-time tool pulled via a range you control), suppress with a one-line rationale.

**Seen in the wild**

- Codecov Bash Uploader compromise (April 2021): downstream builds pulling Codecov via mutable references shipped the tampered uploader for two months. The Maven-side analog is any range-pinned ``codecov`` / scanner / agent jar; same exposure window. https://about.codecov.io/security-update/

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace Maven version ranges (``[1.0,2.0)``, ``[1.0,)``, ``LATEST``, ``RELEASE``) with an exact version pin (``<version>1.2.3</version>``). The range form lets Maven pick any later release that fits, so a compromised patch version reaches the build without a code change. Pair the exact-pin manifest with a verified-by-checksum or verified-by-signature repository policy (MVN-005) so a tampered jar at the same version literal still fails.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-002: pom.xml depends on a mutable SNAPSHOT version { #mvn-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any non-managed ``<version>`` ending in ``-SNAPSHOT`` (case-insensitive). Property references are resolved against the POM's ``<properties>`` first, so a property whose value ends in ``-SNAPSHOT`` still trips the rule. ``<dependencyManagement>`` entries are exempt; centralized version literals are MVN-004's surface.

**Known false-positive modes**

- Multi-module reactor builds where every sibling references ``${project.version}-SNAPSHOT`` during local development. Suppress in your local profile or scope the scan to the release POM; gating release builds on SNAPSHOT-free deps is exactly what this rule is for.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``-SNAPSHOT`` versions with a released, immutable version (``1.2.3``, not ``1.2.3-SNAPSHOT``). Maven treats SNAPSHOT artifacts as mutable: the repository can re-deploy the same coordinate, and ``mvn install`` will pull whatever is current at resolution time. Snapshot dependencies belong to the development inner loop; gate them out of release builds and CI build pipelines.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-003: pom.xml declares a plaintext-HTTP Maven repository { #mvn-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on any ``<repository>``, ``<pluginRepository>``, or ``<distributionManagement>`` URL using the ``http://`` scheme. ``file://`` and ``https://`` are exempt. The rule evaluates both project POMs and per-user / per-CI ``settings.xml`` mirror entries via the orchestrator.

**Known false-positive modes**

- Internal Maven repositories on a fully-isolated build network sometimes legitimately serve over HTTP. If you can actually attest that the network path is end-to-end untamperable (a single-tenant air-gapped subnet), suppress with a rationale naming that boundary.

**Seen in the wild**

- Maven Central enforced HTTPS-only for the central repository in January 2020; the legacy ``http://repo1.maven.org`` endpoint was retired specifically because of MITM-tampering attacks against downstream consumers. https://blog.sonatype.com/central-repository-moving-to-https

<div class="pg-rule__rec" markdown>

**Recommended action**

Change every ``<repository><url>`` to ``https://`` and delete any ``<repository>`` whose host doesn't expose TLS. Plaintext-HTTP repositories let a network attacker swap downloaded jars in flight (the canonical Maven supply-chain MITM attack); ``https://`` plus the repository's published checksums (MVN-005) is the minimum baseline.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-004: pom.xml dependency omits an explicit ``<version>`` { #mvn-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any non-managed ``<dependency>`` whose ``<version>`` element is absent or empty. Managed entries in ``<dependencyManagement>`` are the *source* of the version and intentionally out of scope for the entire Maven rule pack (MVN-001 / MVN-002 / MVN-004 all iterate ``iter_real_dependencies(...)``, which skips managed entries) — a BOM-style version-management block is its own surface and is audited via the inherited POM.

**Known false-positive modes**

- Spring Boot starters and other BOM-managed dependencies intentionally omit ``<version>`` so the imported BOM decides. The rule still fires because the BOM is not visible at static-analysis time; suppress with a rationale naming the BOM POM, or import the BOM explicitly into this project's ``<dependencyManagement>``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Every ``<dependency>`` must carry a ``<version>``, either inline or via a ``<dependencyManagement>`` block in this POM or a parent. Implicit-version dependencies inherit whatever Maven resolves at build time (often the highest available release), so a maintainer push to a higher version reaches the build unobserved. If the version is genuinely managed by a parent POM, declare it in this POM's ``<dependencyManagement>`` so the resolved version is at least pinned at the project level.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-005: Maven repository accepts artifacts without strict checksum gating { #mvn-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Fires when any ``<repository>`` / ``<pluginRepository>`` declares ``<checksumPolicy>warn</checksumPolicy>`` or ``<checksumPolicy>ignore</checksumPolicy>`` (explicitly weakened from the default), or when the policy is absent AND the URL is not Maven Central (Central enforces checksums server-side, so the policy is moot for that single repo). Internal mirrors and third-party repositories are the canonical place this rule fires.

**Known false-positive modes**

- Internal artifact repositories with server-side checksum verification (a Nexus / Artifactory deployment configured to reject mismatched uploads) functionally meet the control even with ``warn`` at the client. The rule cannot see the server-side policy; suppress with a rationale naming the platform / version that enforces it.

<div class="pg-rule__rec" markdown>

**Recommended action**

On every ``<repository>``, set ``<checksumPolicy>fail</checksumPolicy>`` under both ``<releases>`` and ``<snapshots>``. Maven's default policy is ``warn``: a checksum mismatch logs a line and the build continues with the tampered artifact. ``fail`` halts on any mismatch, which is the only setting that actually gates the build on checksum integrity. For Maven 3.9.x and newer, prefer the global ``-C`` / ``-c`` invocation flag in CI plus per-repo ``fail`` so a missing checksumPolicy doesn't downgrade to warn at runtime.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## MVN-006: pom.xml pins a known-compromised Maven Central artifact version { #mvn-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Walks every non-managed dependency against the curated compromised-package registry in ``pipeline_check.core.checks.maven._compromised_packages``. Group/artifact matching is case-insensitive; version matching is exact (with optional regex fallback for advisories that span a range). Property references are resolved against the POM's ``<properties>`` block so ``${log4j.version}`` is checked against its resolved value. ``<dependencyManagement>`` entries are skipped to avoid double-counting when the same coordinate is both managed and consumed.

**Known false-positive modes**

- The registry covers only public, advisory-confirmed compromises and a small set of canonical CVE-mapped vulnerable versions (Log4Shell, Spring4Shell, Text4Shell). For broader CVE coverage, run a dependency-vulnerability scanner (OWASP Dependency-Check, Snyk, Trivy) alongside pipeline-check; MVN-006 is the curated supply-chain anchor.

**Seen in the wild**

- Log4Shell, CVE-2021-44228 (December 2021): the canonical Maven-side ecosystem-wide RCE. Mass exploitation began within hours of public disclosure. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Spring4Shell, CVE-2022-22965 (March 2022): RCE via the spring-beans data-binding path on JDK 9+ WAR deployments. https://nvd.nist.gov/vuln/detail/CVE-2022-22965

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the affected dependency to a post-incident clean version announced in the citing advisory. For Log4Shell and Spring4Shell class CVEs, rotate any secret reachable to production processes during the exposure window (most Maven-side advisories enable unauthenticated RCE on the deployed app, so any in-process credential should be considered exposed). Pair with MVN-005 (strict checksum policy) so future bytes published at the same coordinate are rejected, and with a vuln-scanning step (Snyk, Dependency-Check) for breadth beyond the curated registry.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-007: settings.xml mirror routes external traffic through one repo { #mvn-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any ``<mirror>`` in a ``settings.xml`` whose ``<mirrorOf>`` value is ``*`` or ``external:*`` (the two patterns that capture arbitrary external traffic). Repository-specific patterns (``central``, ``!internal-only,*``) and explicit allowlists are exempt. Project POMs that don't carry a ``<mirrors>`` block silently pass.

**Known false-positive modes**

- Single-team artifact-proxy patterns (one Nexus / Artifactory acting as the universal upstream front) legitimately use ``<mirrorOf>*</mirrorOf>`` and rely on the proxy's own access controls. If the proxy is a controlled artifact-allowlist target rather than a passthrough, suppress with a rationale naming the proxy endpoint and the allowlist that gates it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``<mirrorOf>*</mirrorOf>`` and ``<mirrorOf>external:*</mirrorOf>`` with a narrowly-scoped list naming the upstream repositories you actually want to redirect (``central``, ``central,jcenter``). A wildcard mirror routes every dependency, including ones declared by transitive POMs the build hasn't approved, through the mirror operator: a single compromise of that mirror compromises every artifact the build resolves. Pin the mirror URL to ``https://`` and audit the mirror operator's publishing controls.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-008: Direct dependency was published within the cooldown window { #mvn-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to populate the per-coordinate publish timestamps from the Maven Central search API (``https://search.maven.org/solrsearch/select``). Walks every non-managed ``<dependency>`` with an explicit ``<version>``; flags ones whose ingest timestamp on Central falls inside the cooldown window (default 7 days). ``<dependencyManagement>`` entries are skipped (those are version-management declarations, not real consumption). ``${prop}`` substitution against the POM's ``<properties>`` block is resolved before the lookup so ``${log4j.version}`` is checked against its resolved value. ``-SNAPSHOT`` and Maven version-range literals (``[1.0,2.0)``, ``LATEST``, ``RELEASE``) are out of scope — the cooldown applies to a specific released coordinate. When ``--resolve-remote`` is off or Central can't be reached, the rule passes silently so the absence of the network path doesn't trip CI.

**Known false-positive modes**

- Internally-published artifacts hosted on a private Sonatype Nexus / JFrog Artifactory instance won't appear in Central's search API and are silently skipped. The cooldown gate is a Central-only signal; vendor- or org- internal release trains are out of scope and shouldn't be suppressed (they simply don't fire).
- Same-day patch upgrades from a maintainer the team directly trusts (e.g. an internal fork republished to Central under a corporate group ID) are flagged. Suppress per-resource via ``--ignore-file`` — the cooldown is a default-safe gate, not a hard rule.

**Seen in the wild**

- Log4Shell, CVE-2021-44228 (December 2021): public disclosure on 2021-12-09 triggered Apache's emergency 2.15.0 release the same day; mass exploitation began within hours. Consumers who held even a 1-day cooldown on the affected versions would have caught the upstream advisory before bumping. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Sonatype Lift abuse / typosquat campaigns (2022-2024): periodic surfacing of typosquat coordinates (``org.apaache.*``) pushed to Central, typically yanked within 48 hours of report. A cooldown of any meaningful length would skip them.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either skip the just-published version (pin to the last release older than the cooldown window) or wait until the cooldown has elapsed before bumping the POM. Publisher- account compromises on Maven Central are rarer than on npm / PyPI, but the takedown window is the same shape: Sonatype yanks malicious artifacts within hours-to-days once an advisory lands; holding back N days converts a publisher-compromise window into a vulnerability- disclosure window where either the maintainer rotates the malicious release off Central or the security community files a CVE that MVN-006 can match against.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## MVN-009: Maven artifact has a known OSV advisory { #mvn-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Network-dependent: needs ``--resolve-remote`` to query the OSV advisory database (``api.osv.dev``). Passes silently when the flag is off. Complements MVN-006 (curated offline registry) with the full OSV/GHSA long-tail.

<div class="pg-rule__rec" markdown>

**Recommended action**

Upgrade to a patched version or remove the affected artifact. Consult the advisory URL for remediation guidance.

</div>

</div>

---

## Adding a new maven check

1. Create a new module at
   `pipeline_check/core/checks/maven/rules/mvnNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pom: PomFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``PomFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/maven/MVN-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py maven
   ```
