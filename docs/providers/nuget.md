# NuGet provider

Parses .NET NuGet project files and configuration on disk. Text-only
static analysis, no `dotnet restore`, no NuGet API access (offline
rules). Behind `--resolve-remote`, NUGET-008 queries
`api.nuget.org` for publish-time metadata and NUGET-009 queries the
OSV advisory database.

## Producer workflow

```bash
# --nuget-path is auto-detected when Directory.Packages.props exists.
pipeline_check --pipeline nuget
pipeline_check --pipeline nuget --nuget-path ./src/
```

## Supported file formats

| File | Parse shape |
|------|-------------|
| `*.csproj` | `<PackageReference Include="..." Version="..." />` entries |
| `Directory.Packages.props` | Central package management (`<PackageVersion>` entries) |
| `packages.config` | Legacy format (`<package id="..." version="..." />`) |
| `NuGet.config` | Package sources and `packageSourceMapping` sections |
| `packages.lock.json` | SDK-generated lock file (resolved versions) |

`bin/`, `obj/`, and `.nuget/` directories are skipped.

## What it covers

9 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [NUGET-001](#nuget-001) | Floating NuGet version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NUGET-002](#nuget-002) | Wildcard prerelease NuGet version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NUGET-003](#nuget-003) | PackageReference missing explicit version | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NUGET-004](#nuget-004) | HTTP-only NuGet package source | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-005](#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [NUGET-006](#nuget-006) | No NuGet lock file for reproducible restores | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NUGET-007](#nuget-007) | Multiple NuGet sources without packageSourceMapping | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-008](#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-009](#nuget-009) | NuGet package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-001: Floating NuGet version range { #nuget-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace NuGet floating version ranges (``[1.0,)``, ``(,2.0)``, ``[1.0,2.0)``, ``*``) with an exact version pin (``<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />``). Floating ranges let NuGet resolve any later version that fits the interval, so a compromised patch release reaches the build on the next restore without a project file change. Pair the pinned reference with a committed ``packages.lock.json`` (NUGET-006) for reproducible restores.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-002: Wildcard prerelease NuGet version { #nuget-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace wildcard prerelease specifiers (``*-*``, ``1.0.0-*``) with an exact version pin including the prerelease tag (``1.0.0-beta.1``). The ``-*`` suffix tells NuGet to resolve the latest prerelease matching the prefix, so any newly published prerelease (including a malicious one) is pulled on the next restore. Prerelease packages are often less reviewed than stable releases, increasing the attack surface.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-003: PackageReference missing explicit version { #nuget-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an explicit ``Version`` attribute to every ``<PackageReference>`` element (``<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />``). Without one, NuGet resolves the latest available version at restore time, so a compromised release reaches the build unobserved. If your solution uses Central Package Management (``Directory.Packages.props``), this rule is skipped because versions are governed centrally.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-004: HTTP-only NuGet package source { #nuget-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Change every ``<add key="..." value="http://..." />`` package source in NuGet.config to ``https://``. Plaintext-HTTP sources let a network attacker swap downloaded packages in flight (the canonical supply-chain MITM). If your internal feed has a self-signed certificate, install the CA into the build agent's trust store instead of falling back to HTTP.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## NUGET-005: Known-compromised NuGet package version { #nuget-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate every secret reachable to any process that ran ``dotnet restore`` against this project while the compromised version was installed. Bump the affected PackageReference to a post-incident clean version announced in the citing advisory, regenerate the lock file, and audit CI build logs for the exfiltration shape the advisory documents. Pair with NUGET-006 (lock file for reproducible restores) so a re-publish at the same version literal is caught by the content hash mismatch.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-006: No NuGet lock file for reproducible restores { #nuget-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable NuGet lock files by setting ``<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`` in the csproj (or ``Directory.Build.props`` for solution-wide coverage) and commit the generated ``packages.lock.json``. In CI, restore with ``dotnet restore --locked-mode`` so the build fails if the lock file disagrees with the project file. Without a lock file, ``dotnet restore`` silently upgrades transitive dependencies to whatever the feed currently serves.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-007: Multiple NuGet sources without packageSourceMapping { #nuget-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``<packageSourceMapping>`` section to NuGet.config that maps each package pattern to its intended source. Without source mapping, NuGet queries every configured source for every package and installs the highest version found across all of them, the exact shape exploited by dependency confusion attacks. Source mapping pins each package namespace to one feed so a malicious publication on a secondary feed is never considered.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-008: NuGet package published within the cooldown window { #nuget-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to populate publish timestamps from ``api.nuget.org``. Passes silently when the flag is off.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin to a version published before the cooldown window, or wait until the cooldown has elapsed. Most publisher-account compromises are detected within hours-to-days of publication.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## NUGET-009: NuGet package has a known OSV advisory { #nuget-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Network-dependent: needs ``--resolve-remote`` to query the OSV advisory database. Passes silently when the flag is off.

<div class="pg-rule__rec" markdown>

**Recommended action**

Upgrade to a patched version or remove the affected package. Consult the advisory URL for remediation guidance.

</div>

</div>

---

## Adding a new NuGet check

1. Create a new module at
   `pipeline_check/core/checks/nuget/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/nuget/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py nuget
   ```
