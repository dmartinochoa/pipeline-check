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

18 checks · 0 have an autofix patch (``--fix``).

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
| [NUGET-010](#nuget-010) | NuGet.config stores a feed credential in plaintext | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-011](#nuget-011) | packageSourceMapping pattern is a global wildcard | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-012](#nuget-012) | NuGet.config does not enforce signatureValidationMode = require | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-013](#nuget-013) | dotnet-tools.json entry lacks a version pin | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-014](#nuget-014) | NuGet.config source URL embeds plaintext credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-015](#nuget-015) | PackageReference VersionOverride defeats Central Package Management | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [NUGET-016](#nuget-016) | Private feed without <clear/> inherits the public gallery | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-018](#nuget-018) | Project runs build-time MSBuild logic at restore/build | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [NUGET-019](#nuget-019) | signatureValidationMode=require with no trusted signers | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-001: Floating NuGet version range { #nuget-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when a ``<PackageReference>`` Version attribute contains a NuGet range interval (``[1.0,2.0)``, ``(,2.0]``, etc.) or a bare ``*`` wildcard.

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

Fires when Version ends with ``-*`` or equals ``*-*``.

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

Fires when a ``<PackageReference>`` omits the Version attribute and the project is not centrally managed.

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

Fires when a ``<packageSources>`` entry in NuGet.config uses an ``http://`` URL.

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

Fires when a PackageReference pins to a version in the curated compromised-package registry.

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

Fires when a csproj project exists but no ``packages.lock.json`` was found.

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

Fires when NuGet.config has more than one package source and no ``packageSourceMapping`` section.

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

<div class="pg-rule pg-rule--high" markdown>

## NUGET-010: NuGet.config stores a feed credential in plaintext { #nuget-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-256</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Fires when a ``NuGet.config`` carries a ``<packageSourceCredentials>`` block whose per-source entry includes an ``<add key="ClearTextPassword" value="..." />`` element. The key match is case-insensitive (NuGet itself treats it that way). The rule does NOT read or echo the literal credential value — findings only name the source the credential is bound to so secrets aren't laundered into reports.

An encrypted ``<add key="Password" .../>`` entry is the DPAPI-encrypted form NuGet writes when you run ``nuget sources update -username ... -password ...`` on Windows. That key is NOT flagged here — its value is unreadable without the original user's key material. The rule's surface is specifically the ``ClearTextPassword`` key, which stores the literal credential in committable plaintext.

Note: a session-scoped ``NuGet.config`` written by the build script (never committed) can legitimately use ``ClearTextPassword`` to pass a token from an environment variable to ``dotnet restore``. If you scan a tree that contains such a file, suppress on the specific path and rule pair with a rationale; the rule has no way to tell a build-script-generated config apart from a hand-committed one.

**Known false-positive modes**

- Build-script-generated ``NuGet.config`` files written into a workspace at job time legitimately use ``ClearTextPassword`` because the file isn't committed. The rule can't distinguish those from a checked-in config; suppress with a rationale on the specific path.

**Seen in the wild**

- NuGet credentials in repo history have driven multiple incidents where a private feed token leaked via a ``NuGet.config`` committed to a public mirror or to an open-source release branch; once in git history, the credential is recoverable forever (even after deletion).

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``<add key="ClearTextPassword" .../>`` element from ``<packageSourceCredentials>``. If the feed needs auth for the build, use an environment variable reference (``%FEED_PASSWORD%`` on the value of an encrypted ``<add key="Password" ...>`` entry, populated at job time) or NuGet's encrypted-credential workflow (``nuget sources update -username ... -password ...``, which writes the DPAPI-encrypted ``Password`` key on Windows). On Linux / macOS where DPAPI isn't available, inject the secret at build time via the ``NUGET_CREDENTIALS`` environment variable or a ``-StoredPasswordInClearText`` session-scoped source declared in the build script, never in a checked-in ``NuGet.config``. After removal, rotate the credential — anyone with read access to the repo history has it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-011: packageSourceMapping pattern is a global wildcard { #nuget-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks ``NuGet.config`` ``<packageSourceMapping>`` entries and fires when any ``<package pattern="...">`` is a global wildcard. The recognized wildcard shapes:

* ``*`` — match everything
* ``**`` — equivalent to ``*`` in NuGet pattern syntax

Prefix wildcards (``Microsoft.*``, ``Corp.*``) are the *intended* use of ``<package pattern>`` — they map a package-name namespace to a specific source and don't trip this rule. The signal is specifically the unbounded global wildcard that turns the mapping into a no-op.

Distinct from NUGET-007 (no packageSourceMapping at all): this rule catches the case where mapping exists but is ineffective.

**Known false-positive modes**

- Some workspaces use a global ``*`` deliberately to route all packages through a single internal mirror that does its own dependency-confusion screening. The rule still fires because the mapping itself doesn't carry the screening guarantee. Suppress per config with a one-line rationale naming the mirror's policy.

**Seen in the wild**

- Pattern in .NET monorepos that adopt ``<packageSourceMapping>`` as a quick fix during a dependency-confusion incident response: the initial mapping uses ``*`` to avoid breaking existing restore paths, the cleanup pass that replaces it with explicit prefixes never lands. The mapping looks present at audit time but provides no real gating.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the ``*`` (or other broadly-matching wildcard) pattern with explicit package-name prefixes so each package is routed to the source the team has chosen for it. The point of ``<packageSourceMapping>`` is to gate every package against a single trusted source per namespace; a ``*`` catch-all defeats the gate and lets any package — including dependency-confusion typo-squats — flow through whichever source happens to win the race.

Example for an internal package convention:

    <packageSourceMapping>
      <packageSource key="nuget.org">
        <package pattern="Newtonsoft.Json" />
        <package pattern="Microsoft.*" />
      </packageSource>
      <packageSource key="corp-nexus">
        <package pattern="Corp.*" />
        <package pattern="Internal.*" />
      </packageSource>
    </packageSourceMapping>

Every package now maps to exactly one source via longest-prefix match. A typo-squat that doesn't match a known prefix is rejected at restore time.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-012: NuGet.config does not enforce signatureValidationMode = require { #nuget-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Reads each ``NuGet.config``'s ``<config>`` block for ``signatureValidationMode``. Fires when the key is absent (default is ``accept``) or set to anything other than ``require`` (case-insensitive). The rule does NOT verify that ``<trustedSigners>`` is populated when ``require`` is set; a follow-up rule can audit the signers' completeness.

Distinct from NUGET-010 (cleartext credentials) and NUGET-007 (package-source mapping): those audit credential and routing posture; this rule audits the integrity-verification posture at install time.

**Known false-positive modes**

- Internal-only NuGet feeds where every package is trusted by the workspace's perimeter posture (a single internal Nexus that the operator controls end-to-end) may legitimately accept unsigned packages. Suppress per config with a one-line rationale; production-facing workspaces should require signatures.

**Seen in the wild**

- .NET supply-chain compromise pattern: a popular package is published with a slight name variant via a compromised maintainer account. The original package is signed; the variant isn't. Consumers with ``signatureValidationMode=accept`` install both without distinction; ``require`` mode rejects the unsigned variant at restore time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``signatureValidationMode`` to ``require`` in ``NuGet.config`` and add at least one ``<trustedSigners>`` entry naming the authors / repositories whose packages the project will accept:

    <config>
      <add key="signatureValidationMode" value="require" />
    </config>
    <trustedSigners>
      <author name="microsoft">
        <certificate fingerprint="<sha256-of-cert>"
                     hashAlgorithm="SHA256"
                     allowUntrustedRoot="false" />
      </author>
      <repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json">
        <certificate fingerprint="<sha256-of-cert>"
                     hashAlgorithm="SHA256"
                     allowUntrustedRoot="false" />
      </repository>
    </trustedSigners>

With ``require``, NuGet rejects any package whose signature doesn't validate against a trusted-signers entry — closing the substitution surface that transport-only verification leaves open. The default (``accept``) verifies signatures when present but happily accepts unsigned packages, which means a compromised mirror serving unsigned drop-ins isn't rejected at restore time.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-013: dotnet-tools.json entry lacks a version pin { #nuget-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads every ``.config/dotnet-tools.json`` (and root-level ``dotnet-tools.json``) under the scan path and walks the ``tools`` object. Fires for any entry whose value is either:

* a dict without a ``version`` key, or
* a dict with ``version`` set to an empty string

Wildcard / range version specs (``"*"``, ``"8.0.*"``) are also flagged because they resolve at restore time to the registry's current content.

**Known false-positive modes**

- Some templating projects emit a ``dotnet-tools.json`` with no version field so the user picks a tool version at first use. The rule still fires; suppress per file with a one-line rationale, or — better — fill in the version once the project's tool requirements stabilize.

**Seen in the wild**

- Pattern of .NET tool-manifest compromise: a popular tool ships a poisoned patch release; every consumer running ``dotnet tool restore`` with a manifest that doesn't pin the version picks up the bad binary automatically. The binary's install hook runs in the developer's shell with their local credentials.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an explicit ``version`` field to every tool entry in ``.config/dotnet-tools.json``:

    {
      "version": 1,
      "isRoot": true,
      "tools": {
        "dotnet-ef": {
          "version": "8.0.10",
          "commands": ["dotnet-ef"]
        }
      }
    }

Tools listed in the manifest are restored by ``dotnet tool restore``, which executes the tool's binary on first invocation. Without a version pin, the command resolves to whatever ``nuget.org`` is currently publishing under the tool's name — including a poisoned patch release that runs in the developer's shell or the CI runner with whatever credentials those environments carry.

Mirrors NUGET-001 (PackageReference floating version) but for the tool-manifest surface: tools execute on every developer's machine, while packages typically execute only when the application that consumes them runs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-014: NuGet.config source URL embeds plaintext credentials { #nuget-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads each ``NuGet.config`` ``<packageSources>`` entry and fires when the URL embeds a ``user:pass@`` authority component. Empty-password forms (``https://user:@host``) and ``${env:VAR}`` placeholders are skipped — the former is operator-flagged 'no credential intended' and the latter resolves at restore time from the environment.

Distinct from NUGET-010 (cleartext password in ``<packageSourceCredentials>``) and NUGET-004 (HTTP scheme): those audit credential and transport posture in their canonical NuGet locations. This rule catches the URL-embedded shape, which is the most common developer mistake when adding a private feed manually.

**Known false-positive modes**

- Templated NuGet.config files that materialize a placeholder credential form (``https://__USER__:__TOKEN__@host``) and substitute the real value at build time trip this rule by shape. Suppress per config when the placeholder marker is stable; the rule's placeholder skip-list only recognizes ``${env:VAR}`` and ``${VAR}``.

**Seen in the wild**

- Pattern across .NET enterprise repositories: a contributor pastes a Nexus feed URL with embedded credentials into NuGet.config during a quick test, intends to replace it before commit, the replacement never happens. The credential persists in git history after the fact even if the next commit cleans the file.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential out of the URL and into the ``<packageSourceCredentials>`` section using the encrypted-password form. The recommended flow:

1. Run ``dotnet nuget add source <url> --username <user> --password <pass> --store-password-in-clear-text=false`` on the runner. NuGet stores the credential using the platform's secure-storage API (DPAPI on Windows, keychain on macOS, libsecret on Linux) and writes an encrypted form into the user-level NuGet.config.
2. For CI, inject the credential at restore time from the secret manager: ``dotnet nuget add source ... --password ${env:NUGET_TOKEN}`` is expanded only at execution time, the literal credential never lives in the project's NuGet.config.
3. If the source must live in the project NuGet.config for portability, use only the credential-free URL (``https://nexus.corp/repo``) and rely on the consumer's user-level config (where credentials are encrypted) for authentication.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## NUGET-015: PackageReference VersionOverride defeats Central Package Management { #nuget-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Re-parses each ``.csproj`` and walks ``<PackageReference>`` entries for the ``VersionOverride`` attribute. Fires when the project participates in Central Package Management (i.e. ``NuGetProject.is_central_managed`` is true) AND any ``VersionOverride`` is set.

Skips projects that don't participate in CPM — those use ``Version`` directly on every ``PackageReference``, and the ``VersionOverride`` attribute is a no-op there. The audit anchor is specifically the case where CPM is in force and a project punches a hole through it.

**Known false-positive modes**

- Some workspaces use ``VersionOverride`` to selectively test a newer version of a single package in one project before promoting it to ``Directory.Packages.props``. The rule still fires; suppress per project / per package with a one-line rationale naming the test and the planned promotion milestone.

**Seen in the wild**

- Pattern in long-lived .NET monorepos that adopt CPM during a posture cleanup but never police ``VersionOverride`` usage afterward: individual projects accumulate stale overrides for packages whose central version has since moved on, creating a hidden multi-version graph that defeats the single-version-per-package invariant CPM is meant to guarantee.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``VersionOverride`` attribute and pin the central version instead — update ``Directory.Packages.props`` if the override was meant to bump every consumer, or scope the override to a child ``Directory.Packages.props`` if only a subtree of the workspace needs the bump. The point of Central Package Management is to keep one version per package across the workspace; per-project ``VersionOverride`` punches through that contract and lets individual ``.csproj`` files drift away from the central pin silently.

Two stable remediation patterns:

* If the override exists because one project needs a newer version, accept the bump everywhere: update ``Directory.Packages.props`` to the new version and delete the override.
* If only a subtree of the workspace can take the new version, scope it with a nested ``Directory.Packages.props`` in the subtree's directory; CPM honors the closest parent.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-016: Private feed without <clear/> inherits the public gallery { #nuget-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when a ``NuGet.config`` declares at least one non-``nuget.org`` package source and its ``<packageSources>`` block has no ``<clear />`` element. The rule re-reads the file to detect ``<clear />`` (the loader keeps only ``<add>`` entries). A source counts as the public gallery when its URL contains ``nuget.org``; anything else (an internal Nexus / Artifactory / Azure Artifacts feed, a local folder) is treated as a private feed whose names a public package could shadow.

Distinct from NUGET-007 (multiple sources without ``packageSourceMapping``): NUGET-007 only fires when one config enumerates two or more sources, so it structurally misses the common shape this rule catches, a config that lists only the internal feed while ``nuget.org`` leaks in through config inheritance. Microsoft's "3 Ways to Mitigate Risk Using Private Package Feeds" names ``<clear/>`` as the fix.

**Known false-positive modes**

- A repo whose only source is an internal mirror that itself proxies and screens nuget.org may accept the inherited gallery deliberately. The rule still fires because the config text alone can't prove the mirror screens for dependency confusion. Suppress per config with a one-line rationale naming the mirror's policy.

**Seen in the wild**

- Birsan 2021 dependency-confusion research: internal package names resolved against the public registry because the public feed stayed active alongside the private one. The .NET face of the attack is a NuGet.config that adds a private feed without ``<clear/>``, leaving nuget.org in the resolution set so a public package with the internal name and a higher version is installed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``<clear />`` element as the first child of ``<packageSources>`` in ``NuGet.config``, then list every source the project is allowed to use explicitly:

    <packageSources>
      <clear />
      <add key="internal" value="https://nuget.corp.local/v3/index.json" />
      <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    </packageSources>

NuGet merges ``packageSources`` across the machine, user, and repo configs, so a repo config that lists only the internal feed still resolves ``nuget.org`` (added by the machine-level default config). Because NuGet installs the highest version found across every active source, a public package that shadows an internal name can win the race. ``<clear />`` discards the inherited sources so only the ones you list apply. Pair it with ``<packageSourceMapping>`` (see NUGET-007) to pin each namespace to one feed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-018: Project runs build-time MSBuild logic at restore/build { #nuget-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Re-reads each ``*.csproj`` and fires on two high-signal shapes of build-time code execution:

* an ``<Exec>`` task nested in a ``<Target>`` whose ``BeforeTargets`` or ``AfterTargets`` names a build / restore phase (``Build``, ``Restore``, ``Compile``, ``Pack``, ``Publish``, and the common pre/post hooks), so the command runs automatically; and
* an ``<Import>`` whose ``Project`` references a generated package path property (``$(Pkg...)``), which pulls a package's ``build/`` MSBuild logic into the build.

The rule inspects structure, not command content, so a legitimate codegen ``<Exec>`` is flagged too (see the known false-positive note). ``packages.config`` projects and non-``.csproj`` inputs are skipped.

**Known false-positive modes**

- Many projects use a build-phase ``<Exec>`` for legitimate codegen (T4, protobuf, a version-stamp script). The rule flags the execution surface, not malice, since the command string alone can't be trusted to stay benign. Review the command; if it's a trusted in-repo script, suppress per project with a one-line rationale.

**Seen in the wild**

- MSBuild build-time execution is the .NET parallel of the npm lifecycle-script attack class: a package ships ``build/<id>.props`` / ``.targets`` that MSBuild auto-imports, or a project carries a ``BeforeTargets="Build"`` ``<Exec>``, so attacker-controlled commands run during a routine restore / build with the runner's credentials.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move build-time shell-outs out of the project file, or gate them behind an explicit, reviewed opt-in. Two shapes trip this rule:

1. An ``<Exec>`` task in a ``<Target>`` wired to a build / restore phase via ``BeforeTargets`` / ``AfterTargets`` runs an arbitrary command on every build, in the developer shell and the CI runner with whatever credentials those carry. Prefer a checked-in, reviewed build script invoked explicitly over an auto-running ``<Exec>``; if codegen is unavoidable, pin the tool version and review the command.

2. A ``PackageReference`` with ``GeneratePathProperty="true"`` feeding an ``<Import Project="$(Pkg...)\build\..." />`` auto-imports a package's MSBuild ``.props`` / ``.targets`` (the .NET analog of an npm ``postinstall``). Remove the manual import, or vet the package's ``build/`` payload and pin it by version.

The point is that nothing in a package restore or a routine ``dotnet build`` should be able to execute attacker-controlled host commands without a human having reviewed exactly what runs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## NUGET-019: signatureValidationMode=require with no trusted signers { #nuget-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

The follow-up to NUGET-012. NUGET-012 fires when ``signatureValidationMode`` is not ``require``; this rule fires for the opposite, narrower case: the mode IS ``require`` but ``<trustedSigners>`` is missing or carries no ``<certificate>`` under any ``<author>`` / ``<repository>`` entry. The rule re-reads the file to inspect ``<config>`` and ``<trustedSigners>``. When the mode is anything other than ``require`` the rule passes and leaves the finding to NUGET-012.

**Known false-positive modes**

- A config that inherits ``<trustedSigners>`` from a machine-level or parent ``NuGet.config`` looks empty here but validates correctly at restore time. The rule reads a single file, so it can't see inherited signers. Suppress per config with a one-line rationale pointing at the parent config that supplies the signers.

**Seen in the wild**

- .NET supply-chain hardening guidance: teams enable ``signatureValidationMode=require`` expecting it to reject unsigned or untrusted packages, but without a populated ``<trustedSigners>`` list the setting has no trust anchor to enforce against, so the protection is silently a no-op.

<div class="pg-rule__rec" markdown>

**Recommended action**

When ``signatureValidationMode`` is ``require``, add at least one ``<trustedSigners>`` entry with a certificate so there is something to validate signatures against:

    <config>
      <add key="signatureValidationMode" value="require" />
    </config>
    <trustedSigners>
      <repository name="nuget.org"
                  serviceIndex="https://api.nuget.org/v3/index.json">
        <certificate fingerprint="<sha256-of-cert>"
                     hashAlgorithm="SHA256"
                     allowUntrustedRoot="false" />
      </repository>
    </trustedSigners>

``require`` only rejects untrusted packages when there is a populated signer list to validate against. With ``require`` set but ``<trustedSigners>`` empty or absent, NuGet has no anchor to check signatures against, so the integrity guarantee the mode is supposed to provide doesn't actually hold.

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
