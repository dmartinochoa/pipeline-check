# Package registries (npm / PyPI / Maven)

Category landing page for the language package-registry providers.
These three providers all scan dependency manifests + lockfiles on
disk (no install, no registry fetch) for the supply-chain hygiene
patterns that turned Shai-Hulud, ctx, and Log4Shell into
mass-propagation incidents: floating version specifiers, missing
integrity / hash anchoring, plaintext-HTTP indexes, install-time
lifecycle scripts, and curated known-compromised version
registries.

The home page shows one "Package registries" tile that aggregates
the rule counts across all three; the per-registry pages below
carry the full rule reference for each platform.

## Providers in this category

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="../npm/">
    <h3>npm</h3>
    <p>Parses <code>package.json</code>, <code>package-lock.json</code>, and <code>.npmrc</code>. Lockfile presence, lifecycle scripts, secret-in-files, compromised-package registry.</p>
    <span class="pg-doc-card__meta">{{ providers.npm.checks }}</span>
  </a>
  <a class="pg-doc-card" href="../pypi/">
    <h3>PyPI</h3>
    <p>Parses <code>requirements.txt</code>. Range-pinned versions, missing hashes, compromised-package registry.</p>
    <span class="pg-doc-card__meta">{{ providers.pypi.checks }}</span>
  </a>
  <a class="pg-doc-card" href="../maven/">
    <h3>Maven</h3>
    <p>Parses <code>pom.xml</code> and <code>settings.xml</code>. Floating ranges and SNAPSHOTs, plaintext-HTTP repositories, lax checksumPolicy, wildcard mirrors, Log4Shell-class compromised-package registry.</p>
    <span class="pg-doc-card__meta">{{ providers.maven.checks }}</span>
  </a>
</div>

## What the rule packs share

Common shape across all three:

* **Static parse only.** No package install, no registry network
  call, no daemon access. Manifest + lockfile bytes only.
* **Compromised-package registry.** Each pack ships a curated
  ``_compromised_packages.py`` module of (name, version) pairs
  drawn from real incidents (event-stream, ua-parser-js, coa, rc,
  node-ipc, ctx 0.2.2-0.2.8, requests-darwin-lite 2.27.1,
  Log4Shell / Spring4Shell / Text4Shell). Findings cite the CVE
  and the upstream incident note.
* **Floating-version hygiene.** Range specifiers / SNAPSHOTs /
  unpinned VCS deps all surface as a separate finding from the
  compromised-version one so the operator sees both the
  posture failure and the immediate risk.
* **Transport hygiene.** Plaintext-HTTP registry / index URLs,
  TLS-bypass flags, and lax checksum policies all trigger
  HIGH-severity findings tied to the relevant OWASP CI/CD risk
  and the CIS Supply Chain control.

## CLI

Each provider auto-detects its manifest at cwd and announces the
pick on stderr; pass the explicit flag to scan a different path.

```bash
pipeline_check --pipeline npm     --npm-path path/to/package.json
pipeline_check --pipeline pypi    --pypi-path path/to/requirements.txt
pipeline_check --pipeline maven   --maven-path path/to/pom.xml
```

See each per-registry page for the full rule reference, the
parser scope (which files it loads, which it skips), and the
known-compromised-version registry contents.
