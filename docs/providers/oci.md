# OCI image manifest provider

Parses OCI image manifests / image-indexes from disk, pure JSON, no
registry pull, no image build, no daemon access. The user captures
the manifest with ``docker buildx imagetools inspect --raw <ref>``
(or the equivalent ``oras manifest fetch`` / ``crane manifest``)
and points the scanner at the resulting JSON. Recognized media
types: the OCI 1.0 / 1.1 spec types
(``application/vnd.oci.image.{index,manifest}.v1+json``) and the
Docker-distribution-v2 equivalents BuildKit still emits by default.

## Producer workflow

```bash
# Capture the index from a registry into a JSON file.
docker buildx imagetools inspect --raw \
    ghcr.io/example/app:1.0.0 > image.json

# Run the scanner.
pipeline_check --pipeline oci --oci-manifest image.json

# Or point at a directory; ./index.json is auto-detected.
pipeline_check --pipeline oci --oci-manifest ./oci-layout/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### What the rules expect

OCI rules operate on the manifest *shape* alone, the scanner never
fetches the config blob or layer contents. That keeps the provider
read-from-disk-only and avoids taking on a registry-credential
surface, but it also bounds what's detectable: anything that
requires the config (entrypoint, labels written via
``--label`` rather than ``--annotation``, layer history) is out
of scope. Use the Dockerfile provider in tandem to catch
authoring-time gaps that don't survive into the manifest.

### OCI-specific checks

- **OCI-001**, image manifest must carry
  ``org.opencontainers.image.source`` and
  ``org.opencontainers.image.revision`` annotations. Mirrors
  DF-016 (Dockerfile-time) at the image-manifest layer so a build
  that overrides annotations via ``docker buildx --annotation``
  is still scored.
- **OCI-002**, image index must include at least one attestation
  manifest (BuildKit-style sub-manifest annotated with
  ``vnd.docker.reference.type: attestation-manifest``). This is
  where ``--attest=type=provenance`` and ``--attest=type=sbom``
  land their data; without one, neither SLSA provenance nor an
  SBOM is reachable from the image.
- **OCI-003**, image manifest must carry
  ``org.opencontainers.image.created``. CVE triage uses this to
  determine the image's build date without pulling the config
  blob.

## What it covers

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ATTEST-001](#attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ATTEST-002](#attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ATTEST-003](#attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ATTEST-004](#attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ATTEST-005](#attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [OCI-001](#oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [OCI-002](#oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [OCI-003](#oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [OCI-004](#oci-004) | Image layer references an arbitrary URL (foreign layer) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [OCI-005](#oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [OCI-006](#oci-006) | Image has an excessive layer count | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [OCI-007](#oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [OCI-008](#oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ATTEST-001: SLSA provenance attests an untrusted builder identity { #attest-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads the SLSA provenance from each in-toto Statement carried in the image's attestation manifests, then checks ``predicate.builder.id`` (SLSA v0.2) / ``predicate.runDetails.builder.id`` (SLSA v1) against an allowlist of URI prefixes for hosted CI builders. Fires when the attested builder is unknown or matches a self-hosted-runner shape.

Triggering this rule means the bytes of the runtime image were produced by a builder identity the SLSA contract cannot vouch for. A compromised self-hosted runner can produce a perfectly-formed, signature-valid attestation for a tampered image, so a passing OCI-002 (attestation present) is not the same thing as a trustworthy attestation, this rule is the difference.

**Known false-positive modes**

- Some teams run their own SLSA-conformant builders for policy reasons (air-gapped builds, regulated workloads, FedRAMP environments). Add the builder's URI prefix to a future allowlist override (deferred to v2) or suppress via ignore-file when the team has a documented review of the builder's isolation posture.
- Older BuildKit versions emitted a generic placeholder (``https://github.com/docker/buildx@v0.X``) without tying the identity to the runner. Modern Buildx writes a concrete builder URI; if the scan flags a placeholder, upgrade Buildx and rebuild before treating it as a real incident.

**Seen in the wild**

- [SLSA threat-model v1.0](https://slsa.dev/spec/v1.0/threats): untrusted builder is the canonical Build-track Threat #2 ('Build the package from a modified source'). A tampered self-hosted runner can emit a syntactically-valid attestation for the wrong source.
- GitHub self-hosted runner advisory (CVE-2024-32004 et al.): self-hosted runners default to non-ephemeral, persisted state; a single fork-PR run gives the attacker arbitrary code execution that produces signed artifacts on every subsequent legitimate build. SLSA's isolation requirement (L2+) explicitly excludes this shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Re-run the build on a recognized hosted CI builder (GitHub-hosted runners, slsa-github-generator, Cloud Build, GitLab SaaS, Buildkite, or BuildKit attesting via Docker Hub) so the SLSA ``builder.id`` claim resolves to an isolated, publicly-auditable build environment. Self-hosted runners and unknown builder identities defeat the SLSA L2+ isolation guarantee, the supply-chain trust chain only extends as far as the *builder* the attestation names.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ATTEST-002: SLSA provenance source-repo claim is missing or unverifiable { #attest-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

The ``builder.id`` claim that ATTEST-001 verifies tells you *who* built the image. The source-repo claim ATTEST-002 verifies tells you *what* they built. Both are required for the SLSA chain to be meaningful: a trusted builder running an unknown source produces a signed attestation for code you can't audit.

The rule walks the SLSA provenance predicate for a source URI. Path varies by spec version:
  - v0.2: ``predicate.invocation.configSource.uri``
  - v1.0: ``predicate.buildDefinition.externalParameters`` (builder-specific, commonly ``.workflow.repository`` or ``.source.uri``)
Fires when:
  - no URI is present anywhere on the expected paths;
  - the URI is a known placeholder (empty, ``?``, ``unknown``, ``n/a``);
  - the URI doesn't parse as a recognizable VCS / HTTPS shape;
  - a URI is present but the corresponding digest field is missing or all-zeros (the bytes aren't actually pinned).

**Known false-positive modes**

- Some SLSA Phase-0 attestations omit the digest field on purpose, the build was reproducible-by-source rather than pinned to a commit. Suppress via ignore-file when the team has documented this trade-off; the default expectation for any image promoted to a production registry is a concrete commit pin.
- Builders that emit free-form ``externalParameters`` shapes (some self-hosted SLSA implementations) may carry the source URI under a non-canonical key. The rule walks every string value in ``externalParameters`` looking for a VCS URI; if none is found, the finding fires. Add the builder to a future allowlist override (deferred) when the shape is intentional.

**Seen in the wild**

- [SLSA threat-model v1.0, Source-track Threat #4](https://slsa.dev/spec/v1.0/threats) ('Build uses unauthorized source'): a builder pulling code from a fork or a different ref than the operator believes produces an attestation that signs the wrong bytes.
- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): the build system pulled tampered source from an unauthorized branch via SUNSPOT, producing 'authentic' signed builds for code the development team never wrote. A pinned, verified source-repo claim is the control SLSA L2+ requires specifically to detect this shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Ensure the build emits SLSA provenance with a concrete source-repo URI plus a commit-level digest. For SLSA v0.2 that's ``predicate.invocation.configSource.uri`` + ``configSource.digest`` (typically ``sha1`` for git refs). For SLSA v1, ``predicate.buildDefinition.externalParameters`` should name the workflow's source repository, and ``predicate.buildDefinition.resolvedDependencies`` should include the same source pinned by digest. A missing or placeholder URI ('', 'unknown', 'n/a') leaves consumers unable to confirm what code produced the image.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ATTEST-003: SBOM contains floating-version dependencies { #attest-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

ATTEST-001 verifies the builder; ATTEST-002 verifies the source; ATTEST-003 verifies the *contents* of what was shipped. A signed SBOM that declares ``openssl`` version ``latest`` is worse than no SBOM, the signature gives the rot a stamp of approval. Vulnerability-scanning tooling that reads the SBOM produces false negatives because the version it queries CVE databases for is unstable.

Detection walks every SBOM attestation (predicate types starting with ``https://spdx.dev/Document`` or ``https://cyclonedx.org/bom``) and checks each declared package's version field against a floating-shape regex. A package is considered pinned when its version matches a concrete release identifier (semver, calver, sha-style digest, or any git tag with at least one numeric component).

**Known false-positive modes**

- Some SBOM emitters legitimately leave ``versionInfo`` empty for system-injected components the build couldn't resolve (e.g. ``glibc`` from the base image when the image was built without distro metadata). Suppress via ignore-file scoped to the manifest path when the SBOM was produced in a context that intentionally elides those entries; for production-bound images the expectation is full version coverage.
- Source-only components (a Git repo bundled into a builder stage) sometimes carry the branch name in version. Long-term that's still a floating reference (the branch tip moves), so the rule fires by design; switch to tag+digest pinning before suppressing.

**Seen in the wild**

- [Log4Shell downstream impact](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a) (CVE-2021-44228): organizations with SBOMs at the ready could ship patches in hours; those without (or with floating-version SBOMs) spent days auditing builds to discover what they actually shipped. The ``log4j-core@latest`` shape was the worst case — the SBOM said the right name but no consumer could pin which exact bytes were in production.
- Common SBOM-quality findings (NTIA SBOM Minimum Elements report, 2021): version completeness consistently the lowest-scoring dimension across producers. Floating versions account for the bulk of unconsumed SBOMs in vulnerability-management pipelines.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every dependency in the SBOM to a concrete version (a released semver, a digest, or a tag-plus-commit pair). Floating values like ``latest``, ``*``, ``master``, an empty string, or a bare major like ``v1`` defeat the SBOM's purpose: a consumer can't reproduce or vulnerability-scan what they don't have a fixed version of. SPDX 2.x carries version under ``packages[*].versionInfo``; CycloneDX uses ``components[*].version``. Both fields are optional in the spec but operationally required for any meaningful SBOM consumption.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ATTEST-004: SLSA provenance ships without a resolved-dependencies set { #attest-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Walks every SLSA provenance attestation on the image index and reads the materials list at the spec-version-appropriate path. Both v0.2 and v1 are accepted. A missing key, a non-list value, and an empty list all fail (each shape means the consumer gets no input chain-of-custody). Per-material content validation (digest map populated, URI well-formed) is deferred to a future rule, this one establishes that the list exists.

Pairs with ATTEST-003: ATTEST-003 verifies the SBOM covers package-level inputs, ATTEST-004 verifies the build-level inputs. Both are needed for the SLSA Build-track L3 'isolated, reproducible' claim; SBOM-only coverage misses the resolved base image and the build-tool chain.

**Known false-positive modes**

- Trivial ``FROM scratch`` images with no build-time dependencies legitimately have an empty materials list. The rule has no way to distinguish 'trivial build' from 'instrumentation gap', the SLSA spec treats both as the same fail-closed signal. Suppress per-image via ``--ignore-file`` once you've verified the build genuinely has nothing to attest.
- Some builders (older BuildKit, hand-rolled generators) populate ``materials`` but omit the ``digest`` map, which the SLSA spec marks recommended-not-required. This rule accepts that shape today (list non-empty = pass); a future ATTEST-NNN will tighten to require digest coverage.

**Seen in the wild**

- [SLSA v1 spec, Build track L3 requirements](https://slsa.dev/spec/v1.0/levels#build-l3): resolved dependencies are a Build-track requirement, not an optional courtesy. The provenance was supposed to answer 'what went into this artifact'; an empty resolvedDependencies list answers 'we declined to say', which is materially worse than 'we didn't produce an attestation' because consumers see a signed-and-stamped document and trust it.
- tj-actions/changed-files compromise (CVE-2025-30066, March 2025): forensic teams reconstructing the blast radius needed to know which downstream images consumed the compromised action's outputs. Builds whose provenance carried materials lists pinpointed the exposure in minutes; builds without paid for the gap in days of manual review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the builder to emit a non-empty ``materials`` (SLSA v0.2) or ``resolvedDependencies`` (SLSA v1) list with one entry per ingredient the build consumed. For BuildKit, set ``--attest=type=provenance,mode=max`` so the resolved-base-image + checked-out source land in the attestation. For slsa-github-generator the L3 presets populate this automatically; teams running a custom generator must add the inputs explicitly. An empty list is structurally indistinguishable from 'the build had no inputs' and breaks downstream vulnerability correlation.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ATTEST-005: In-toto Statement subject is missing or unpinned { #attest-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Walks every parsed in-toto Statement (SLSA provenance + SBOM both) and validates the subject array. Three failure shapes:
  - ``subject`` is missing or an empty list, the Statement attests nothing.
  - A subject entry has no ``digest`` map, the entry names an artifact but doesn't bind to its bytes.
  - A digest value is empty, all-zeros, or not valid hex, the bind exists structurally but the value is a placeholder.

Hex validation is conservative: the value must consist entirely of ``0-9`` and ``a-f`` (case-insensitive) and the length must be a multiple of two (a valid byte encoding). Algorithm-specific length checks (``sha256`` = 64 chars, ``sha1`` = 40) are not enforced here, some registries truncate to a 16-char prefix and the rule accepts those as long as the bytes are well-formed.

**Known false-positive modes**

- Some experimental attestor implementations emit Statements with placeholder subjects for in-flight verification (the bytes are still being uploaded when the attestation is signed). Suppress per-manifest via ``--ignore-file`` if the team has a documented review of the deferred-binding pattern; the default expectation for any image promoted to a production registry is a subject digest that matches the actual image bytes.
- Multi-subject Statements (one attestation covering multiple sibling artifacts) are accepted, as long as *every* entry has a populated digest. A partially-filled subject array fires because the unbound entries are the substitution surface, the rest don't compensate.

**Seen in the wild**

- [in-toto Statement spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md): the subject digest is the cryptographic bind between a signed envelope and the artifact bytes. A placeholder value reduces the attestation to a free-floating signature attackers can re-attach.
- [SLSA threat-model v1.0, Statement-Track Threats](https://slsa.dev/spec/v1.0/threats): attestation substitution is called out as the primary Statement-track threat. The mitigation listed is exactly this rule: 'consumers MUST verify the subject digest matches the artifact they are about to use'.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the builder to emit Statements with a non-empty ``subject`` array whose entries each carry a populated ``digest`` map. The digest value must be a real hex encoding of the artifact's bytes, an empty string or all-zeros placeholder defeats verification. For BuildKit this is automatic when ``--attest=type=provenance`` is set alongside ``--push``; older Buildx versions sometimes emitted Statements with empty subjects, upgrade if you see this fire on a recent build. For slsa-github-generator and cosign-attested workflows the subject is populated by the framework, an empty subject usually means a custom attestor was wired up incorrectly.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## OCI-001: Image manifest is missing OCI provenance annotations { #oci-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without these two annotations a pulled image can't be traced back to a source revision, so an incident-response team has no way to reach the build that produced it. The rule fires on whichever layer the manifest carries (top-level for an index, sub-manifest for a per-platform image); DF-016 catches the same gap at Dockerfile authoring time, OCI-001 catches it once the image has been built and any later ``docker buildx --annotation`` overrides have already been applied.

**Known false-positive modes**

- Throwaway / scratch images that never leave a developer's machine (e.g. ``image inspect`` of an intermediate build stage) don't need provenance annotations. Suppress via ignore-file rather than removing the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Stamp the image with at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). With ``docker buildx`` this is ``--label org.opencontainers.image.source=...`` plus ``--label org.opencontainers.image.revision=...`` at build time, or set them as image annotations through ``--annotation`` so they appear on the manifest itself (``manifest.annotations`` is what registries surface to ``manifest inspect``).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## OCI-002: Image is missing a build attestation manifest { #oci-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Build attestations are the canonical place for SLSA provenance and SBOM data on an OCI image. A multi-platform image index that ships per-architecture manifests but no attestation-manifest sibling means there's no signed record of how the image was built or what's inside it, so consumers can't enforce SLSA Build-L2+ or feed an SBOM into vulnerability triage. A single-platform manifest (no image index) also fails this rule, attestations require the index-of-manifests shape that BuildKit produces by default.

**Known false-positive modes**

- Intermediate / cache-only images pushed by CI for later-stage consumption may legitimately ship without attestations to keep build artifacts small. Suppress via ignore-file when this is the deliberate shape, the default expectation for any image that reaches a production registry is a full attestation set.
- Some registries strip the attestation sub-manifests on pull (``docker pull`` of a single platform unwraps the index). If the JSON you're scanning came from ``docker manifest inspect`` rather than ``docker buildx imagetools inspect --raw``, attestations may be invisible even when present upstream.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the image with ``docker buildx build --attest=type=provenance,mode=max --attest=type=sbom`` (or the equivalent BuildKit frontend flags). Both attestations land as sibling sub-manifests inside the image index, annotated with ``vnd.docker.reference.type: attestation-manifest`` and linked to their target manifest via ``vnd.docker.reference.digest``. Verify after pushing with ``docker buildx imagetools inspect <ref>``, the ``Attestations`` section should list both predicate types.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## OCI-003: Image manifest is missing the ``image.created`` annotation { #oci-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Image age isn't a security boundary on its own, but a missing ``image.created`` annotation makes routine triage questions ("is this image stale enough to warrant a rebuild?", "was this image built before or after the CVE-2024-XXXX advisory?") much harder to answer automatically. Surfacing the gap as LOW-severity catches the omission early without overwhelming reports for an otherwise-well-formed image.

**Known false-positive modes**

- Reproducible-build pipelines deliberately omit ``image.created`` (or pin it to ``SOURCE_DATE_EPOCH``) so the same source produces a byte-identical image. Suppress via ignore-file when reproducibility is the goal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Stamp ``org.opencontainers.image.created`` with the build timestamp (RFC 3339 / ISO 8601, e.g. ``2025-01-30T18:00:00Z``). With ``docker buildx`` either pass ``--label org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)`` at build time, or rely on the BuildKit frontend default which does it automatically when ``SOURCE_DATE_EPOCH`` is unset. The annotation lets downstream vuln scanners and registries surface image age, which is the lightest-weight CVE-triage signal available without pulling the config blob.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## OCI-004: Image layer references an arbitrary URL (foreign layer) { #oci-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

A layer with a ``urls:`` field is fetched from whatever URL the manifest declares, not from the registry the image was pulled from. The digest is still verified after the fetch, so a passive attacker can't substitute a different blob, but an attacker who controls the URL endpoint can serve different content depending on the client (server-side cloaking) or simply take the endpoint offline to break image pulls. The rule fires on any layer whose descriptor includes a non-empty ``urls:`` array; it doesn't try to validate URL hygiene (HTTPS, allow-list of hosts) since the existence of the field alone is the policy violation.

**Known false-positive modes**

- Legacy Windows Server base images (pre-Windows 11 / Server 2022) ship layers from ``mcr.microsoft.com`` with this mechanism. Suppress via ignore-file when the Windows image is intentional, the rule has no way to distinguish a Microsoft-blessed URL from any other.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rebuild the image without foreign-layer references. The OCI / Docker spec lets a layer descriptor carry a ``urls:`` field that tells the client to pull the layer blob from an arbitrary HTTP location at image-pull time, bypassing the registry's content-addressed store. The mechanism exists for proprietary base layers (notably Windows Server base images that ship from ``mcr.microsoft.com``) but is increasingly deprecated, modern Windows images at ``mcr.microsoft.com/windows/servercore:ltsc2022`` no longer use it. If the foreign URL is genuinely required, host the blob inside your own registry and pin it by digest the same as any other layer.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## OCI-005: Image manifest is missing the ``image.licenses`` annotation { #oci-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without ``image.licenses`` an SBOM tool either has to fall back to scanning the layer contents (slow, best-effort) or simply mark the image as ``license: unknown`` in compliance reports. The same field is what container registries surface to the operator UI, so its absence also makes manual license review harder. The rule is LOW severity because a missing license is a hygiene gap rather than a security boundary, but it ratchets up SBOM quality enough that it's worth catching at scan time.

**Known false-positive modes**

- Internal images that never leave a private registry and aren't subject to OSS license compliance audits may legitimately omit the annotation. Suppress via ignore-file when this is the deliberate stance.
- Multi-license images with ambiguous coverage (e.g. a base image plus mixed-license app code) sometimes skip the annotation rather than emit a misleading single-license value. In that case, the correct fix is to emit the SPDX compound expression (``MIT AND Apache-2.0``); suppression is the wrong answer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Stamp ``org.opencontainers.image.licenses`` with the SPDX expression for the image's contents (e.g. ``Apache-2.0``, ``MIT AND Apache-2.0``, ``Apache-2.0 WITH LLVM-exception``). With ``docker buildx`` the simplest path is to add ``--label org.opencontainers.image.licenses=Apache-2.0`` (or, for annotation-based propagation onto the manifest, ``--annotation manifest:org.opencontainers.image.licenses=Apache-2.0``). The OCI image-spec annotation is a well-known SPDX expression carrier, downstream SBOM generators and registry UIs read it directly without needing per-tool configuration.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## OCI-006: Image has an excessive layer count { #oci-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1037</span>
</div>

Each layer is a content-addressed blob with its own registry round-trip on pull, its own caching decision, and its own potential for credential leakage (a ``RUN`` step that touched a secret leaves the secret in that layer's tar archive even if a later layer deletes it). The rule fires above 40 layers, which empirically captures the ``docker history`` blowout that happens when a Dockerfile's ``RUN`` lines don't collapse (``RUN apt-get update`` followed by ``RUN apt-get install`` followed by ``RUN apt-get clean`` is three layers where one would do). Indexes don't have layers of their own, the rule passes on them and applies instead to each per-platform image manifest a downstream scan loads.

**Known false-positive modes**

- Some legitimately large base images (CUDA / ML toolchains, fully-built distros) ship with 30-50 layers by design. Suppress via ignore-file when the layer count reflects a deliberate base-image choice rather than Dockerfile RUN-step sprawl.

<div class="pg-rule__rec" markdown>

**Recommended action**

Squash the image's layer count by collapsing adjacent ``RUN`` directives in the Dockerfile (``RUN apt-get update && apt-get install ... && rm -rf /var/lib/apt/lists/*`` is the canonical pattern), ordering ``COPY`` lines so cache invalidation moves them as a unit, and using multi-stage builds to drop build-time-only artifacts before the final ``FROM``. BuildKit's ``--squash`` flag flattens the result if the Dockerfile shape can't be restructured. Most well-tuned production images sit between 5 and 20 layers; anything past 40 is almost always accidental Dockerfile sprawl, not intentional layering.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## OCI-007: Image manifest uses legacy schemaVersion 1 (no content addressing) { #oci-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

The OCI image-spec (1.0+) and Docker Distribution v2 both encode ``schemaVersion: 2`` on every manifest. The older Docker v1 format set ``schemaVersion: 1`` and stored the rootfs as a chain of un-addressed tarballs with the chain identity hashed end-to-end at pull time. Anything below 2 is by definition a non-content-addressed manifest. The detection is a strict equality check against schemaVersion.

**Known false-positive modes**

- Some internal Harbor / Nexus deployments still proxy legacy Docker images that haven't been rebuilt; a pull succeeds because the proxy upgrades the manifest at request time, but the on-disk JSON if you saved it with ``inspect --raw`` may still report the original schemaVersion. If your registry is doing this in-flight promotion you can suppress; otherwise re-run the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rebuild and re-push the image with a current builder (``docker buildx build`` / ``buildah`` / ``ko``) so the registry produces a v2 manifest with content-addressed layer descriptors. Docker Distribution v1 manifests predate the digest-pinned design that lets a client verify a pulled blob matches the manifest the registry served, so a v1 pull has no way to detect tampering between the registry and the runtime. Registries have been refusing v1 pushes for years (Docker Hub since 2019, GHCR / quay.io / ECR / Artifact Registry never supported them on read), but a pre-existing v1 image can still be sitting in a private registry; the rule catches it before that image gets promoted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## OCI-008: Manifest references digest using unsupported hash algorithm { #oci-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-327</span> <span class="pg-tag pg-tag--cwe">CWE-328</span>
</div>

The OCI image-spec mandates ``sha256:`` or ``sha512:`` for content descriptors. ``sha1:`` and ``md5:`` were never permitted by the spec but show up occasionally in mirror exports and forensic JSON; this rule catches them.

Detection scope: the config descriptor digest, every layer descriptor digest (single-image manifests), and every sub-manifest entry digest in an image index. The matcher accepts ``sha256:`` and ``sha512:`` as the only valid prefixes; anything else fires.

**Known false-positive modes**

- Test fixtures and intentionally-corrupt CTF images sometimes use degraded hashes for pedagogical reasons. Suppress on the specific path with an ignore-file when this is the deliberate shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rebuild and re-push the image so every descriptor (config, layers, sub-manifest entries) carries a ``sha256:`` digest. ``sha512:`` is also acceptable per the OCI spec, but anything weaker (md5, sha1) breaks the integrity guarantee the registry pull is supposed to provide. sha1 has had practical collisions since SHAttered (2017); md5 has had them since the early 2000s. A manifest that pins a layer by sha1 lets an attacker who can produce a colliding blob substitute a different tarball without changing the manifest, the registry's content-addressing then ratifies the substitution.

</div>

</div>

---

## Adding a new OCI image manifest check

1. Create a new module at
   `pipeline_check/core/checks/oci/rules/ociNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(manifest: OCIManifest) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``OCIManifest``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/oci/OCI-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py oci
   ```
