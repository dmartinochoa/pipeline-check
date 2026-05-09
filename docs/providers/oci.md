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

3 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [OCI-001](#oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [OCI-002](#oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [OCI-003](#oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> |  |

---

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
