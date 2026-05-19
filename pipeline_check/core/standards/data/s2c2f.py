"""S2C2F. Secure Supply Chain Consumption Framework (OpenSSF / Microsoft).

S2C2F is a purpose-built framework for how an organization *consumes*
open-source software in its CI/CD pipeline. It's organized into 8
practices (Ingest, Scan, Inventory, Update, Enforce, Audit, Rebuild,
Fix) with requirements at maturity levels L1–L4.

This scanner evidences a focused subset, the requirements that show
up as pipeline configuration (not the ones that require org-level
process or external tooling visibility). Level 4 rebuild requirements
(REB-1: rebuild on trusted infra, REB-2/3/4: sign + SBOM the rebuild)
overlap the signing / SBOM / SLSA-attestation rules directly.

Unmapped practices (require introspection outside this scanner):
  ING-2 (binary repo manager), ING-4 (source mirror), INV-1 (component
  inventory registry), AUD-1/2 (per-PR evidence), SCA-2 (license
  scanning), SCA-4 (EOL tracking), FIX-1/2/3 (incident process).
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="s2c2f",
    title="Secure Supply Chain Consumption Framework",
    version="2024-05",
    url="https://github.com/ossf/s2c2f/blob/main/specification/framework.md",
    controls={
        # ── Ingest ─────────────────────────────────────────────────
        "ING-1": "L1: Use package managers trusted by your organization",
        "ING-3": "L1: Have the capability to deny-list specific vulnerable / malicious OSS",
        # ── Scan ───────────────────────────────────────────────────
        "SCA-1": "L1: Scan OSS for known vulnerabilities",
        "SCA-3": "L2: Scan OSS for malware",
        # ── Update ─────────────────────────────────────────────────
        "UPD-1": "L1: Update vulnerable OSS manually (pin + track versions)",
        "UPD-2": "L3: Enable automated OSS updates (Dependabot / Renovate)",
        # ── Enforce ────────────────────────────────────────────────
        "ENF-1": "L2: Enforce security policy of OSS usage (block on violation)",
        "ENF-2": "L2: Break the build when a violation is detected",
        # ── Rebuild ────────────────────────────────────────────────
        "REB-2": "L4: Digitally sign rebuilt / produced OSS artifacts",
        "REB-3": "L4: Generate SBOMs for artifacts produced",
        "REB-4": "L4: Digitally sign SBOMs produced (attested provenance)",
    },
    mappings={
        # ── ING-1 / ING-3: trusted sources, deny-listable ──────────
        "GHA-018":  ["ING-1"],
        "GL-018":   ["ING-1"],
        "BB-014":   ["ING-1"],
        "ADO-018":  ["ING-1"],
        "JF-018":   ["ING-1"],
        "CC-018":   ["ING-1"],
        "CA-002":   ["ING-1", "ING-3"],    # public upstream = no deny-list gate
        "ECR-006":  ["ING-1", "ING-3"],    # untrusted upstream = can't deny-list at the registry boundary
        "GHA-029":  ["ING-1"],             # package source bypasses lockfile
        "GL-027":   ["ING-1"],
        "BB-027":   ["ING-1"],
        "ADO-028":  ["ING-1"],
        "JF-031":   ["ING-1"],
        "CC-028":   ["ING-1"],
        "BK-004":   ["ING-1"],             # curl-pipe to shell
        "BK-008":   ["ING-1"],             # TLS bypass
        "TKN-008":  ["ING-1"],             # remote install / TLS bypass
        "ARGO-008": ["ING-1"],             # remote install / TLS bypass
        # TLS / certificate verification bypass across CI providers
        # = breaks the trusted-source guarantee for OSS install steps.
        "GL-023":   ["ING-1"],             # GitLab TLS bypass
        "BB-023":   ["ING-1"],             # Bitbucket TLS bypass
        "ADO-023":  ["ING-1"],             # Azure DevOps TLS bypass
        "JF-023":   ["ING-1"],             # Jenkins TLS bypass
        "JF-035":   ["ING-1"],             # httpRequest ignoreSslErrors: true
        "DR-006":   ["ING-1"],             # Drone TLS bypass
        "GCB-011":  ["ING-1"],             # Cloud Build TLS bypass
        "GHA-016":  ["ING-1"],             # remote script piped to shell
        "GHA-017":  ["ING-1"],             # package install from insecure source
        # NPM / PyPI / Maven manifest static analysis
        "NPM-003":  ["ING-1"],             # non-registry source (git/path/tarball)
        "NPM-004":  ["ING-1"],             # install-time lifecycle script
        "NPM-007":  ["ING-1"],             # .npmrc ignore-scripts enforcement
        "PYPI-003": ["ING-1"],             # http index / --trusted-host
        "PYPI-005": ["ING-1"],             # --extra-index-url (dep confusion)
        "MVN-003":  ["ING-1"],             # plaintext-HTTP repository
        "MVN-007":  ["ING-1"],             # settings.xml wildcard mirror
        # Dockerfile env-bypass pack disables the trusted-source channel
        # for any subsequent OSS install in the image.
        "DF-021":   ["ING-1"],             # pip install TLS bypass / http index
        "DF-022":   ["ING-1", "UPD-1"],    # npm install (not npm ci) — re-resolves
        "DF-024":   ["ING-1"],             # npm install runs lifecycle scripts
        "DF-026":   ["ING-1"],             # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["ING-1"],             # PYTHONHTTPSVERIFY=0
        "DF-028":   ["ING-1"],             # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["ING-1"],             # REQUESTS_CA_BUNDLE neutered

        # ── SCA-1: scan for known vulns ────────────────────────────
        "GHA-020":  ["SCA-1"],
        "GL-019":   ["SCA-1"],
        "BB-015":   ["SCA-1"],
        "ADO-020":  ["SCA-1"],
        "JF-020":   ["SCA-1"],
        "CC-020":   ["SCA-1"],
        "GCB-008":  ["SCA-1"],
        "ECR-001":  ["SCA-1"],
        "ECR-007":  ["SCA-1"],             # Inspector v2 enhanced scanning
        "BK-012":   ["SCA-1"],
        "TKN-012":  ["SCA-1"],
        "ARGO-012": ["SCA-1"],

        # ── SCA-3: scan for malware / malicious activity ───────────
        "CB-011":   ["SCA-3"],
        "GHA-027":  ["SCA-3"],
        "GHA-056":  ["SCA-3", "ING-3"],     # known worm IOC = denyable + malware-class
        "GHA-057":  ["SCA-3"],              # scanner-output-to-egress is malicious shape
        "GHA-058":  ["SCA-3"],              # AI-CLI bypass turns the runner into a scanner
        "GHA-059":  ["SCA-3"],              # npm install without registry-signature verification
        "GL-034":   ["SCA-3"],              # npm install without registry-signature verification
        # Known-compromised package / action references are the
        # canonical deny-list signal: each finding is one entry on a
        # curated deny-list of versions that should never be installed.
        # Maps to SCA-3 (malware-class detection) + ING-3 (deny-list
        # capability), same shape as GHA-056 above.
        "GHA-040":  ["SCA-3", "ING-3"],     # known-compromised action ref
        "NPM-006":  ["SCA-3", "ING-3"],     # compromised npm version
        "PYPI-006": ["SCA-3", "ING-3"],     # compromised PyPI version
        "MVN-006":  ["SCA-3", "ING-3"],     # compromised Maven version
        # Reputation-class deny-list signals: not malware-confirmed,
        # but each finding is one entry on a curated deny-list of
        # references that should require human-in-the-loop review
        # before installation.
        "GHA-041":  ["ING-3"],              # single-maintainer action
        "GHA-042":  ["ING-3"],              # very-young action repo
        "GHA-043":  ["ING-3"],              # low-star + sensitive perms
        "GHA-047":  ["ING-3"],              # fresh-ref cooldown
        "GL-025":   ["SCA-3"],
        "BB-025":   ["SCA-3"],
        "ADO-026":  ["SCA-3"],
        "JF-029":   ["SCA-3"],
        "CC-026":   ["SCA-3"],

        # ── UPD-1: pin + track (pinning rules evidence manual mgmt) ─
        "GHA-001":  ["UPD-1"],
        "GHA-025":  ["UPD-1"],
        "GHA-021":  ["UPD-1"],             # lockfile present = tracked versions
        "GL-001":   ["UPD-1"],
        "GL-005":   ["UPD-1"],
        "GL-009":   ["UPD-1"],
        "GL-021":   ["UPD-1"],
        "GL-028":   ["UPD-1"],
        "GL-030":   ["UPD-1"],
        "BB-001":   ["UPD-1"],
        "BB-009":   ["UPD-1"],
        "BB-021":   ["UPD-1"],
        "ADO-001":  ["UPD-1"],
        "ADO-005":  ["UPD-1"],
        "ADO-009":  ["UPD-1"],
        "ADO-021":  ["UPD-1"],
        "ADO-025":  ["UPD-1"],
        "JF-001":   ["UPD-1"],
        "JF-009":   ["UPD-1"],
        "JF-021":   ["UPD-1"],
        "CC-001":   ["UPD-1"],
        "CC-003":   ["UPD-1"],
        "CC-021":   ["UPD-1"],
        "CC-029":   ["UPD-1"],
        "GCB-001":  ["UPD-1"],
        "CB-005":   ["UPD-1"],
        "CB-009":   ["UPD-1"],
        "ECR-002":  ["UPD-1"],
        "BK-001":   ["UPD-1"],
        "TKN-001":  ["UPD-1"],
        "ARGO-001": ["UPD-1"],
        # Drone pinning surface
        "DR-001":   ["UPD-1"],             # step image not digest-pinned
        "DR-005":   ["UPD-1"],             # plugin floating tag
        "DR-008":   ["UPD-1"],             # pull: never (skips registry verification)
        # NPM / PyPI / Maven pinning
        "NPM-001":  ["UPD-1"],             # floating range in package.json
        "NPM-002":  ["UPD-1"],             # lock entry missing integrity
        "NPM-005":  ["UPD-1"],             # git dep with mutable ref
        "PYPI-001": ["UPD-1"],             # requirements lacks ==pin
        "PYPI-002": ["UPD-1"],             # hash pinning missing
        "PYPI-004": ["UPD-1"],             # VCS dep without commit SHA
        "MVN-001":  ["UPD-1"],             # floating Maven version range
        "MVN-002":  ["UPD-1"],             # mutable SNAPSHOT dep
        "MVN-004":  ["UPD-1"],             # missing <version> element
        "MVN-005":  ["UPD-1"],             # lax repository checksumPolicy
        # OCI image manifest pinning
        "OCI-007":  ["UPD-1"],             # legacy schemaVersion 1 (no digest immutability)
        "OCI-008":  ["UPD-1"],             # weak digest algorithm
        # Reusable / cross-template pinning surface
        "GHA-023":  ["UPD-1"],             # reusable workflow not SHA-pinned
        "GHA-051":  ["UPD-1"],             # services / container image unpinned
        "BB-029":   ["UPD-1"],             # step + service image not digest-pinned
        "BB-030":   ["SCA-3"],             # npm install without registry-signature verification

        # ── UPD-2: automated update tool ───────────────────────────
        "GHA-022":  ["UPD-2"],
        "GL-022":   ["UPD-2"],
        "BB-022":   ["UPD-2"],
        "ADO-022":  ["UPD-2"],
        "JF-022":   ["UPD-2"],
        "CC-022":   ["UPD-2"],

        # ── ENF-1 / ENF-2: enforce policy, break build on violation ─
        # Approval-gate and deploy-env rules evidence the "stop" step.
        "CP-001":   ["ENF-1", "ENF-2"],
        "CP-005":   ["ENF-1", "ENF-2"],
        "CD-002":   ["ENF-1"],
        "GHA-014":  ["ENF-1"],
        "GL-004":   ["ENF-1", "ENF-2"],
        "GL-029":   ["ENF-2"],
        "BB-004":   ["ENF-1"],
        "ADO-004":  ["ENF-1"],
        "JF-005":   ["ENF-1"],
        "JF-024":   ["ENF-1"],
        "CC-009":   ["ENF-1"],
        "CB-008":   ["ENF-1"],
        "BK-007":   ["ENF-1"],             # deploy block step
        "BK-013":   ["ENF-1"],             # deploy branches: filter

        # ── REB-2: digital signing of artifacts ────────────────────
        "SIGN-001": ["REB-2"],
        "SIGN-002": ["REB-2"],
        "LMB-001":  ["REB-2"],
        "CP-002":   ["REB-2"],
        "ECR-005":  ["REB-2"],
        "CA-001":   ["REB-2"],
        "GHA-006":  ["REB-2"],
        "GL-006":   ["REB-2"],
        "BB-006":   ["REB-2"],
        "ADO-006":  ["REB-2"],
        "JF-006":   ["REB-2"],
        "CC-006":   ["REB-2"],
        "GCB-009":  ["REB-2"],
        "BK-009":   ["REB-2"],
        "TKN-009":  ["REB-2"],
        "ARGO-009": ["REB-2"],

        # ── REB-3: SBOM generation ─────────────────────────────────
        "GHA-007":  ["REB-3"],
        "GL-007":   ["REB-3"],
        "BB-007":   ["REB-3"],
        "ADO-007":  ["REB-3"],
        "JF-007":   ["REB-3"],
        "CC-007":   ["REB-3"],
        "BK-010":   ["REB-3"],
        "TKN-010":  ["REB-3"],
        "ARGO-010": ["REB-3"],
        # OCI image provenance annotations are the "SBOM accompanies
        # artifact" surface for container artifacts; same shape as
        # DF-016 above.
        "OCI-001":  ["REB-3"],             # missing OCI provenance annotations
        "OCI-003":  ["REB-3"],             # missing image.created
        "OCI-005":  ["REB-3"],             # missing image.licenses
        # Helm chart provenance metadata
        "HELM-005": ["REB-3"],             # maintainers chain-of-custody
        "HELM-007": ["REB-3"],             # description empty
        "HELM-010": ["REB-3"],             # appVersion empty
        # SBOM content gaps live here too (the SBOM exists but
        # under-specifies what it should track).
        "ATTEST-003": ["REB-3"],           # SBOM floating versions
        "ATTEST-004": ["REB-3"],           # provenance lacks resolved materials
        "ATTEST-007": ["REB-3"],           # SBOM missing supplier attribution

        # ── REB-4: signed-SBOM / attested provenance ───────────────
        "GHA-024":  ["REB-4"],
        "GL-024":   ["REB-4"],
        "BB-024":   ["REB-4"],
        "ADO-024":  ["REB-4"],
        "JF-028":   ["REB-4"],
        "CC-024":   ["REB-4"],
        "BK-011":   ["REB-4"],
        "TKN-011":  ["REB-4"],
        "ARGO-011": ["REB-4"],
        # in-toto / SLSA attestation content rules: each flags the
        # provenance document itself (untrusted builder, unverifiable
        # source claim, unpinned subject, missing buildType) — these
        # are the REB-4 "attested provenance" failure modes.
        "ATTEST-001": ["REB-4"],           # untrusted SLSA builder identity
        "ATTEST-002": ["REB-4"],           # source-repo claim missing/unverifiable
        "ATTEST-005": ["REB-4"],           # in-toto subject digest unpinned
        "ATTEST-006": ["REB-4"],           # buildType missing / placeholder
        "OCI-002":    ["REB-4"],           # missing OCI build attestation

        # ── Dockerfile (image build = OSS consumption boundary) ───
        # ING-1 covers using trusted package managers / registries;
        # SCA-1 covers vuln scanning OSS; UPD-1 / UPD-2 cover
        # tracking and updating OSS; REB-2 / REB-3 cover signing
        # and SBOMs of produced artifacts.
        "DF-001":  ["ING-1", "UPD-1"],   # FROM not digest-pinned
        "DF-003":  ["ING-1", "UPD-1"],   # ADD remote no integrity
        "DF-004":  ["ING-1"],            # curl-pipe
        "DF-010":  ["UPD-1"],            # apt upgrade unpinned
        "DF-011":  ["UPD-1"],            # no cache cleanup
        "DF-016":  ["REB-3"],            # no OCI provenance labels

        # ── Helm chart deps (chart = OSS bundled into a release) ──
        "HELM-001": ["ING-1"],           # legacy v1
        "HELM-002": ["UPD-1", "REB-3"],  # missing Chart.lock digests
        "HELM-003": ["ING-1"],           # non-HTTPS dep repo
        "HELM-004": ["UPD-1"],           # version range
        "HELM-008": ["UPD-1"],           # stale Chart.lock
        "HELM-009": ["ING-1"],           # non-HTTPS home/sources
    },
)
