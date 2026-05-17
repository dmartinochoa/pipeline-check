"""Token catalogs and blob-level detection helpers.

These live separate from :mod:`base` because they're cross-provider
content heuristics, not framework primitives. Rule files that just
need "does this workflow sign?" / "does this workflow scan for
vulns?" import from here; the rest of ``base.py`` stays focused on
the check class, finding dataclass, and severity/confidence enums.
"""
from __future__ import annotations

from typing import Any

from .blob import blob_lower

# Case-insensitive substring tokens; a workflow passes the signing check if
# any token appears anywhere in its string content.
SIGN_TOKENS = (
    "cosign", "sigstore", "slsa-github-generator",
    "slsa-framework/slsa-", "notation-sign",
)

# SBOM tokens: direct hits pass on their own. Trivy only passes when combined
# with "sbom" or "cyclonedx" in the same blob.
SBOM_DIRECT_TOKENS = (
    "cyclonedx", "syft", "anchore/sbom-action",
    "spdx-sbom-generator", "microsoft/sbom-tool",
)

# Provenance tokens, narrower than SIGN_TOKENS. SLSA Build L3 requires
# an in-toto attestation produced by a hardened builder, not just a
# signed artifact. Anything here provably produces a provenance
# attestation; ``cosign sign`` alone does NOT (it signs the artifact
# but doesn't emit an in-toto statement describing how it was built).
PROVENANCE_TOKENS = (
    "slsa-github-generator",        # GHA. SLSA Level 3 builder
    "slsa-framework/slsa-",          # SLSA GitHub org actions
    "actions/attest-build-provenance",  # GHA, native build-provenance action
    "actions/attest@",               # GHA, generic attest action
    "cosign attest",                 # sigstore attestation (distinct from `cosign sign`)
    "witness run",                   # testifysec/witness attestor
    "in-toto-attestation",           # in-toto library/CLI
    "intoto.jsonl",                  # standard provenance filename
    "provenance.intoto",             # common provenance output name
)


# Tokens that indicate a workflow produces deployable artifacts.
# Used by the signing/SBOM/vuln-scan checks to suppress false positives
# on lint/test-only workflows that don't produce anything to sign or scan.
#
# Bare-word tokens like ``publish`` / ``deploy`` / ``release`` were removed
# because they false-positived on workflows whose only mention of those
# verbs came from branch names ("release-please"), PR titles ("Cherry-
# pick from release"), or step names ("Deploy preview"). Each entry below
# is either an executable command shape (``gh release create``) or a
# concrete reusable-action ``uses:`` ref (``softprops/action-gh-release``)
# so that mere prose mention of "release" or "deploy" no longer trips the
# downstream signing / SBOM / SLSA rules.
_ARTIFACT_TOKENS = (
    # Container builds + pushes
    "docker push", "docker build",
    "docker/build-push-action",
    "docker/metadata-action",
    "buildah push", "podman push",
    # GitHub Actions artifact + release flows. ``upload-artifact@`` is
    # anchored with ``@`` so ``actions/upload-pages-artifact@<ref>`` (a
    # docs/Pages site, not a software artifact) doesn't match.
    "actions/upload-artifact@",
    "softprops/action-gh-release",
    "actions/create-release",
    "actions/upload-release-asset",
    "gh release create", "gh release upload",
    # Jenkins
    "archiveartifacts",
    # CircleCI
    "store_artifacts", "persist_to_workspace",
    # Cloud deploys
    "aws s3 cp", "aws s3 sync",
    "aws cloudformation deploy",
    "aws ecs update-service",
    "aws deploy create-deployment",
    "atlassian/aws-s3-deploy",      # Bitbucket Pipelines pipe
    "atlassian/aws-ecs-deploy",     # Bitbucket Pipelines pipe
    "aws-cli/setup-and-deploy",     # CircleCI orb command
    "kubectl apply", "helm upgrade", "helm install",
    "terraform apply",
    "gcloud app deploy", "gcloud run deploy", "gcloud functions deploy",
    "az webapp deploy", "az functionapp deployment",
    # Language package registries
    "twine upload", "cargo publish", "gem push",
    "npm publish", "yarn publish", "pnpm publish",
    "pypa/gh-action-pypi-publish",
    "mvn deploy", "gradle publish",
)


# Substrings the artifact heuristic must ignore: GitHub Pages
# deployments embed the verbs ``deploy`` / ``publish`` in canonical
# action names (``actions/deploy-pages``, ``actions/upload-pages-
# artifact``) but ship a static site, not a software artifact, and
# don't need cosign / SBOM / SLSA-attest. Pre-strip these zones from
# the blob before the bare-token match runs so the catch-all tokens
# above don't bleed into Pages-only workflows.
_ARTIFACT_TOKEN_EXCLUDE_ZONES = (
    "actions/deploy-pages",
    "actions/upload-pages-artifact",
    "actions/configure-pages",
)


#: Vulnerability scanning tool tokens, same detection pattern as
#: ``has_signing`` / ``has_sbom``.
VULN_SCAN_TOKENS = (
    "trivy ", "grype ", "snyk ", "npm audit", "yarn audit",
    "safety check", "pip-audit", "osv-scanner", "govulncheck",
    "cargo audit", "bundler-audit", "bundle audit",
    "docker scout", "codeql-action", "github/codeql-action",
    "semgrep ", "bandit ", "checkov ", "tfsec ",
)


def produces_artifacts(doc: Any) -> bool:
    """Return True when the workflow appears to produce deployable artifacts.

    Heuristic: if no artifact-production token appears anywhere in the
    workflow's string content, the workflow is likely lint/test-only and
    the signing/SBOM/vulnerability-scanning checks should not fire.

    Pages-only workflows are recognized structurally and return False
    even when the blob contains the substring ``deploy`` (which would
    otherwise match via step names like "Deploy to GitHub Pages" or
    step ids like ``id: deployment``). The presence of
    ``actions/deploy-pages`` is the unambiguous signal: that action
    can only deploy a static GitHub Pages site, never a software
    artifact, and the rest of the workflow's verbiage about
    "deployment" is incidental to that.

    The substring zones are also pre-stripped so a workflow that
    *also* has a real artifact-producing step (e.g. publishes a
    package AND has Pages docs) still returns True via the genuine
    artifact token while the Pages action's own substrings can't
    contribute.
    """
    blob = blob_lower(doc)
    if "actions/deploy-pages" in blob:
        return False
    for zone in _ARTIFACT_TOKEN_EXCLUDE_ZONES:
        blob = blob.replace(zone, "")
    return any(tok in blob for tok in _ARTIFACT_TOKENS)


def has_signing(doc: Any) -> bool:
    blob = blob_lower(doc)
    return any(tok in blob for tok in SIGN_TOKENS)


def has_provenance(doc: Any) -> bool:
    """Return True when the workflow emits an in-toto/SLSA provenance attestation.

    Distinct from :func:`has_signing`, a workflow that only runs
    ``cosign sign`` signs the artifact but doesn't produce a
    provenance statement describing *how* the artifact was built.
    SLSA Build Level 3 requires the latter.

    Note: PyPI trusted publishing's PEP 740 attestations are also
    valid provenance, but the ``with: { attestations: true }`` opt-in
    is a structural signal (YAML parses ``true`` as a bool, not a
    string), the per-rule check in
    ``checks/github/rules/gha024_slsa_provenance.py`` covers that
    case directly.
    """
    blob = blob_lower(doc)
    return any(tok in blob for tok in PROVENANCE_TOKENS)


def has_sbom(doc: Any) -> bool:
    blob = blob_lower(doc)
    if any(tok in blob for tok in SBOM_DIRECT_TOKENS):
        return True
    if "trivy" in blob and ("sbom" in blob or "cyclonedx" in blob):
        return True
    return False


def has_vuln_scanning(doc: Any) -> bool:
    """Return True if the pipeline invokes a known vulnerability scanner."""
    blob = blob_lower(doc)
    return any(tok in blob for tok in VULN_SCAN_TOKENS)
