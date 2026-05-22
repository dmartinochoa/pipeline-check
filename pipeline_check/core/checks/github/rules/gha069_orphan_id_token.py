"""GHA-069. ``id-token: write`` granted without an OIDC-consumer step.

zizmor proposal #1968 (``orphan-id-token``). A job that grants
``id-token: write`` is asking GitHub's OIDC provider to mint a
fresh token on every step's behalf. Workflows typically need this
permission for one of two reasons:

1. **Cloud-credentials exchange.** ``aws-actions/configure-aws-
   credentials`` (or the GCP / Azure equivalents) trades the OIDC
   token for short-lived cloud credentials.
2. **Trusted publishing / signing.** ``pypa/gh-action-pypi-publish``
   (PEP 740), ``docker/build-push-action`` with provenance /
   sbom, ``slsa-framework/slsa-github-generator``, and similar
   publish-with-provenance actions exchange the OIDC token for
   Sigstore signing credentials.

When the ``id-token: write`` scope is granted but no step in the
job consumes it, the workflow is minting tokens with zero benefit
and additional risk surface. Any later step that gets compromised
(supply-chain attack on an action, ``run:`` injection,
``setup-*`` action escalation) can request an OIDC token and
exchange it through a relay attacker controls. The scope is
permission surface with no value, the canonical least-privilege
violation.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-069",
    title="``id-token: write`` granted without an OIDC-consumer step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-272", "CWE-269"),  # Least Privilege Violation
    recommendation=(
        "Drop ``id-token: write`` from the job's ``permissions:`` "
        "block when no step exchanges the OIDC token for cloud "
        "credentials, signs an artifact, or publishes with "
        "attestation. If the workflow gains an OIDC consumer "
        "later (a new ``aws-actions/configure-aws-credentials`` "
        "step, a ``pypa/gh-action-pypi-publish`` upgrade), restore "
        "the scope at the job level rather than the workflow "
        "level. Job-level grants minimize the window in which the "
        "scope is in effect."
    ),
    docs_note=(
        "Fires when both conditions hold:\n\n"
        "1. The job has ``id-token: write`` (either declared on "
        "the job's own ``permissions:`` block, or inherited from a "
        "workflow-level block that the job didn't override).\n"
        "2. None of the job's steps invokes a known OIDC-token "
        "consumer (see ``_OIDC_CONSUMER_PREFIXES`` below).\n\n"
        "The consumer list covers the canonical cloud-credentials "
        "actions (``aws-actions/configure-aws-credentials``, "
        "``azure/login``, ``google-github-actions/auth``), the "
        "trusted-publishing pack (``pypa/gh-action-pypi-publish``, "
        "``rubygems/release-gem``, ``crates-io/publish-action``), "
        "and the Sigstore signing pack (``sigstore/cosign-installer``, "
        "``sigstore/gh-action-sigstore-python``,\n"
        "``slsa-framework/slsa-github-generator``,\n"
        "``actions/attest-build-provenance``,\n"
        "``actions/attest-sbom``, and the\n"
        "``docker/build-push-action`` with ``provenance:`` /\n"
        "``sbom:`` / ``attestations:`` set). When a workflow adds a "
        "new consumer not in this list, file an issue so the rule "
        "can recognize it."
    ),
    known_fp=(
        "Composite actions whose body consumes the OIDC token but "
        "whose entry point is named in a workflow that wouldn't "
        "otherwise match the consumer list. The local composite-"
        "action discovery path (``GitHubContext.from_path``) "
        "synthesizes those bodies as ``__composite__`` jobs, so "
        "the rule sees the inner steps. Suppress per-job via "
        "ignore-file when a workflow consumes the OIDC token via "
        "a third-party action this rule's consumer list doesn't "
        "name yet.",
    ),
    incident_refs=(
        "zizmor proposal #1968 (orphan-id-token audit): "
        "https://github.com/zizmorcore/zizmor/issues/1968",
    ),
    exploit_example=(
        "# Vulnerable: ``id-token: write`` granted, no step\n"
        "# consumes the token. Any later step that's compromised\n"
        "# (action upstream takeover, run injection, cache\n"
        "# poisoning) can request an OIDC token and exchange it\n"
        "# through an attacker relay.\n"
        "permissions:\n"
        "  contents: read\n"
        "  id-token: write\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: drop the unused scope. Restore it only when an\n"
        "# OIDC consumer step is added.\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh"
    ),
)


#: Known OIDC-token consumers. A step matching any of these prefixes
#: (case-insensitive, prefix-match on the ``uses:`` value before
#: ``@``) prevents the job from being flagged. The list is curated;
#: missing consumers should be added when discovered.
_OIDC_CONSUMER_PREFIXES: tuple[str, ...] = (
    # Cloud-credentials
    "aws-actions/configure-aws-credentials",
    "azure/login",
    "google-github-actions/auth",
    # Trusted publishing (PEP 740, etc.)
    "pypa/gh-action-pypi-publish",
    "rubygems/release-gem",
    "crates-io/publish-action",
    "release-drafter/release-drafter",
    # Sigstore signing pack
    "sigstore/cosign-installer",
    "sigstore/gh-action-sigstore-python",
    "slsa-framework/slsa-github-generator",
    "actions/attest-build-provenance",
    "actions/attest-sbom",
    "actions/attest",
    # docker/build-push-action when its ``with:`` enables
    # provenance / sbom / attestations consumes the OIDC token
    # for Sigstore signing. Detected via with-key inspection in
    # ``_step_consumes_id_token`` rather than this prefix list.
)

#: ``docker/build-push-action`` consumes the OIDC token only when one
#: of these ``with:`` keys is truthy. ``provenance: false`` /
#: ``sbom: false`` / ``attestations: false`` are explicit opt-outs and
#: do NOT count as consumers.
_DOCKER_OIDC_WITH_KEYS: tuple[str, ...] = (
    "provenance",
    "sbom",
    "attestations",
)


def _job_has_id_token_write(
    job: dict[str, Any], workflow: dict[str, Any],
) -> bool:
    """Return True if *job* effectively has ``id-token: write``.

    A job-level ``permissions:`` block REPLACES the workflow-level
    block (GitHub's permission semantics). Without a job-level
    block, the job inherits the workflow's permissions. Both the
    explicit ``id-token: write`` shape and the ``permissions:
    write-all`` umbrella grant count.
    """
    job_perms = job.get("permissions")
    if isinstance(job_perms, dict):
        return job_perms.get("id-token") == "write"
    if isinstance(job_perms, str):
        return job_perms == "write-all"
    wf_perms = workflow.get("permissions")
    if isinstance(wf_perms, dict):
        return wf_perms.get("id-token") == "write"
    if isinstance(wf_perms, str):
        return wf_perms == "write-all"
    return False


def _step_consumes_id_token(step: dict[str, Any]) -> bool:
    """Return True when *step* legitimately consumes an OIDC token."""
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    action_ref = uses.split("@", 1)[0].strip().lower()
    if any(
        action_ref.startswith(prefix.lower())
        for prefix in _OIDC_CONSUMER_PREFIXES
    ):
        return True
    # ``docker/build-push-action`` is conditional on ``with:`` keys.
    if action_ref.startswith("docker/build-push-action"):
        with_block = step.get("with")
        if isinstance(with_block, dict):
            for key in _DOCKER_OIDC_WITH_KEYS:
                value = with_block.get(key)
                if value is None:
                    continue
                # Treat any non-false-ish value as consumer.
                if isinstance(value, bool):
                    if value:
                        return True
                elif isinstance(value, str):
                    if value.strip().lower() not in ("false", "off", "no", "0"):
                        return True
                else:
                    return True
    return False


def _job_has_oidc_consumer(job: dict[str, Any]) -> bool:
    """Return True when at least one step in *job* consumes an OIDC token."""
    for step in iter_steps(job):
        if _step_consumes_id_token(step):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        if not _job_has_id_token_write(job, doc):
            continue
        if _job_has_oidc_consumer(job):
            continue
        offenders.append(job_id)
    passed = not offenders
    desc = (
        "Every job with ``id-token: write`` invokes an OIDC consumer."
        if passed else
        f"{len(offenders)} job(s) grant ``id-token: write`` with no "
        f"OIDC-consumer step: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. The scope mints "
        f"tokens for no benefit and any later compromised step can "
        f"request and relay them."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(offenders),
    )
