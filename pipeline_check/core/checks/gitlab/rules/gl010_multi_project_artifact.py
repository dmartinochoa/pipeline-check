"""GL-010, multi-project artifact ingestion must verify upstream output."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-010",
    title="Multi-project pipeline ingests upstream artifact unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step before consuming the artifact: "
        "`cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` "
        "against a manifest signed by the upstream project's release "
        "key. Only consume artifacts produced by upstream pipelines "
        "whose origin you can trust."
    ),
    docs_note=(
        "`needs: { project: ..., artifacts: true }` pulls artifacts "
        "from another project's pipeline. If that upstream project "
        "accepts MR pipelines, the artifact may have been built by "
        "attacker-controlled code."
    ),
    exploit_example=(
        "# Vulnerable: every run of ``deploy`` downloads the binary\n"
        "# from ``vendor-team/build``'s latest pipeline and executes\n"
        "# it. If that upstream project accepts MR pipelines, an MR\n"
        "# author can push a malicious binary as ``build-output``\n"
        "# and have it run inside ``deploy`` with the deploy job's\n"
        "# credentials.\n"
        "deploy:\n"
        "  stage: deploy\n"
        "  needs:\n"
        "    - project: vendor-team/build\n"
        "      job: package\n"
        "      ref: main\n"
        "      artifacts: true\n"
        "  script:\n"
        "    - ./build-output/release    # runs the upstream binary\n"
        "\n"
        "# Safe: verify a signed manifest (cosign / GPG / SHA-256\n"
        "# from a trusted publisher) before executing anything from\n"
        "# the downloaded directory. The verify step must come BEFORE\n"
        "# any step that reads the artifact.\n"
        "deploy:\n"
        "  stage: deploy\n"
        "  needs:\n"
        "    - project: vendor-team/build\n"
        "      job: package\n"
        "      ref: main\n"
        "      artifacts: true\n"
        "  script:\n"
        "    - cosign verify-attestation\n"
        "        --type slsaprovenance\n"
        "        --certificate-identity-regexp 'https://gitlab.com/vendor-team/build/'\n"
        "        --certificate-oidc-issuer 'https://gitlab.com'\n"
        "        ./build-output/release\n"
        "    - ./build-output/release"
    ),
)


def _job_verifies(job: dict[str, Any]) -> bool:
    for line in job_scripts(job):
        low = line.lower()
        if (
            "cosign verify" in low
            or "sha256sum --check" in low
            or "sha256sum -c" in low
            or "gpg --verify" in low
        ):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    any_ingesting = False
    unverified: list[str] = []
    for name, job in iter_jobs(doc):
        needs = job.get("needs")
        ingests_here = isinstance(needs, list) and any(
            isinstance(n, dict) and n.get("project") and n.get("artifacts")
            for n in needs
        )
        if not ingests_here:
            continue
        any_ingesting = True
        # The verification has to run in the same job that ingests the
        # cross-project artifact; a ``cosign verify`` in an unrelated job
        # (of a different artifact) doesn't protect this ingestion.
        if not _job_verifies(job):
            unverified.append(name)
    if not any_ingesting:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not pull artifacts from another project.",
            recommendation="No action required.", passed=True,
        )
    passed = not unverified
    desc = (
        "Multi-project artifact ingestion is paired with a verification step."
        if passed else
        f"{len(unverified)} job(s) pull artifacts from another project via "
        f"`needs: {{ project: ..., artifacts: true }}` but run no signature "
        f"or checksum verification: {', '.join(unverified)}. If the upstream "
        "project accepts MR pipelines, the artifact may have been "
        "built by attacker-controlled code."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
