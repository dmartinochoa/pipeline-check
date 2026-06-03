"""GHA-115. ``id-token: write`` granted workflow-wide instead of job-scoped.

Defense-in-depth from the npm "trusted publishing, untrusted branch"
writeup. When ``id-token: write`` sits on the **top-level**
``permissions:`` block, every job that doesn't override its permissions
inherits the right to mint an OIDC token. If only a subset of jobs
actually consume the token (a publish or cloud-credentials job), the
other inheriting jobs (build, test, lint) carry a publish-capable mint
right they never use. A supply-chain compromise of one of those jobs (a
poisoned action, a ``run:`` injection) can then request an OIDC token
and relay it, even though that job had no business minting one.

The least-privilege fix is to push ``id-token: write`` down to the
specific job that consumes it, so the mint right exists only where it's
needed and only for that job's duration.

Pairs with:

* **GHA-069** (orphan ``id-token``) fires when a job grants the scope
  and *no* step consumes it (granted-but-unused). GHA-115 is the
  granted-too-broadly case: the scope is consumed somewhere, but the
  workflow-level grant hands it to jobs that don't need it.
* **GHA-113** / **GHA-114** are the publish-side rules; GHA-115 narrows
  the blast radius of the token those rules are about.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from .gha069_orphan_id_token import _job_has_oidc_consumer

RULE = Rule(
    id="GHA-115",
    title="``id-token: write`` granted workflow-wide instead of job-scoped",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-272", "CWE-269"),
    recommendation=(
        "Move ``id-token: write`` off the workflow-level "
        "``permissions:`` block and onto only the job(s) that consume "
        "the OIDC token (the publish / cloud-credentials job):\n\n"
        "- Set the workflow-level ``permissions:`` to what the other "
        "jobs actually need (often ``contents: read``), and add a "
        "job-level ``permissions: { id-token: write, ... }`` to the "
        "consuming job only.\n"
        "- A workflow-level grant gives every job that doesn't override "
        "its permissions the right to mint an OIDC token, so a "
        "compromised build / test / lint job can request a "
        "publish-capable token it never needed and relay it.\n"
        "- Job-level grants also minimize the window in which the mint "
        "right is in effect (see GHA-069)."
    ),
    docs_note=(
        "Fires when all three hold:\n\n"
        "1. The workflow's **top-level** ``permissions:`` block grants "
        "``id-token: write`` (or ``permissions: write-all``).\n"
        "2. At least one job consumes the OIDC token (a known consumer "
        "step, the same list GHA-069 uses: cloud-credentials actions, "
        "trusted-publisher actions, the Sigstore signing pack, "
        "``docker/build-push-action`` with provenance / sbom).\n"
        "3. At least one job inherits the workflow-level grant (it "
        "declares no ``permissions:`` block of its own, so the "
        "job-level block does not REPLACE the inherited one) AND does "
        "NOT consume the token.\n\n"
        "The conjunction is the granted-too-broadly shape: the scope is "
        "used somewhere, so dropping it entirely (GHA-069) is wrong, "
        "but the workflow-level grant hands a publish-capable mint right "
        "to jobs that don't need it. When NO job consumes the token, "
        "GHA-069 covers the orphan case instead. When every inheriting "
        "job consumes it, the grant is not over-broad and the rule "
        "stays silent. A consuming job that declares its own "
        "``id-token: write`` does not need the workflow-level grant, so "
        "the workflow-level grant is still flagged if any other job "
        "inherits it without consuming.\n\n"
        "Defaults to MEDIUM confidence: the over-broad determination "
        "depends on recognizing every job's OIDC consumer, and a "
        "consumer reached through an action the shared consumer list "
        "doesn't name yet can make a consuming job look non-consuming."
    ),
    known_fp=(
        "A workflow where every inheriting job legitimately consumes "
        "the OIDC token (e.g. a matrix of publish jobs) is not flagged. "
        "A consumer reached through a third-party action this rule's "
        "list doesn't recognize yet can make a consuming job look "
        "non-consuming, over-flagging it as over-broad. Extend the "
        "consumer list (shared with GHA-069) or suppress per-workflow "
        "via ``--ignore-file``.",
    ),
    incident_refs=(
        "Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, "
        "Untrusted Branch', 2026), defense-in-depth item: scope "
        "``id-token: write`` to the publish job so a compromised "
        "sibling job cannot mint a publish-capable token: "
        "https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
    ),
    exploit_example=(
        "# Vulnerable: ``id-token: write`` is granted workflow-wide, so\n"
        "# the build job (which never touches OIDC) inherits the right\n"
        "# to mint a publish-capable token. A compromised build step\n"
        "# can request and relay one.\n"
        "permissions:\n"
        "  contents: read\n"
        "  id-token: write\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci --ignore-scripts && npm run build\n"
        "  publish:\n"
        "    needs: build\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: pypa/gh-action-pypi-publish@<sha>\n"
        "\n"
        "# Safe: the workflow-level grant is dropped; only the publish\n"
        "# job that consumes the token declares ``id-token: write``.\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci --ignore-scripts && npm run build\n"
        "  publish:\n"
        "    needs: build\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: pypa/gh-action-pypi-publish@<sha>"
    ),
)


def _workflow_grants_id_token(doc: dict[str, Any]) -> bool:
    """Return True if the workflow-level ``permissions:`` grants id-token."""
    perms = doc.get("permissions")
    if isinstance(perms, dict):
        return perms.get("id-token") == "write"
    if isinstance(perms, str):
        return perms == "write-all"
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _workflow_grants_id_token(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "The workflow-level ``permissions:`` block does not grant "
                "``id-token: write``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    any_consumer = False
    # Jobs that inherit the workflow grant (no own ``permissions:`` block)
    # but never consume the token: the over-broad exposure.
    over_broad: list[str] = []
    for job_id, job in iter_jobs(doc):
        consumes = _job_has_oidc_consumer(job)
        any_consumer = any_consumer or consumes
        inherits = "permissions" not in job
        if inherits and not consumes:
            over_broad.append(job_id)

    # No consumer anywhere -> the whole grant is orphaned; GHA-069 owns
    # that. Every inheriting job consumes -> the grant is not over-broad.
    passed = not (any_consumer and over_broad)
    desc = (
        "Every job that inherits the workflow-level ``id-token: write`` "
        "consumes the OIDC token (or the scope is unused, which GHA-069 "
        "covers)."
        if passed else
        f"``id-token: write`` is granted workflow-wide, but "
        f"{len(over_broad)} job(s) inherit the mint right without "
        f"consuming the token: {', '.join(over_broad[:5])}"
        f"{'…' if len(over_broad) > 5 else ''}. Scope ``id-token: "
        f"write`` to the consuming job(s) so a compromised sibling job "
        f"can't mint a publish-capable token."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=() if passed else tuple(over_broad),
    )
