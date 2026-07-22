"""ARGO-015. Input artifact pulls from an insecure (non-HTTPS) URL."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    ArgoContext,
    doc_location,
    iter_templates,
    template_name,
    workflow_spec,
)

RULE = Rule(
    id="ARGO-015",
    title="Input artifact pulls from an insecure (non-HTTPS) URL",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS", "ESF-D-COMMS-INTEGRITY"),
    cwe=("CWE-319", "CWE-829"),
    recommendation=(
        "Pull every input artifact over HTTPS. Replace ``http://`` "
        "with ``https://`` in any ``http.url:`` block, and use "
        "``https://`` git remote URLs instead of ``git://``, "
        "``ssh://``-without-key-pinning, or anonymous-cleartext "
        "access. Plain HTTP fetches let any on-path attacker swap "
        "the artifact bytes for a different payload, and Argo "
        "will execute whatever bytes arrive without an integrity "
        "check unless the artifact source provides one (S3 + "
        "checksum, OCI + digest). If the artifact source genuinely "
        "doesn't ship over HTTPS (a legacy internal mirror), wrap "
        "it in a CDN or proxy that adds TLS, then pin the artifact "
        "by checksum on the consuming side."
    ),
    docs_note=(
        "Argo Workflows resolves input artifacts before the "
        "template's container starts. The source can be ``http``, "
        "``git``, ``s3``, ``gcs``, ``azure``, ``hdfs``, ``oss``, "
        "or ``raw``. The rule fires when:\n\n"
        "- ``http.url`` starts with ``http://`` (cleartext fetch)\n"
        "- ``git.repo`` starts with ``git://`` (legacy unauthenticated "
        "git protocol, no integrity)\n"
        "- ``s3.endpoint`` is set with ``insecure: true`` (explicit "
        "TLS bypass)\n\n"
        "Other artifact sources are skipped, an OCI / S3 / GCS pull "
        "carries its own integrity / signing posture that lives "
        "outside this rule."
    ),
    known_fp=(
        "Local-mirror development workflows occasionally use "
        "``http://`` against an internal registry that's only "
        "reachable from a private network. The integrity guarantee "
        "still relies on network isolation rather than transport "
        "encryption; suppress on the specific template name when "
        "this is the deliberate shape.",
    ),
    exploit_example=(
        "# Vulnerable: ``http://`` artifact URL means Argo fetches\n"
        "# the input over plaintext. Any on-path attacker (compromised\n"
        "# corporate proxy, malicious VPN, BGP hijack on the internal\n"
        "# mirror) substitutes the dataset; Argo executes whatever\n"
        "# bytes arrive. ``git://`` is the same shape — legacy\n"
        "# unauthenticated git with no integrity check.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  templates:\n"
        "    - name: process\n"
        "      inputs:\n"
        "        artifacts:\n"
        "          - name: dataset\n"
        "            path: /input/dataset.tar.gz\n"
        "            http:\n"
        "              url: http://internal-mirror.example.com/datasets/v1.tar.gz\n"
        "\n"
        "# Safe: HTTPS for the fetch. For high-value artifacts, also\n"
        "# verify a producer-signed checksum after download (the\n"
        "# artifact source providing an integrity guarantee, e.g.\n"
        "# S3 + ETag or an OCI artifact + content digest).\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  templates:\n"
        "    - name: process\n"
        "      inputs:\n"
        "        artifacts:\n"
        "          - name: dataset\n"
        "            path: /input/dataset.tar.gz\n"
        "            http:\n"
        "              url: https://internal-mirror.example.com/datasets/v1.tar.gz"
    ),
)


def _scan_artifact(art: dict[str, Any]) -> str | None:
    """Return a short reason if *art* is an insecure artifact source."""
    http = art.get("http")
    if isinstance(http, dict):
        url = http.get("url")
        if isinstance(url, str) and url.lower().startswith("http://"):
            return f"http.url={url[:60]}"
    git = art.get("git")
    if isinstance(git, dict):
        repo = git.get("repo")
        if isinstance(repo, str) and repo.lower().startswith("git://"):
            return f"git.repo={repo[:60]}"
    s3 = art.get("s3")
    if isinstance(s3, dict) and s3.get("insecure") is True:
        endpoint = str(s3.get("endpoint") or "")[:40]
        return f"s3 insecure: {endpoint}"
    return None


def _template_artifacts(tmpl: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    inputs = tmpl.get("inputs")
    if isinstance(inputs, dict):
        arts = inputs.get("artifacts")
        if isinstance(arts, list):
            out.extend(a for a in arts if isinstance(a, dict))
    return out


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for art in _template_artifacts(tmpl):
                reason = _scan_artifact(art)
                if reason:
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)} "
                        f"artifact[{art.get('name', '?')}]: {reason}"
                    )
                    locations.append(doc_location(doc, tmpl))
        # Workflow-global input artifacts (``spec.arguments.artifacts``)
        # are a valid Argo source location too, not just template inputs.
        arguments = workflow_spec(doc).get("arguments")
        global_arts = arguments.get("artifacts") if isinstance(arguments, dict) else None
        if isinstance(global_arts, list):
            for art in (a for a in global_arts if isinstance(a, dict)):
                reason = _scan_artifact(art)
                if reason:
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"spec.arguments artifact[{art.get('name', '?')}]: "
                        f"{reason}"
                    )
                    locations.append(doc_location(doc))
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No template input artifact pulls over an insecure URL."
        if passed else
        f"{len(offenders)} input artifact(s) pull over an insecure "
        f"URL: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
