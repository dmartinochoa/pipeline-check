"""GHA-039. ``services.<x>.credentials`` / ``container.credentials`` literal."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-039",
    title="services / container credentials embedded as literal in workflow",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Move every ``services.<name>.credentials.username`` / "
        "``credentials.password`` value (and the same field on a "
        "job-level ``container:`` block) out of the workflow YAML "
        "and into a repository or environment secret. Reference "
        "the secret via ``${{ secrets.NAME }}`` from the same "
        "credentials block. Anything written as a literal is "
        "permanently visible in every fork of the repo, every "
        "build log that prints the runner's start banner, and "
        "every cached job summary, so the credential must be "
        "treated as compromised on the spot. The fix is the "
        "rotation, plus the secret reference, plus a check that "
        "no other workflow keeps the literal pattern."
    ),
    docs_note=(
        "GitHub Actions accepts a ``credentials:`` map on both "
        "the job-level ``container:`` block (the runner image) "
        "and on each ``services.<name>:`` entry (sidecar "
        "containers). The map is the documented way to pull a "
        "private image from a registry that requires auth, and "
        "it expects ``${{ secrets.* }}`` references for both "
        "fields.\n\n"
        "GHA-008 scans the workflow for credential **patterns** "
        "(AWS access keys, JWTs, Slack tokens, etc.) but doesn't "
        "trip on a plain password like ``hunter2`` or a "
        "registry username like ``ci-deploy-bot``. GHA-039 "
        "catches them by **position**: any literal value in a "
        "``credentials.username`` / ``credentials.password`` "
        "field is by definition a leaked credential, regardless "
        "of its shape. Closes parity with Zizmor's "
        "``hardcoded-container-credentials`` rule."
    ),
    known_fp=(
        "Workflows that legitimately use a public anonymous "
        "registry mirror occasionally hardcode ``username: "
        "anonymous`` / ``password: \"\"`` for clarity. Both "
        "shapes are filtered out automatically (empty / "
        "whitespace-only values, plus the literal "
        "``anonymous`` username), but if your fixture uses "
        "another sentinel for anonymous access, suppress the "
        "specific job/service in the ignore-file rather than "
        "the rule globally.",
    ),
)


# Reference shapes the rule treats as safe:
#   ``${{ secrets.NAME }}``           - canonical secrets reference
#   ``${{ vars.NAME }}``               - non-secret config var, public anyway
#   ``${{ inputs.NAME }}``             - workflow_call passthrough
#   ``${{ env.NAME }}``                - resolved at run time from env
#   ``${{ github.actor }}`` / similar  - runtime-resolved metadata
_SAFE_REFERENCE_RE = re.compile(r"\$\{\{\s*[A-Za-z_][\w.]*\s*\}\}")

# Documented sentinels that mean "no auth", not a real credential.
_ANONYMOUS_USERNAMES: frozenset[str] = frozenset({
    "anonymous", "guest", "public", "noauth",
})


def _is_safe(value: Any, *, field: str) -> bool:
    """True when *value* doesn't represent a leaked credential."""
    if value is None:
        return True
    if not isinstance(value, str):
        # Numbers / booleans in a credentials field are always
        # garbage, treat them as unsafe so the workflow author has
        # to rotate / fix.
        return False
    stripped = value.strip()
    if not stripped:
        return True
    if _SAFE_REFERENCE_RE.fullmatch(stripped):
        return True
    # Mid-string ``${{ secrets.X }}`` references are also safe in
    # practice, the build log won't print the secret bytes. The
    # fullmatch above missed them only because the YAML loader
    # may concatenate, e.g. ``prefix-${{ secrets.X }}``.
    if _SAFE_REFERENCE_RE.search(stripped) and "secrets." in stripped:
        return True
    if (
        field == "username"
        and stripped.lower() in _ANONYMOUS_USERNAMES
    ):
        return True
    return False


def _scan_credentials(node: Any, breadcrumb: str) -> list[str]:
    """Return offender labels when *node*'s ``credentials:`` block
    embeds a literal username / password.
    """
    if not isinstance(node, dict):
        return []
    creds = node.get("credentials")
    if not isinstance(creds, dict):
        return []
    out: list[str] = []
    for field in ("username", "password"):
        if field not in creds:
            continue
        if not _is_safe(creds.get(field), field=field):
            out.append(f"{breadcrumb}.credentials.{field}")
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        offenders.extend(
            _scan_credentials(
                job.get("container"),
                breadcrumb=f"jobs.{job_id}.container",
            )
        )
        services = job.get("services")
        if isinstance(services, dict):
            for svc_name, svc in services.items():
                offenders.extend(
                    _scan_credentials(
                        svc,
                        breadcrumb=f"jobs.{job_id}.services.{svc_name}",
                    )
                )
    passed = not offenders
    desc = (
        "No services / container credentials block holds a literal "
        "value, every entry resolves to ``${{ secrets.* }}`` or "
        "is empty."
        if passed else
        f"{len(offenders)} credentials field(s) embed a literal "
        f"value: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The credential is "
        f"visible in every fork and every build log; rotate and "
        f"replace with ``${{{{ secrets.NAME }}}}``."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
