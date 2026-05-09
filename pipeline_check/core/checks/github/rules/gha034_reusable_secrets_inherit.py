"""GHA-034, reusable workflow called with ``secrets: inherit``."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-034",
    title="Reusable workflow called with secrets: inherit",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-SECRETS"),
    cwe=("CWE-272",),
    recommendation=(
        "Replace ``secrets: inherit`` with an explicit list of just "
        "the secrets the called workflow actually needs (``secrets: "
        "{ NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``). ``inherit`` "
        "passes every secret the caller can see, including ones the "
        "downstream workflow has no business reading. A compromised "
        "or buggy reusable workflow can then exfiltrate credentials "
        "the caller never intended to share."
    ),
    docs_note=(
        "Fires on a ``jobs.<id>.uses: ...`` reference whose sibling "
        "``secrets:`` value is the literal string ``inherit``. This is "
        "distinct from GHA-025 (which gates on the *pin* of the called "
        "workflow): inheritance is a problem even when the call is SHA-"
        "pinned, because the surface a compromised callee sees is "
        "every caller secret instead of just the named ones. Explicit "
        "lists also document the contract, reviewers see exactly "
        "which secrets cross the workflow boundary."
    ),
    known_fp=(
        "Single-tenant repos that share their entire secrets set with "
        "every reusable workflow by policy. Rare in practice, "
        "explicit lists make the secret flow visible and don't add "
        "much typing. Suppress with ``.pipelinecheckignore`` and a "
        "rationale rather than disabling the rule everywhere.",
    ),
)


def _is_inherit(value: Any) -> bool:
    """True when ``value`` is the literal ``inherit`` string.

    GitHub Actions accepts ``secrets: inherit`` (string form) only;
    a mapping value (``secrets: { ... }``) is the explicit form and
    passes this rule.
    """
    return isinstance(value, str) and value.strip().lower() == "inherit"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        # Only reusable-workflow calls have ``uses:`` at the job level.
        # A regular job with ``uses:`` only inside a step's body is
        # out of scope here.
        if not isinstance(job.get("uses"), str):
            continue
        if _is_inherit(job.get("secrets")):
            offenders.append(job_id)
    passed = not offenders
    desc = (
        "No reusable-workflow call uses ``secrets: inherit``."
        if passed else
        f"{len(offenders)} reusable-workflow call(s) pass every "
        f"caller secret via ``secrets: inherit``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. "
        f"List the required secrets explicitly so a compromised "
        f"callee can't reach unrelated credentials."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
