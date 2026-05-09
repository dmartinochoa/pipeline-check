"""GHA-037. ``actions/checkout`` persists GITHUB_TOKEN into ``.git/config``."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-037",
    title="actions/checkout persists GITHUB_TOKEN into .git/config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-4"),
    esf=("ESF-D-SECRETS", "ESF-D-CODE-INTEGRITY"),
    cwe=("CWE-522", "CWE-552"),
    recommendation=(
        "Set ``persist-credentials: false`` on every "
        "``actions/checkout`` step that doesn't need to push back "
        "to the repo. The default in v3 / v4 is ``true``, which "
        "writes the GITHUB_TOKEN into ``.git/config`` as an "
        "``http.https://github.com/.extraheader`` line. Any "
        "subsequent ``run:`` step in the same job can read it "
        "with ``git config --get http.https://github.com/."
        "extraheader`` and exfiltrate the token to a remote "
        "endpoint, even if that step's own scope is read-only. "
        "If the workflow genuinely needs to push (release "
        "publishing, doc-site deploys), do the push as the very "
        "next step and immediately follow with a checkout that "
        "sets ``persist-credentials: false`` so the token doesn't "
        "leak into later, less-trusted steps."
    ),
    docs_note=(
        "Detection fires on any step whose ``uses:`` starts with "
        "``actions/checkout@`` and whose ``with:`` block either "
        "omits ``persist-credentials`` (the unsafe default) or "
        "sets it to ``true`` explicitly.\n\n"
        "This is the failure pattern Zizmor calls *Artipacked* "
        "and the StepSecurity / harden-runner audit set tracks "
        "as ``persist-credentials``-default. Real-world exploit "
        "chains (the ``ultralytics`` 2024 RCE, multiple Mend / "
        "Snyk advisories) leverage exactly this primitive: a "
        "first checkout step persists the token, a later "
        "``run:`` step (often a build script the attacker can "
        "influence via PR contents) reads ``.git/config`` and "
        "ships the token out.\n\n"
        "Sister rule: GHA-019 catches the explicit ``echo "
        "$GITHUB_TOKEN > file`` shape; GHA-037 catches the "
        "implicit checkout-default that doesn't go through a "
        "``run:`` line at all."
    ),
    known_fp=(
        "Workflows that genuinely need ``persist-credentials: "
        "true`` to push back to the repo (a release-tag bot, a "
        "docs-deploy job, ``stefanzweifel/git-auto-commit-"
        "action``) shouldn't suppress this rule globally; "
        "instead, scope ``persist-credentials: true`` to a "
        "named step, then run the push immediately, then use a "
        "fresh ``actions/checkout`` with ``persist-credentials: "
        "false`` so the token doesn't leak into later steps. "
        "Suppress on the specific step name only when the "
        "scoped pattern is in place.",
    ),
)


def _checkout_persists(step: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(unsafe, reason)`` for an ``actions/checkout`` step.

    ``unsafe`` is True when the step omits ``persist-credentials``
    (so the v3 / v4 default of ``true`` applies) or sets it to
    ``true`` explicitly. The reason string is short, plumbed into
    the finding description.
    """
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return True, "persist-credentials not set (default: true)"
    raw = with_block.get("persist-credentials")
    if raw is None:
        return True, "persist-credentials not set (default: true)"
    # YAML lets users write ``true`` / ``"true"`` / ``True``;
    # tolerate the string form because some parsers preserve it.
    if raw is True:
        return True, "persist-credentials: true"
    if isinstance(raw, str) and raw.strip().lower() == "true":
        return True, "persist-credentials: 'true'"
    return False, ""


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            # ``owner/repo`` portion of a GitHub Actions ``uses:``
            # ref is case-insensitive (``Actions/Checkout@v4`` and
            # ``actions/checkout@v4`` resolve to the same action),
            # so lowercase before matching to catch case-variant
            # workflows.
            if not isinstance(uses, str) or not uses.lower().startswith(
                "actions/checkout@"
            ):
                continue
            unsafe, reason = _checkout_persists(step)
            if unsafe:
                step_label = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"{job_id}.{step_label}: {reason}")
    passed = not offenders
    desc = (
        "Every actions/checkout step pins persist-credentials: false."
        if passed else
        f"{len(offenders)} actions/checkout step(s) leak GITHUB_TOKEN "
        f"into .git/config: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Set ``persist-"
        f"credentials: false`` so later run: steps can't read the "
        f"token via ``git config --get http.<host>.extraheader``."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
