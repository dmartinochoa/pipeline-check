"""TKN-014, Tekton step scripts run unpinned package installs."""
from __future__ import annotations

from ...base import (
    PKG_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    Finding,
    Severity,
)
from ...rule import Rule
from ..base import TektonContext, iter_step_scripts

RULE = Rule(
    id="TKN-014",
    title="Tekton step script runs unpinned package install",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Pin every package install to a lockfile or a "
        "checksum-verified version. ``npm ci`` (not ``npm "
        "install``), ``yarn install --frozen-lockfile``, "
        "``pip install -r requirements.txt --require-hashes``, "
        "``bundle install --frozen``. Don't use ``--trusted-"
        "host`` / ``--no-verify`` / a non-HTTPS index URL — "
        "those bypass TLS or trust validation entirely (TKN-008 "
        "covers the TLS subset; this rule covers the lockfile "
        "subset)."
    ),
    docs_note=(
        "Detection reuses the cross-provider primitives "
        "``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from "
        "``checks/base.py``. Same rule pack already exists for "
        "GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / "
        "``GL-022``), Bitbucket / Azure DevOps / Jenkins / "
        "CircleCI / Cloud Build / Buildkite / Drone. Tekton "
        "was a gap; this closes it. Only ``Task`` and "
        "``ClusterTask`` documents are scanned because that's "
        "where Tekton step scripts live."
    ),
    known_fp=(
        "Bootstrap-stage installs that intentionally pull "
        "latest (``apt-get install -y curl`` for a tooling "
        "image rebuild) sometimes legitimately bypass the "
        "lockfile. Suppress via ignore-file scoped to the "
        "specific step name.",
    ),
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            insecure = PKG_INSECURE_RE.search(script)
            unpinned = PKG_NO_LOCKFILE_RE.search(script)
            hit = insecure or unpinned
            if hit:
                kind = "insecure" if insecure else "unpinned"
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: [{kind}] "
                    f"{hit.group(0)[:50].strip()}"
                )
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No step script runs an insecure or unpinned package "
        "install."
        if passed else
        f"{len(offenders)} step script(s) run insecure or "
        f"unpinned package installs: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
