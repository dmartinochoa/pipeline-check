"""BK-014, step commands run unpinned package installs."""
from __future__ import annotations

from typing import Any

from ...base import (
    PKG_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    Finding,
    Severity,
)
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-014",
    title="Step commands run unpinned package installs",
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
        "those bypass TLS or trust validation entirely (BK-008 "
        "covers the TLS subset; this rule covers the lockfile "
        "subset)."
    ),
    docs_note=(
        "Detection reuses the cross-provider primitives "
        "``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from "
        "``checks/base.py``. Same rule pack already exists for "
        "GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / "
        "``GL-022``), Bitbucket Pipelines / Azure DevOps / Jenkins / "
        "CircleCI / Google Cloud Build / Drone. Buildkite was a gap; "
        "this closes it.\n\n"
        "Insecure variants (``PKG_INSECURE_RE``): ``pip "
        "--index-url http://``, ``pip --trusted-host``, ``npm "
        "--registry http://``, ``gem --source http://``, "
        "``nuget --Source http://``, ``cargo --index http://``. "
        "Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): "
        "``npm install`` (should be ``npm ci``), bare ``pip "
        "install <pkg>`` without ``-r`` or ``--require-hashes``, "
        "``yarn install`` without ``--frozen-lockfile``, "
        "``bundle install`` without ``--frozen``, ``cargo "
        "install``, ``go install`` without an ``@vN.N`` pin, "
        "``poetry install`` without ``--no-update``."
    ),
    known_fp=(
        "Bootstrap-stage installs that intentionally pull "
        "latest (``apt-get install -y curl`` for a tooling "
        "image rebuild) sometimes legitimately bypass the "
        "lockfile. Suppress via ignore-file scoped to the "
        "specific step label when this is the deliberate "
        "shape; the broader pinning policy still covers the "
        "rest of the pipeline.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            insecure = PKG_INSECURE_RE.search(cmd)
            unpinned = PKG_NO_LOCKFILE_RE.search(cmd)
            hit = insecure or unpinned
            if hit:
                kind = "insecure" if insecure else "unpinned"
                offenders.append(
                    f"{step_label(step, idx)}: [{kind}] "
                    f"{hit.group(0)[:60].strip()}"
                )
                break
    passed = not offenders
    desc = (
        "No step runs an insecure or unpinned package install."
        if passed else
        f"{len(offenders)} step(s) run insecure or unpinned "
        f"package installs: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
