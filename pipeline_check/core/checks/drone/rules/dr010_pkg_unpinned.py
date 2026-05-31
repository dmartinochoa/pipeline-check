"""DR-010. Step commands run unpinned package installs."""
from __future__ import annotations

from ...base import (
    PKG_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    Finding,
    Severity,
)
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_steps,
    step_commands,
    step_label,
)

RULE = Rule(
    id="DR-010",
    title="Step commands run unpinned package installs",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Pin every package install to a lockfile or a "
        "checksum-verified version. For pip, use ``pip install "
        "--require-hashes -r requirements.txt`` or ``-r "
        "requirements.txt`` with hashes baked into the lock; "
        "``pip install <package>`` without a version pin or "
        "lockfile flag is the unsafe shape. For npm, prefer "
        "``npm ci`` over ``npm install`` so the lockfile is "
        "load-bearing. Yarn: ``yarn install --frozen-lockfile``. "
        "Bundle: ``bundle install --frozen``. Cargo / go install: "
        "always pin to a tag or commit. Do NOT use ``--trusted-"
        "host`` / ``--no-verify`` / a non-HTTPS index URL — "
        "those bypass TLS or trust validation entirely (DR-006 "
        "covers the TLS subset; this rule covers the lockfile "
        "subset)."
    ),
    docs_note=(
        "Detection reuses the cross-provider primitives "
        "``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from "
        "``checks/base.py``. The same rule pack already exists "
        "for GHA (``GHA-021`` / ``GHA-022``), GitLab "
        "(``GL-021`` / ``GL-022``), Bitbucket Pipelines / Azure DevOps / "
        "Jenkins / CircleCI / Google Cloud Build / Buildkite / Tekton "
        "/ Argo. Drone was the missing port; this closes the "
        "gap.\n\n"
        "Insecure variants matched (``PKG_INSECURE_RE``): "
        "``pip --index-url http://``, ``pip --trusted-host``, "
        "``npm --registry http://``, ``gem --source http://``, "
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
        "specific step name when this is the deliberate shape; "
        "the broader pinning policy still covers the rest of "
        "the pipeline.",
    ),
    exploit_example=(
        "# Vulnerable: an unpinned package install in a step's commands.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "steps:\n"
        "  - name: build\n"
        "    image: node:20\n"
        "    commands:\n"
        "      - npm install\n"
        "      - npm run build\n"
        "\n"
        "# Attack: `npm install` resolves dependencies fresh against the\n"
        "# registry instead of honoring the committed lockfile, so a\n"
        "# newly published malicious version (typosquat, dependency-\n"
        "# confusion, or a compromised maintainer) is pulled into the\n"
        "# build and runs with the step's credentials.\n"
        "\n"
        "# Safe: install from the lockfile exactly.\n"
        "      - npm ci\n"
        "      - npm run build"
    ),
)


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored, no "
                "shell command surface to scan."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        for cmd in step_commands(step):
            insecure = PKG_INSECURE_RE.search(cmd)
            unpinned = PKG_NO_LOCKFILE_RE.search(cmd)
            hit = insecure or unpinned
            if hit:
                kind = "insecure" if insecure else "unpinned"
                offenders.append(
                    f"steps.{step_label(step, idx)}: "
                    f"[{kind}] {hit.group(0)[:60].strip()}"
                )
                break  # one offender per step keeps the desc short
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
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
