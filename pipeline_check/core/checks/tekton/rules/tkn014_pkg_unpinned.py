"""TKN-014, Tekton step scripts run unpinned package installs."""
from __future__ import annotations

from ...base import (
    PKG_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    Finding,
    Location,
    Severity,
)
from ...rule import Rule
from ..base import TektonContext, doc_location, iter_step_scripts

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
        "``GL-022``), Bitbucket Pipelines / Azure DevOps / Jenkins / "
        "CircleCI / Google Cloud Build / Buildkite / Drone. Tekton "
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
    exploit_example=(
        "# Vulnerable: a Task step script with an unpinned install.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata:\n"
        "  name: build\n"
        "spec:\n"
        "  steps:\n"
        "    - name: deps\n"
        "      image: node:20\n"
        "      script: |\n"
        "        npm install\n"
        "        npm run build\n"
        "\n"
        "# Attack: `npm install` resolves dependencies fresh against the\n"
        "# registry instead of honoring the committed lockfile, so a\n"
        "# newly published malicious version (typosquat, dependency-\n"
        "# confusion, or a compromised maintainer) is pulled into the\n"
        "# build and runs in the step's pod with its mounted\n"
        "# credentials.\n"
        "\n"
        "# Safe: install from the lockfile exactly.\n"
        "        npm ci\n"
        "        npm run build"
    ),
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
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
                locations.append(doc_location(doc))
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
        locations=locations,
    )
