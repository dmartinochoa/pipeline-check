"""ARGO-014, Argo template scripts run unpinned package installs."""
from __future__ import annotations

from typing import Any

from ...base import (
    PKG_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    Finding,
    Severity,
)
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-014",
    title="Argo template script runs unpinned package install",
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
        "those bypass TLS or trust validation entirely "
        "(ARGO-008 covers the TLS subset; this rule covers "
        "the lockfile subset)."
    ),
    docs_note=(
        "Detection reuses the cross-provider primitives "
        "``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from "
        "``checks/base.py``. Same rule pack already exists "
        "for GHA (``GHA-021`` / ``GHA-022``), GitLab "
        "(``GL-021`` / ``GL-022``), Bitbucket Pipelines / Azure DevOps "
        "/ Jenkins / CircleCI / Google Cloud Build / Buildkite / "
        "Tekton / Drone. Argo was a gap; this closes it.\n\n"
        "Walks ``script.source`` plus joined ``container.args`` "
        "/ ``container.command`` text per template. Steps and "
        "tasks across DAG / steps templates are equally in "
        "scope because they all reduce to a container with a "
        "shell payload."
    ),
    known_fp=(
        "Bootstrap-stage installs that intentionally pull "
        "latest (``apt-get install -y curl`` for a tooling "
        "image rebuild) sometimes legitimately bypass the "
        "lockfile. Suppress via ignore-file scoped to the "
        "specific template name.",
    ),
    exploit_example=(
        "# Vulnerable: a script template installs dependencies with no\n"
        "# lockfile or hash pinning.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: { name: ci }\n"
        "spec:\n"
        "  entrypoint: test\n"
        "  templates:\n"
        "    - name: test\n"
        "      script:\n"
        "        image: node@sha256:abc123...\n"
        "        command: [sh]\n"
        "        source: |\n"
        "          npm install\n"
        "          npm test\n"
        "\n"
        "# Attack: `npm install` resolves the `^` / `~` ranges in\n"
        "# package.json against the live registry at run time instead\n"
        "# of the committed lockfile, so a freshly published malicious\n"
        "# patch of a transitive dependency (the event-stream /\n"
        "# Shai-Hulud shape) lands in the workflow pod and its\n"
        "# postinstall runs with the workflow's credentials.\n"
        "\n"
        "# Safe: install the locked set with integrity checks.\n"
        "      script:\n"
        "        image: node@sha256:abc123...\n"
        "        command: [sh]\n"
        "        source: |\n"
        "          npm ci\n"
        "          npm test"
    ),
)


def _container_text(container: dict[str, Any]) -> str:
    parts: list[str] = []
    src = container.get("source")
    if isinstance(src, str):
        parts.append(src)
    for key in ("command", "args"):
        v = container.get(key)
        if isinstance(v, list):
            parts.extend(s for s in v if isinstance(s, str))
        elif isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                blob = _container_text(container)
                if not blob:
                    continue
                insecure = PKG_INSECURE_RE.search(blob)
                unpinned = PKG_NO_LOCKFILE_RE.search(blob)
                hit = insecure or unpinned
                if hit:
                    kind = "insecure" if insecure else "unpinned"
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: [{kind}] "
                        f"{hit.group(0)[:50].strip()}"
                    )
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No template script runs an insecure or unpinned "
        "package install."
        if passed else
        f"{len(offenders)} template script(s) run insecure or "
        f"unpinned package installs: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
