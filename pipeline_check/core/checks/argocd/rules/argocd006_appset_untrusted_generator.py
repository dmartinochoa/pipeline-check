"""ARGOCD-006. ApplicationSet PR/SCM generator without project whitelist."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applicationsets

RULE = Rule(
    id="ARGOCD-006",
    title="Argo CD ApplicationSet PR/SCM generator without project allowlist",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-1357",),
    recommendation=(
        "When using ``pullRequest`` or ``scmProvider`` generators, "
        "pin ``template.spec.project`` to a single static project "
        "name (not a generator-interpolated placeholder) and "
        "constrain the generator with a ``filters:`` branchMatch / "
        "labels block. Otherwise an attacker who opens a PR (or "
        "creates a repo in the matched org) materializes a new "
        "Argo CD Application under whatever project the placeholder "
        "resolves to."
    ),
    docs_note=(
        "Walks ``spec.generators[]``. Fires when a generator entry "
        "carries a ``pullRequest`` or ``scmProvider`` key (or a "
        "``git`` generator with ``directories`` / ``files``) AND "
        "``spec.template.spec.project`` is either the literal "
        "``default`` or contains a generator-template placeholder "
        "like ``{{repo}}`` / ``{{branch}}`` / ``{{path[0]}}``. "
        "Static project + filtered generator passes."
    ),
    exploit_example=(
        "# Vulnerable: any PR opened against any repo whose name\n"
        "# matches the org filter spawns a fresh Application under\n"
        "# the 'default' project, which typically has wildcarded\n"
        "# sourceRepos + destinations.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: ApplicationSet\n"
        "metadata: { name: pr-previews, namespace: argocd }\n"
        "spec:\n"
        "  generators:\n"
        "    - pullRequest:\n"
        "        github:\n"
        "          owner: example-corp\n"
        "          # no labels / branchMatch filter\n"
        "  template:\n"
        "    spec:\n"
        "      project: default\n"
        "      source: { repoURL: '{{repo}}', targetRevision: '{{branch}}', path: . }\n"
        "      destination: { server: https://kubernetes.default.svc, namespace: '{{branch}}' }\n"
        "\n"
        "# Safer: scoped generator with branch / label filter and a\n"
        "# tightly-scoped project.\n"
        "spec:\n"
        "  generators:\n"
        "    - pullRequest:\n"
        "        github:\n"
        "          owner: example-corp\n"
        "          labels: ['preview']\n"
        "        requeueAfterSeconds: 300\n"
        "  template:\n"
        "    spec:\n"
        "      project: previews"
    ),
)


_PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")
_RISKY_GENERATORS = ("pullRequest", "scmProvider")


def _has_filter(gen_block: dict[str, Any]) -> bool:
    """Return True if the generator block carries a filter/constraint."""
    if not isinstance(gen_block, dict):
        return False
    if gen_block.get("filters"):
        return True
    # pullRequest generators nest filters under the provider sub-key.
    for sub in ("github", "gitlab", "bitbucket", "bitbucketServer", "gitea"):
        node = gen_block.get(sub)
        if isinstance(node, dict):
            labels = node.get("labels")
            if isinstance(labels, list) and labels:
                return True
            if node.get("branchMatch"):
                return True
    return False


def _git_dir_or_files(gen_block: dict[str, Any]) -> bool:
    if not isinstance(gen_block, dict):
        return False
    return bool(gen_block.get("directories") or gen_block.get("files"))


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    appsets = list(iter_applicationsets(ctx))
    for aset in appsets:
        spec = aset.data.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        generators = spec.get("generators")
        template = spec.get("template") or {}
        tspec = template.get("spec") if isinstance(template, dict) else None
        project = tspec.get("project") if isinstance(tspec, dict) else None
        if not isinstance(project, str):
            project = ""
        project_is_risky = (
            project == "default"
            or project == ""
            or bool(_PLACEHOLDER_RE.search(project))
        )
        if not isinstance(generators, list):
            continue
        for entry in generators:
            if not isinstance(entry, dict):
                continue
            risky_kind = None
            for kind in _RISKY_GENERATORS:
                if isinstance(entry.get(kind), dict):
                    risky_kind = kind
                    break
            if risky_kind is None:
                git_block = entry.get("git")
                if isinstance(git_block, dict) and _git_dir_or_files(git_block):
                    risky_kind = "git-directories"
            if risky_kind is None:
                continue
            gen_block = entry.get(risky_kind) if risky_kind in _RISKY_GENERATORS else entry.get("git")
            if project_is_risky and not _has_filter(gen_block or {}):
                offenders.append(
                    f"{aset.display}: {risky_kind} generator + project={project!r} "
                    f"without filters"
                )
    if not appsets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD ApplicationSet documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every ApplicationSet PR/SCM generator pairs a filter with a static project."
        if passed else
        f"{len(offenders)} ApplicationSet generator(s) untrusted: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
