"""ADO-025 — cross-repo templates must pin a ref: to a commit SHA.

ADO-011 covers the PR-branch swap on *local* templates. This rule
covers the parallel risk for *cross-repo* templates: a ``template:
foo.yml@resource`` that points at an ``resources.repositories`` entry
without a ``ref:`` (or with a branch/tag ref) will follow whatever
upstream commit the callee repo publishes — effectively RCE by tag
move.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="ADO-025",
    title="Cross-repo template not pinned to commit SHA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "On every ``resources.repositories`` entry referenced from a "
        "``template: ...@repo-alias`` directive, set ``ref: refs/tags/"
        "<sha>`` or the bare 40-char commit SHA — never a branch or "
        "floating tag. A moved branch/tag swaps the template body "
        "without changing your pipeline file."
    ),
    docs_note=(
        "Azure Pipelines resolves ``template: build.yml@tools`` "
        "against the ``tools`` repo resource's ``ref:`` field. When "
        "that ref is ``refs/heads/main`` (or missing, which defaults "
        "to the pipeline's default branch), a push to the callee repo "
        "changes what your pipeline runs on the next invocation."
    ),
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TEMPLATE_AT_RE = re.compile(r"@([A-Za-z_][\w-]*)\s*$")


def _find_template_aliases(node: Any, aliases: set[str]) -> None:
    """Collect ``<name>`` aliases from every ``template: foo.yml@<name>``."""
    if isinstance(node, dict):
        for key, val in node.items():
            if key == "template" and isinstance(val, str):
                m = _TEMPLATE_AT_RE.search(val)
                if m:
                    aliases.add(m.group(1))
            _find_template_aliases(val, aliases)
    elif isinstance(node, list):
        for item in node:
            _find_template_aliases(item, aliases)


def _repo_is_pinned(repo: dict) -> bool:
    ref = repo.get("ref")
    if not isinstance(ref, str):
        return False
    # Accept ``refs/tags/<sha>`` or a bare 40-char SHA.
    bare = ref.removeprefix("refs/tags/").removeprefix("refs/heads/")
    # Pinned when the ref is a 40-char SHA; refs/heads/* or refs/tags/v1
    # (a floating tag) aren't pinned enough.
    return bool(_SHA_RE.match(bare))


def check(path: str, doc: dict[str, Any]) -> Finding:
    resources = doc.get("resources") or {}
    if not isinstance(resources, dict):
        return _passed(path, "No resources declared.")
    repos = resources.get("repositories") or []
    if not isinstance(repos, list):
        return _passed(path, "No repository resources declared.")

    # Build alias → repo-entry map.
    repo_by_alias: dict[str, dict] = {}
    for entry in repos:
        if not isinstance(entry, dict):
            continue
        alias = entry.get("repository")
        if isinstance(alias, str):
            repo_by_alias[alias] = entry

    if not repo_by_alias:
        return _passed(path, "No repository resources declared.")

    # Which aliases are actually referenced from ``template: ...@alias``?
    template_aliases: set[str] = set()
    _find_template_aliases(doc, template_aliases)

    offenders: list[str] = []
    for alias in sorted(template_aliases):
        entry = repo_by_alias.get(alias)
        if entry is None:
            continue  # template referenced an alias we can't resolve
        if not _repo_is_pinned(entry):
            ref = entry.get("ref") or "<unpinned>"
            offenders.append(f"{alias} (ref: {ref})")

    passed = not offenders
    desc = (
        "Every cross-repo template pins a 40-char commit SHA."
        if passed else
        f"Cross-repo template reference(s) follow floating refs: "
        f"{', '.join(offenders)}. A push to the callee repo can swap "
        "the template body without updating your pipeline file."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )


def _passed(path: str, reason: str) -> Finding:
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=reason,
        recommendation="No action required.", passed=True,
    )
