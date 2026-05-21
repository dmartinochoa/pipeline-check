"""ADO-025, cross-repo templates must pin a ref: to a commit SHA.

ADO-011 covers the PR-branch swap on *local* templates. This rule
covers the parallel risk for *cross-repo* templates: a ``template:
foo.yml@resource`` that points at an ``resources.repositories`` entry
without a ``ref:`` (or with a branch/tag ref) will follow whatever
upstream commit the callee repo publishes, effectively RCE by tag
move.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.sha_ref import SHA_RE as _SHA_RE
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
        "<sha>`` or the bare 40-char commit SHA, never a branch or "
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
    exploit_example=(
        "# Vulnerable: ``ref: refs/heads/main`` on a cross-repo\n"
        "# template is mutable. Whoever can push to ``main`` on\n"
        "# ``ci-templates`` ships code into every consumer's\n"
        "# pipeline on the next run.\n"
        "resources:\n"
        "  repositories:\n"
        "    - repository: templates\n"
        "      type: git\n"
        "      name: myorg/ci-templates\n"
        "      ref: refs/heads/main\n"
        "steps:\n"
        "  - template: build.yml@templates\n"
        "\n"
        "# Safe: pin to a tag (immutable in Azure Repos when\n"
        "# branch policies enforce tag-protect) or a 40-char\n"
        "# commit SHA. Renovate's azure-pipelines updater bumps\n"
        "# these in reviewable PRs.\n"
        "resources:\n"
        "  repositories:\n"
        "    - repository: templates\n"
        "      type: git\n"
        "      name: myorg/ci-templates\n"
        "      ref: 0123456789abcdef0123456789abcdef01234567   # v1.4.2\n"
        "steps:\n"
        "  - template: build.yml@templates"
    ),
)

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


def _repo_is_pinned(repo: dict[str, Any]) -> bool:
    ref = repo.get("ref")
    if not isinstance(ref, str):
        return False
    # Branches are always mutable, even a branch named after a SHA
    # (``refs/heads/<40-hex>``) is just a movable pointer. Reject the
    # whole namespace before the SHA check so the alias shape can't
    # masquerade as an immutable pin.
    if ref.startswith("refs/heads/"):
        return False
    # Accept ``refs/tags/<sha>`` or a bare 40-char SHA. ``refs/tags/v1``
    # (a floating tag) won't survive the _SHA_RE check below.
    bare = ref.removeprefix("refs/tags/")
    return bool(_SHA_RE.match(bare))


def check(path: str, doc: dict[str, Any]) -> Finding:
    resources = doc.get("resources") or {}
    if not isinstance(resources, dict):
        return _passed(path, "No resources declared.")
    repos = resources.get("repositories") or []
    if not isinstance(repos, list):
        return _passed(path, "No repository resources declared.")

    # Build alias → repo-entry map.
    repo_by_alias: dict[str, dict[str, Any]] = {}
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
