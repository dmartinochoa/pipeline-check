"""BB-018, cache key must not derive from attacker-controllable input."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

# Attacker-controllable pipeline vars. ``BITBUCKET_PR_DESTINATION_BRANCH``
# is deliberately excluded: the PR *destination* (target) branch is a
# repo-owned protected name, not a value the PR author controls.
_CACHE_TAINT_RE = re.compile(
    r"\$\{?(?:BITBUCKET_BRANCH|BITBUCKET_TAG|BITBUCKET_BOOKMARK)\}?"
)

RULE = Rule(
    id="BB-018",
    title="Cache key derives from attacker-controllable input",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345",),
    recommendation=(
        "Build the cache key from values the attacker cannot control. "
        "Prefer `hashFiles()` on lockfiles enforced by branch "
        "protection. Never include $BITBUCKET_BRANCH or PR-related "
        "variables in the cache key."
    ),
    docs_note=(
        "Bitbucket caches are restored by key. When the key includes "
        "a value the PR author controls (the source branch name, tag, "
        "or bookmark), a pull-request pipeline can plant a poisoned "
        "cache entry that a subsequent default-branch build restores. "
        "The PR *destination* branch and the Bitbucket-assigned PR ID "
        "aren't author-controlled, so they don't taint the key."
    ),
    exploit_example=(
        "# Vulnerable: cache path is namespaced by the branch name.\n"
        "definitions:\n"
        "  caches:\n"
        "    deps: node_modules-$BITBUCKET_BRANCH\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        caches: [deps]\n"
        "        script:\n"
        "          - npm ci\n"
        "\n"
        "# Attack: open a PR from a branch you name. Your PR pipeline\n"
        "# populates the `deps` cache under your branch-derived key. A\n"
        "# later default-branch build that resolves the same attacker-\n"
        "# influenced key restores your poisoned node_modules and runs\n"
        "# it.\n"
        "\n"
        "# Safe: key the cache on values the attacker can't change, not\n"
        "# on the branch.\n"
        "definitions:\n"
        "  caches:\n"
        "    deps: node_modules"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    definitions = doc.get("definitions", {})
    caches = definitions.get("caches", {}) if isinstance(definitions, dict) else {}
    if isinstance(caches, dict):
        for name, val in caches.items():
            if isinstance(val, str) and _CACHE_TAINT_RE.search(val):
                offenders.append(f"definitions.caches.{name}")
    # Also check inline caches references in pipelines steps
    pipelines = doc.get("pipelines")
    if isinstance(pipelines, dict):
        for cat, value in pipelines.items():
            if isinstance(value, dict):
                for sub, items in value.items():
                    _check_items(items, f"{cat}.{sub}", offenders)
            elif isinstance(value, list):
                _check_items(value, str(cat), offenders)
    passed = not offenders
    desc = (
        "No cache key derives from attacker-controllable input."
        if passed
        else f"Cache key includes attacker-controlled variable in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )


def _check_items(items: object, prefix: str, offenders: list[str]) -> None:
    if not isinstance(items, list):
        return
    for idx, entry in enumerate(items):
        if not isinstance(entry, dict):
            continue
        step = entry.get("step")
        if not isinstance(step, dict):
            continue
        caches = step.get("caches")
        if isinstance(caches, list):
            for c in caches:
                if isinstance(c, str) and _CACHE_TAINT_RE.search(c):
                    offenders.append(f"{prefix}[{idx}].caches")
