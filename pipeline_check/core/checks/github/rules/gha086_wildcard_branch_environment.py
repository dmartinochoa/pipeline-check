"""GHA-086. Wildcard branch trigger gates an ``environment:`` deploy.

cicd-goat scenario 25 (CICD-SEC-1 / CICD-SEC-5): a deploy job binds
``environment: production`` for the required-reviewer gate, but the
workflow's ``on: push: branches: ['main*']`` trigger uses a wildcard
pattern. Anyone with push access creates a branch matching the
pattern (``main-evil``, ``release/anything``, etc.) and the
environment's protection-branches rule lets it deploy.

The matching protection setting lives in GitHub repo settings and
can't be read from YAML. This rule covers the visible-in-YAML half:
a wildcard trigger feeding an environment-gated job is the canonical
bypass shape regardless of how the protection rule is configured.
Even when the operator pinned the protection rule to an exact branch,
the wildcard trigger still indicates the deploy gate isn't being
enforced at the workflow level either.

Pairs with GHA-014 (deploy job missing environment binding) which
fires on the opposite case: the trigger is fine but the gate is
missing. Together they cover both halves of the gate-bypass surface.
"""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-086",
    title="Wildcard branch trigger gates an environment-bound deploy",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284", "CWE-863"),
    recommendation=(
        "Pin ``on: push: branches:`` to the exact branch names that "
        "should be allowed to deploy (``branches: [main]``, not "
        "``branches: ['main*']``). Configure the matching GitHub "
        "environment's ``Deployment branches and tags`` rule with "
        "``Selected branches and tags`` -> exact match. For high-"
        "blast-radius environments, require deployment from a "
        "protected tag rather than a branch, tags are immutable in "
        "a way branches are not."
    ),
    docs_note=(
        "Fires when both conditions hold:\n\n"
        "1. The workflow's ``on: push: branches:`` filter contains "
        "at least one wildcard pattern (``*``, ``?``, ``+``, "
        "``[...]``). ``branches: [main]`` is exact-match and stays "
        "silent; ``branches: ['main*']``, ``branches: "
        "['release/*']``, and ``branches: ['*']`` all fire.\n"
        "2. At least one job in the workflow binds "
        "``environment: <name>`` (either the short string form or "
        "the long ``environment: {name: <name>, url: ...}`` mapping).\n\n"
        "The combination is the canonical "
        "deployment-branches-rule-bypass topology: the trigger "
        "accepts every branch matching the pattern, the environment "
        "gate fires on the deployment, but the reviewer prompt does "
        "not surface the diff. A branch named ``main-anything`` "
        "matches and the reviewer is asked to approve a generic "
        "``production`` deploy.\n\n"
        "Branch wildcards in ``branches-ignore:`` are not flagged "
        "(they restrict triggers rather than expand them). Tag "
        "filters (``tags:``) are not flagged because tag creation "
        "is generally a higher-privilege operation than branch "
        "creation."
    ),
    known_fp=(
        "Internal-only environments scoped to a release-branch "
        "convention (``release/*``) where the protection rule is "
        "intentionally configured to allow any branch matching the "
        "convention. The bypass surface is real but the operator has "
        "accepted it. Suppress per-workflow via ignore-file when the "
        "convention is documented and the environment's protection "
        "rule is audited.",
    ),
    incident_refs=(
        "OWASP CICD-SEC-1 (Insufficient Flow Control Mechanisms): "
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-01-Insufficient-Flow-Control-Mechanisms",
    ),
    exploit_example=(
        "# Vulnerable: workflow triggers on any branch starting with\n"
        "# ``main``, then deploys to the ``production`` environment.\n"
        "# A user with push access creates branch ``main-evil``, the\n"
        "# environment's reviewer is prompted to approve a deploy\n"
        "# from a branch that looks innocuous in the dialog.\n"
        "on:\n"
        "  push:\n"
        "    branches: ['main*']\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment:\n"
        "      name: production\n"
        "      url: https://prod.example.com\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./deploy.sh\n"
        "\n"
        "# Safe: branches filter pinned to the exact branch the\n"
        "# protection rule whitelists. No matching ``main-anything``\n"
        "# bypass.\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment:\n"
        "      name: production\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./deploy.sh"
    ),
)


# GitHub branch filter pattern glob metacharacters. Per the
# `Filter pattern cheat sheet`_ in GHA docs: ``*`` (zero+ chars
# except ``/``), ``**`` (zero+ chars including ``/``), ``?``
# (single char), ``+`` (one+ of preceding char), ``[abc]``
# (character set). Negation (``!``) is positional and indicates
# an exclude pattern, not a wildcard itself.
#
# .. _Filter pattern cheat sheet:
#    https://docs.github.com/en/actions/using-workflows/
#    workflow-syntax-for-github-actions#filter-pattern-cheat-sheet
_WILDCARD_CHARS = ("*", "?", "+", "[")


def _is_wildcard_pattern(pattern: str) -> bool:
    """Return True if *pattern* contains a glob metacharacter.

    Conservative: any literal occurrence of ``*``, ``?``, ``+``,
    or ``[`` is treated as a wildcard. A pattern with a leading
    ``!`` (negation) followed by an exact branch name is *not* a
    wildcard, so the negation is stripped before checking.
    """
    body = pattern.lstrip("!").strip()
    return any(c in body for c in _WILDCARD_CHARS)


def _wildcard_branch_filters(doc: dict[str, Any]) -> list[str]:
    """Return wildcard patterns under ``on.push.branches`` (if any).

    Empty list when:
      * the workflow has no ``on:`` block
      * the ``on:`` block has no ``push:`` event
      * ``push:`` carries no ``branches:`` filter
      * every branch pattern is exact-match
    """
    on = doc.get("on")
    if on is None:
        from typing import cast
        wf_any: dict[Any, Any] = cast("dict[Any, Any]", doc)
        on = wf_any.get(True)
    if not isinstance(on, dict):
        return []
    push = on.get("push")
    if not isinstance(push, dict):
        return []
    branches = push.get("branches")
    if isinstance(branches, str):
        branches_list = [branches]
    elif isinstance(branches, list):
        branches_list = [str(b) for b in branches]
    else:
        return []
    return [p for p in branches_list if _is_wildcard_pattern(p)]


def _environment_bound_jobs(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(job_id, job_dict)`` for each job that binds ``environment:``."""
    bound: list[tuple[str, dict[str, Any]]] = []
    for job_id, job in iter_jobs(doc):
        env = job.get("environment")
        if env is None:
            continue
        if isinstance(env, str):
            if env.strip():
                bound.append((job_id, job))
        elif isinstance(env, dict):
            name = env.get("name")
            if isinstance(name, str) and name.strip():
                bound.append((job_id, job))
    return bound


def check(path: str, doc: dict[str, Any]) -> Finding:
    wildcards = _wildcard_branch_filters(doc)
    if not wildcards:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No wildcard branch filter on the workflow's "
                "``on: push:`` trigger."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    bound = _environment_bound_jobs(doc)
    if not bound:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Wildcard branch filter present, but no job binds an "
                "``environment:`` so the bypass surface is empty."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    job_ids = [job_id for job_id, _ in bound]
    locations: list[Location] = []
    for _, job in bound:
        line = _line_of(job)
        if line is not None:
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))
    desc = (
        f"Workflow trigger uses wildcard branch pattern(s) "
        f"{', '.join(repr(p) for p in wildcards)} while "
        f"{len(bound)} job(s) bind an ``environment:`` "
        f"({', '.join(job_ids)}). Any branch matching the wildcard "
        f"can deploy to that environment if the protection rule is "
        f"also pattern-based, bypassing the reviewer gate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
        job_anchors=tuple(job_ids),
    )
