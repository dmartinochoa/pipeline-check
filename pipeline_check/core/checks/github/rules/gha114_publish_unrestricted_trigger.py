"""GHA-114. Package-publish workflow reachable from an unrestricted push trigger.

The "untrusted branch" half of the npm trusted-publishing attack. A
workflow that publishes a package (an ``npm publish`` / ``twine
upload`` / trusted-publisher action, etc.) should run only from a
trusted, hard-to-forge ref: a tag, a ``workflow_dispatch``, or a
``release: published`` event. When the same workflow is reachable from
``on: push`` to *any* branch (a wildcard ``branches:`` pattern, or no
``branches:`` filter at all), anyone who can create a branch can run
the publish path.

That is exactly what the Red Hat npm compromise (BoostSecurity,
"Trusted Publishing, Untrusted Branch", 2026) walked through: a
counterfeit ``.github/workflows/ci.yml`` pushed to a throwaway
``oidc-*`` branch, alive for seconds, triggered by a plain ``push``,
minted the OIDC token and published. A tag-only or dispatch-gated
trigger would have refused to run from the throwaway branch.

Pairs with:

* **GHA-113** (OIDC publish, no environment gate) is the other half:
  the token mints from any branch because nothing pins the ref.
  GHA-114 is the trigger side, GHA-113 is the gate side, and AC-038
  intersects them on the same job (a publish token mintable from any
  branch with no human or branch gate).
* **GHA-086** (wildcard branch trigger gates an ``environment:``
  deploy) is the environment-bound case; GHA-114 generalizes it to the
  no-environment publish case, where there is no reviewer prompt at all.
"""
from __future__ import annotations

from typing import Any, cast

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from .gha113_oidc_publish_environment import _step_publishes

RULE = Rule(
    id="GHA-114",
    title="Package-publish workflow runs on an unrestricted push trigger",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-2"),
    esf=("ESF-C-APPROVAL", "ESF-D-TOKEN-HYGIENE"),
    cwe=("CWE-284", "CWE-863"),
    recommendation=(
        "Trigger a publish workflow only from a ref an attacker cannot "
        "cheaply create:\n\n"
        "- Prefer ``on: push: tags: ['v*']`` (or ``on: release: types: "
        "[published]``) so only a tag/release, not an arbitrary branch, "
        "runs the publish path. Tags are a higher-privilege operation "
        "than branch creation.\n"
        "- Or gate the release behind ``on: workflow_dispatch`` so a "
        "human starts it.\n"
        "- If a branch ``push`` trigger is unavoidable, pin "
        "``branches:`` to the exact protected release branch (``branches: "
        "[main]``, never ``branches: ['*']`` / ``['release/*']`` / no "
        "filter), and pair it with a protected ``environment:`` whose "
        "deployment-branch rule enforces the same ref (see GHA-113).\n\n"
        "A publish workflow runnable by ``push`` to any branch is the "
        "untrusted-branch half of the trusted-publishing attack: a "
        "counterfeit workflow on a throwaway branch publishes as the "
        "real release."
    ),
    docs_note=(
        "Fires when both hold:\n\n"
        "1. The workflow runs a package-publish step in some job, "
        "run-based (``npm`` / ``pnpm`` / ``yarn publish``, ``twine "
        "upload``, ``poetry`` / ``uv publish``, ``gem push``, ``cargo "
        "publish``) or a trusted-publisher action (``pypa/gh-action-"
        "pypi-publish`` / ``rubygems/release-gem`` / ``crates-io/"
        "publish-action``). Same publish surface as GHA-113.\n"
        "2. The workflow is reachable from an unrestricted ``push``: a "
        "wildcard ``branches:`` pattern (``*``, ``?``, ``+``, ``[``), or "
        "no ``branches:`` filter at all (bare ``on: push`` / ``push: "
        "{}`` fires on every branch).\n\n"
        "Restricted triggers pass: a tag-only push (``push: {tags: "
        "['v*']}`` with no ``branches:``), an exact branch list "
        "(``branches: [main]``), ``workflow_dispatch``-only, or "
        "``release``-only. When ``push`` carries both an exact branch "
        "list and tags it stays silent; a wildcard or unfiltered "
        "branch push fires even if a tag filter is also present, "
        "because the branch path still runs the publish. ``branches-"
        "ignore`` without ``branches:`` is unrestricted (every "
        "non-ignored branch fires). Emits ``job_anchors`` for the "
        "publish jobs so AC-038 can intersect with GHA-113 on the same "
        "job.\n\n"
        "Defaults to MEDIUM confidence: an internal continuous-delivery "
        "pipeline may intentionally publish a snapshot to a private "
        "registry on every branch push, so an unrestricted-trigger "
        "publish is not always a public-release exposure."
    ),
    known_fp=(
        "Internal continuous-delivery pipelines that intentionally "
        "publish a snapshot / pre-release artifact on every push to a "
        "development branch (the publish target is a private staging "
        "registry, not the public index). The unrestricted trigger is "
        "by design there; suppress per-workflow via ``--ignore-file`` "
        "once the publish target is confirmed non-public.",
        "A workflow whose only ``push`` trigger is an exact protected "
        "branch is not flagged, but the writeup still recommends a tag "
        "or dispatch trigger over a branch push for public releases.",
    ),
    incident_refs=(
        "Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, "
        "Untrusted Branch', 2026): a counterfeit ``ci.yml`` on a "
        "throwaway ``oidc-*`` branch, triggered by a plain ``push``, "
        "minted an OIDC token and published 30+ packages. A tag-only "
        "or dispatch-gated trigger would not have run from the "
        "throwaway branch: https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
    ),
    exploit_example=(
        "# Vulnerable: the publish workflow runs on a plain branch\n"
        "# push with no branch filter, so a counterfeit copy on a\n"
        "# throwaway branch publishes as the real release.\n"
        "on:\n"
        "  push:\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - run: npm publish --provenance --access public\n"
        "\n"
        "# Safe: the publish path runs only on a version tag, a ref an\n"
        "# attacker cannot cheaply create. A push to a throwaway branch\n"
        "# never reaches the publish step.\n"
        "on:\n"
        "  push:\n"
        "    tags: ['v*']\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - run: npm publish --provenance --access public"
    ),
)


# GitHub branch-filter glob metacharacters (filter-pattern cheat sheet):
# ``*`` / ``**`` / ``?`` / ``+`` / ``[...]``. A leading ``!`` is
# positional negation, not a wildcard, so it is stripped first.
_WILDCARD_CHARS = ("*", "?", "+", "[")


def _is_wildcard_pattern(pattern: str) -> bool:
    body = pattern.lstrip("!").strip()
    return any(c in body for c in _WILDCARD_CHARS)


def _workflow_on(doc: dict[str, Any]) -> Any:
    """Return the workflow's ``on:`` value, handling the YAML 1.1 quirk
    where a bare ``on:`` key is parsed as the boolean ``True``."""
    on = doc.get("on")
    if on is None:
        # YAML 1.1 parses a bare ``on:`` key as the boolean True.
        wf_any: dict[Any, Any] = cast("dict[Any, Any]", doc)
        on = wf_any.get(True)
    return on


def _unrestricted_push(doc: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(is_unrestricted, reason)`` for the workflow's push trigger.

    Unrestricted means a ``push`` event reachable from a ref an attacker
    can create: a wildcard ``branches:`` pattern, or no ``branches:``
    filter at all (every branch fires). A tags-only push, an exact
    branch list, or no ``push`` event is restricted.
    """
    on = _workflow_on(doc)
    # ``on: push`` (string) or ``on: [push, ...]`` (list): bare push,
    # every branch fires.
    if isinstance(on, str):
        if on == "push":
            return True, "bare ``on: push`` (every branch fires)"
        return False, ""
    if isinstance(on, list):
        if "push" in on:
            return True, "bare ``on: push`` (every branch fires)"
        return False, ""
    if not isinstance(on, dict):
        return False, ""
    if "push" not in on:
        return False, ""
    push = on.get("push")
    # ``push:`` with no mapping (null / empty) -> every branch fires.
    if not isinstance(push, dict):
        return True, "``on: push`` with no branch filter (every branch fires)"
    branches = push.get("branches")
    if branches is None:
        # No branches filter. A tags-only push is restricted; otherwise
        # (incl. branches-ignore) every branch fires.
        if push.get("tags") is not None:
            return False, ""
        return True, "``on: push`` with no branch filter (every branch fires)"
    if isinstance(branches, str):
        blist = [branches]
    elif isinstance(branches, list):
        blist = [str(b) for b in branches]
    else:
        return False, ""
    wild = [p for p in blist if _is_wildcard_pattern(p)]
    if wild:
        return True, (
            "wildcard branch pattern(s) "
            + ", ".join(repr(p) for p in wild)
        )
    return False, ""


def check(path: str, doc: dict[str, Any]) -> Finding:
    pub_ids: dict[str, None] = {}
    labels: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            is_pub, label = _step_publishes(step)
            if not is_pub:
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            pub_ids[job_id] = None
            labels.append(f"{job_id}.{name} ({label})")
            locations.append(step_location(path, step))
    if not pub_ids:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No package-publish step in this workflow.",
            recommendation=RULE.recommendation, passed=True,
        )
    unrestricted, reason = _unrestricted_push(doc)
    if not unrestricted:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "The publish workflow's trigger is restricted (a tag, "
                "an exact branch, workflow_dispatch, or release), so a "
                "throwaway branch cannot reach the publish path."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        f"A publish workflow is reachable from an unrestricted push "
        f"trigger ({reason}): {', '.join(labels[:5])}"
        f"{'…' if len(labels) > 5 else ''}. A counterfeit copy of this "
        f"workflow on a throwaway branch publishes as the real release "
        f"(the Red Hat npm 'untrusted branch' shape). Trigger publishes "
        f"from a tag, release, or workflow_dispatch instead."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
        job_anchors=tuple(pub_ids),
    )
