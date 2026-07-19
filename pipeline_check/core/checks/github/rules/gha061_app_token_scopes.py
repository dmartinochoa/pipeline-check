"""GHA-061. GitHub App-token minted without a ``permissions:`` filter."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-061",
    title="GitHub App token minted without a `permissions:` filter",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5", "CICD-SEC-2"),
    esf=("ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Pass an explicit ``permissions:`` filter when minting a "
        "GitHub App installation token. The minted token will then "
        "carry only the requested scopes even if the App's install "
        "grants more. Example:\n\n"
        "    - id: app-token\n"
        "      uses: actions/create-github-app-token@<sha>\n"
        "      with:\n"
        "        app-id: ${{ secrets.RELEASE_APP_ID }}\n"
        "        private-key: ${{ secrets.RELEASE_APP_KEY }}\n"
        "        permissions: >-\n"
        '          {"contents":"write"}\n\n'
        "List every scope the consuming steps actually need; a "
        "future reader (and an attacker who lands a step in this "
        "job) can then see exactly what the token can do. Apps are "
        "commonly installed with broad org-wide scopes "
        "(``contents: write, packages: write, actions: write, "
        "pull-requests: write, ...``) because granular per-install "
        "permissions are tedious; without the filter the runner "
        "token inherits every one of them."
    ),
    docs_note=(
        "Fires when a step uses one of the known App-token "
        "minting actions without a ``with.permissions`` input:\n\n"
        "- ``actions/create-github-app-token`` (the official "
        "action; the canonical pattern documented on the "
        "GitHub Apps + Actions page).\n"
        "- ``tibdex/github-app-token`` (the older community "
        "action that the official one replaced; many workflows "
        "still pin it).\n"
        "- ``peter-murray/workflow-application-token-action`` "
        "(similar shape, older.)\n\n"
        "The rule is shape-only and doesn't inspect what the App "
        "is actually installed with. That's intentional: the "
        "scanner can't see the org-side install record, so the "
        "right contract is 'always declare the scopes you need at "
        "mint time'. Pairs with GHA-050 (publish without OIDC) on "
        "the long-lived-credential axis: GHA-050 covers static "
        "registry tokens minted by the operator, GHA-061 covers "
        "short-lived App tokens that nonetheless carry org-wide "
        "scope."
    ),
    known_fp=(
        "A workflow that genuinely needs every scope the App "
        "carries (rare; usually a release-orchestrator job that "
        "writes ``contents`` + ``packages`` + ``deployments`` + "
        "``actions``). The right response is still to list those "
        "scopes explicitly so the breadth is documented, not to "
        "suppress the rule.",
        "First-publish bootstrap on a brand-new App install where "
        "the available scopes haven't been finalized yet. "
        "Suppress on the specific step until the App install "
        "settles.",
    ),
    incident_refs=(
        "zizmor's ``github-app`` audit (2025) flagged this shape "
        "after multiple incident reviews showed Apps installed "
        "with broad scopes minting full-scope tokens for jobs "
        "that only needed ``contents: write``. The runtime cost "
        "of one missing ``permissions:`` line is the same as a "
        "PAT with all those scopes leaked into the runner.",
    ),
    exploit_example=(
        "# Vulnerable: token inherits every permission the App\n"
        "# install grants on the org (commonly contents: write,\n"
        "# packages: write, actions: write, pull-requests: write,\n"
        "# deployments: write, ...). Any later step that lands\n"
        "# attacker-controlled shell exfils a token whose blast\n"
        "# radius is 'everything the App can do' rather than the\n"
        "# single scope this job actually needed.\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: app-token\n"
        "        uses: actions/create-github-app-token@<sha>\n"
        "        with:\n"
        "          app-id: ${{ secrets.RELEASE_APP_ID }}\n"
        "          private-key: ${{ secrets.RELEASE_APP_KEY }}\n"
        "          owner: ${{ github.repository_owner }}\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          token: ${{ steps.app-token.outputs.token }}\n"
        "      - run: git push --follow-tags\n"
        "\n"
        "# Safe: explicit scope list. Token can push tags and\n"
        "# nothing else, even if the App install carries more.\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: app-token\n"
        "        uses: actions/create-github-app-token@<sha>\n"
        "        with:\n"
        "          app-id: ${{ secrets.RELEASE_APP_ID }}\n"
        "          private-key: ${{ secrets.RELEASE_APP_KEY }}\n"
        "          owner: ${{ github.repository_owner }}\n"
        "          permissions: >-\n"
        '            {"contents":"write"}\n'
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          token: ${{ steps.app-token.outputs.token }}\n"
        "      - run: git push --follow-tags"
    ),
)


# Known App-token minting actions. Match the prefix before ``@``; any
# version pin (tag, branch, sha) is allowed. Lowercased for the
# comparison.
_APP_TOKEN_ACTIONS: tuple[str, ...] = (
    "actions/create-github-app-token",
    "tibdex/github-app-token",
    "peter-murray/workflow-application-token-action",
)


def _is_app_token_step(step: dict[str, Any]) -> str | None:
    """Return the matched action prefix if *step* mints an App token."""
    uses = step.get("uses")
    if not isinstance(uses, str):
        return None
    action = uses.split("@", 1)[0].strip().lower()
    for prefix in _APP_TOKEN_ACTIONS:
        if action == prefix:
            return prefix
    return None


def _step_declares_permissions(step: dict[str, Any]) -> bool:
    """True when the step passes a non-empty ``with.permissions`` input."""
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    # The official ``actions/create-github-app-token`` has no
    # ``permissions`` input; it scopes the token via granular
    # ``permission-<scope>: read|write`` inputs. Treat any such key as a
    # declared filter, alongside the ``permissions`` block that
    # tibdex / peter-murray use.
    for key, kv in with_block.items():
        if not (isinstance(key, str) and key.startswith("permission-")):
            continue
        if kv is not None and (not isinstance(kv, str) or kv.strip()):
            return True
    val = with_block.get("permissions")
    if val is None:
        return False
    if isinstance(val, str):
        return bool(val.strip())
    # YAML can hand us a dict / list when the user inlines a multi-line
    # block-scalar mapping instead of the JSON-string shape the action
    # accepts at runtime. Treat any non-empty value as a declaration.
    if isinstance(val, (dict, list)):
        return bool(val)
    return True


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            prefix = _is_app_token_step(step)
            if prefix is None:
                continue
            if _step_declares_permissions(step):
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"{job_id}.{name} ({prefix})")
            locations.append(step_location(path, step))
            anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No GitHub App token-minting step found, or every minting "
        "step declares an explicit ``permissions:`` filter."
        if passed else
        f"{len(offenders)} App-token mint step(s) carry no "
        f"``permissions:`` filter and inherit the App install's "
        f"full scope: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Apps are commonly "
        f"installed with broad org-wide scopes; without the filter "
        f"the token's blast radius is whatever the install grants."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
