"""GHA-049. Workflow step pushes commits or creates repos under another owner."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-049",
    title="Workflow step makes a privileged git write (cross-repo or actions[bot] bypass)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-913", "CWE-284"),
    recommendation=(
        "Don't push from CI to a repository whose owner is supplied "
        "by an unvetted source (an env var, a workflow input, an "
        "interpolated PR field, or a step output). Cross-repo writes "
        "from CI are the second leg of the Shai-Hulud propagation "
        "loop, the worm uses the runner's GITHUB_TOKEN (or a stolen "
        "PAT) to ``git push`` or ``gh repo create`` against every "
        "repo the token can reach. If the workflow truly needs to "
        "push to an external repo, bind the step to a protected "
        "``environment:`` and pin the destination to a literal "
        "``owner/repo`` string."
    ),
    docs_note=(
        "Four shapes are detected in ``run:`` bodies:\n\n"
        "1. ``git push`` to a remote whose URL is interpolated from "
        "an expression (``${{ ... }}``), an env var (``$VAR``), or "
        "is not the canonical ``origin`` / ``upstream``;\n"
        "2. ``gh repo create`` / ``gh repo edit`` / ``gh repo "
        "transfer`` / ``gh api /repos/...`` whose target owner is "
        "parameterized;\n"
        "3. ``gh release create`` / ``gh release upload`` against a "
        "repo specified via ``-R <owner>/<repo>`` where the value is "
        "parameterized rather than a literal allow-list entry;\n"
        "4. ``git config user.name 'github-actions[bot]'`` (or "
        "``actions-user`` / ``41898282+github-actions[bot]``) "
        "co-occurring with any ``git push`` in the same job. The "
        "combination is the canonical branch-protection bypass-abuse "
        "shape: GitHub's documented operational convenience is to "
        "list ``github-actions[bot]`` in "
        "``Allow specified actors to bypass required pull requests`` "
        "on the default branch, after which any workflow that "
        "assumes that identity can push to ``main`` without review. "
        "The SCM provider's SCM-018 catches the branch-protection "
        "side; this leg catches the workflow that's pre-positioned "
        "to exploit it.\n\n"
        "Pairs with GHA-048 (self-mutation, which catches the *write* "
        "into ``.github/workflows/`` of a sibling workflow): "
        "GHA-049 catches the *push* primitive that lets a worm leave "
        "the current repo. Together they cover both halves of the "
        "Shai-Hulud propagation step."
    ),
    known_fp=(
        "Mirror jobs (push to ``github.com/<our-org>/<mirror>``), "
        "monorepo release jobs that push to a publishing org, and "
        "release-please-style automation legitimately push to a "
        "different repo. Suppress on the specific step name with a "
        "rationale that names the literal target. The rule does NOT "
        "fire on ``git push origin <ref>`` or ``git push upstream "
        "<ref>`` where the remote URL is otherwise unspecified.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the propagation loop combined "
        "a stolen GITHUB_TOKEN with ``gh repo create`` plus "
        "``git push`` to seed ``shai-hulud-workflow.yml`` into every "
        "repo the token could reach. Without the cross-repo push "
        "primitive the worm cannot leave the first infected runner.",
    ),
    exploit_example=(
        "# Vulnerable: every repo the token can write to becomes a\n"
        "# propagation target on the next push trigger.\n"
        "jobs:\n"
        "  spread:\n"
        "    permissions: { contents: write, administration: write }\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          for repo in $(gh repo list \"$ORG\" --json name -q '.[].name'); do\n"
        "            gh repo clone \"$ORG/$repo\" \"/tmp/$repo\"\n"
        "            cp payload.yml \"/tmp/$repo/.github/workflows/lint.yml\"\n"
        "            git -C \"/tmp/$repo\" add .github/workflows/lint.yml\n"
        "            git -C \"/tmp/$repo\" commit -m 'ci: add lint workflow'\n"
        "            git -C \"/tmp/$repo\" push origin main\n"
        "          done\n"
        "\n"
        "# Safe: cross-repo pushes only from an environment-gated job\n"
        "# pinned to a literal destination, with a fine-scoped PAT\n"
        "# (not the workflow's GITHUB_TOKEN).\n"
        "jobs:\n"
        "  mirror:\n"
        "    environment: mirror-protected\n"
        "    permissions: { contents: read }\n"
        "    steps:\n"
        "      - run: git push https://x-access-token:${{ secrets.MIRROR_PAT }}@github.com/our-org/our-mirror.git main"
    ),
)


# ``git push <url>`` where the URL is parameterized. Three risky forms:
#  - ``${{ ... }}`` interpolation in the URL (any expression)
#  - ``$VAR`` / ``${VAR}`` shell interpolation in the URL
#  - explicit ``https://...github.com/<owner>/`` URL (any owner)
#
# Benign forms NOT matched: ``git push origin <ref>``,
# ``git push upstream <ref>``, ``git push -u origin <ref>``.
_GIT_PUSH_RE = re.compile(
    r"\bgit\s+push\s+(?:[-\w]+\s+)*"   # any flags
    r"(?:"
    r"\$\{\{[^}]+\}\}"                  # ${{ ... }} expression
    r"|\$\{?\w+\}?(?:/\S+)?"            # $VAR interpolation
    r"|https?://[^\s/@]+@?[^\s]+"       # explicit URL
    r")",
    re.IGNORECASE,
)

# Suppress the URL match when the URL is a literal first-party origin
# (``git push origin <ref>`` style). Detected after the broad match
# fires; this re-checks the captured token.
_BENIGN_REMOTE_RE = re.compile(r"^(origin|upstream|fork|mirror)$", re.IGNORECASE)

# ``gh repo`` write verbs against a parameterized target. Reads pass,
# and literal pinned ``owner/repo`` strings pass too — those are the
# allow-list case the rule docstring carves out.
_GH_REPO_WRITE_RE = re.compile(
    r"\bgh\s+repo\s+(?:create|edit|transfer|archive|delete|rename)\s+"
    r"(?:[-\w]+\s+)*"
    r"(?:\$\{\{[^}]+\}\}|\$\{?\w+\}?)",
    re.IGNORECASE,
)

# ``gh api -X POST /repos/<owner>/<repo>`` family. ``GET`` calls are
# reads; ``POST`` / ``PUT`` / ``PATCH`` / ``DELETE`` are writes. Only
# parameterized targets fire; literal ``/repos/<owner>/<repo>`` paths
# are treated as allow-listed.
_GH_API_WRITE_RE = re.compile(
    r"\bgh\s+api\s+(?:-X\s+|--method\s+)?(POST|PUT|PATCH|DELETE)\s+"
    r"[\"']?/repos/(?:\$\{\{[^}]+\}\}|\$\{?\w+\}?)",
    re.IGNORECASE,
)

# Bot-identity assumption. The GitHub Actions runtime exposes the bot
# user under several stable forms; teams pin either the noreply email
# (``41898282+github-actions[bot]@users.noreply.github.com``), the
# bot username (``github-actions[bot]``), or the legacy ``actions-user``
# spelling. The patterns are case-insensitive on the spelling but
# require the literal bracketed ``[bot]`` marker where applicable.
_ACTIONS_BOT_IDENTITY_RE = re.compile(
    r"\bgit\s+config\s+(?:--\S+\s+)*user\.(?:name|email)\s+"
    r"[\"']?(?:"
    r"github-actions\[bot\]"
    r"|41898282\+github-actions\[bot\]@users\.noreply\.github\.com"
    r"|actions-user"
    r")[\"']?",
    re.IGNORECASE,
)

# Any git push command (origin or otherwise) — the bot-identity shape
# treats ANY push as the bypass primitive, since the branch-protection
# misconfiguration on the remote side, not the URL on the workflow
# side, is what makes the push privileged.
_ANY_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)

# ``gh release create -R <owner>/<repo>`` / ``gh release upload -R ...``
# against a parameterized target.
_GH_RELEASE_RE = re.compile(
    r"\bgh\s+release\s+(?:create|upload|edit|delete)\b[^\n]*"
    r"(?:-R|--repo)\s+"
    r"(\$\{\{[^}]+\}\}|\$\{?\w+\}?)",
    re.IGNORECASE,
)


def _line_pushes_externally(line: str) -> str | None:
    """Return a short label for the unsafe pattern in *line*, or ``None``."""
    m = _GIT_PUSH_RE.search(line)
    if m:
        # If the match captured ``origin`` / ``upstream`` / similar
        # via the ``$VAR`` branch (e.g. ``git push origin``), let it
        # pass; otherwise fire.
        captured = m.group(0).split(maxsplit=2)[-1].strip()
        captured = captured.lstrip("${").rstrip("}")
        if not _BENIGN_REMOTE_RE.match(captured):
            return "git push to parameterized URL"
    if _GH_REPO_WRITE_RE.search(line):
        return "gh repo write to parameterized target"
    if _GH_API_WRITE_RE.search(line):
        return "gh api write to parameterized /repos/ path"
    if _GH_RELEASE_RE.search(line):
        return "gh release write to parameterized -R target"
    return None


def _find_actions_bot_bypass(
    job_id: str, job: dict[str, Any], path: str,
) -> tuple[str, list[Any]] | None:
    """Return ``(label, locations)`` when the job assumes the
    github-actions[bot] identity AND pushes git in the same scope.

    Job-scoped because the identity assignment and the push commonly
    span steps (one ``git config user.name``, one ``git push`` later).
    The label points at the push step so the report shows the
    privilege-using line, not the cosmetic identity line.
    """
    has_bot_identity = False
    push_step: dict[str, Any] | None = None
    push_step_name = ""
    for idx, step in enumerate(iter_steps(job)):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if _ACTIONS_BOT_IDENTITY_RE.search(run):
            has_bot_identity = True
        if _ANY_GIT_PUSH_RE.search(run) and push_step is None:
            push_step = step
            push_step_name = (
                step.get("name") or step.get("id") or f"steps[{idx}]"
            )
    if not (has_bot_identity and push_step is not None):
        return None
    label = (
        f"{job_id}.{push_step_name}: git push as github-actions[bot] "
        f"(branch-protection bypass-allowlist abuse shape)"
    )
    return label, [step_location(path, push_step)]


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for line in run.splitlines():
                label = _line_pushes_externally(line)
                if label is None:
                    continue
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"{job_id}.{name}: {label}")
                locations.append(step_location(path, step))
                break  # one offender per step is enough
        bot_bypass = _find_actions_bot_bypass(job_id, job, path)
        if bot_bypass is not None:
            label, locs = bot_bypass
            offenders.append(label)
            locations.extend(locs)
    passed = not offenders
    desc = (
        "No workflow step pushes to a parameterized external repo."
        if passed else
        f"{len(offenders)} step(s) push to a parameterized destination: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Cross-repo writes from "
        f"CI are the worm-propagation primitive Shai-Hulud relied on."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
