"""GHA-063. ``if:`` predicate compares actor to a bot login, spoofable.

zizmor's ``bot-conditions`` audit (the canonical writeup) flags the
shape ``if: github.actor == 'dependabot[bot]'`` (or
``github.triggering_actor``, or ``github.event.sender.login``).
The intuition is "only run this job when Dependabot triggered it"
but the comparison is a string equality against a context that a
maintainer can re-run a workflow under, and the re-run sets the
actor field to the re-runner's login, which can be any value
including ``dependabot[bot]``.

Same shape applies to other ``[bot]`` logins (``renovate[bot]``,
``github-actions[bot]``) and to the ``contains(..., 'bot')`` /
``endsWith(..., '[bot]')`` predicates that authors reach for as a
"is the trigger from any bot" shortcut.

The fix is: don't gate on the actor field. Gate on an authenticated
signal (``github.event.pull_request.user.type == 'Bot'`` together
with ``github.event.pull_request.user.login == 'dependabot[bot]'``,
or a maintainer-controlled CODEOWNERS / label check) that an
attacker re-running the workflow can't forge.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-063",
    title="``if:`` predicate gates on a spoofable bot-actor comparison",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-290",),  # Authentication Bypass by Spoofing
    recommendation=(
        "Don't gate on ``github.actor`` / ``github.triggering_actor`` "
        "/ ``github.event.sender.login``. Any maintainer with write "
        "access can re-run a workflow, which sets those fields to the "
        "re-runner's login, and on a PR they were merging the bot's "
        "side-effects can ride along. Use authenticated signals: "
        "``github.event.pull_request.user.type == 'Bot'`` together "
        "with a specific ``login`` check, or a maintainer-controlled "
        "label / CODEOWNERS gate."
    ),
    docs_note=(
        "Fires when a job-level or step-level ``if:`` expression "
        "compares one of the three actor-side context fields "
        "(``github.actor``, ``github.triggering_actor``, "
        "``github.event.sender.login``) to a bot login. Three "
        "spelling variations are detected:\n\n"
        "1. Equality against a literal ``*[bot]`` string:\n"
        "   ``github.actor == 'dependabot[bot]'``.\n"
        "2. ``contains(github.actor, 'bot')`` and the related "
        "``endsWith(github.actor, '[bot]')`` shortcut.\n"
        "3. Inequality used as a gate (``!= 'dependabot[bot]'``) "
        "is also flagged because the inverted form has the same "
        "spoofability surface.\n\n"
        "Out of scope (deliberate carve-out): predicates that pair "
        "the actor check with ``github.event.pull_request.user.type "
        "== 'Bot'`` are not flagged. The ``type`` field is set by "
        "GitHub from the account's registration record, not from "
        "the trigger, and a re-run can't forge it. The rule fires "
        "only when the actor comparison stands alone."
    ),
    known_fp=(
        "A workflow that legitimately wants to display a different "
        "log message when re-run by the bot (e.g. for human-"
        "readable triage) and isn't using the predicate as a "
        "security gate. Suppress per-step via ignore-file. Note "
        "that ``${{ github.actor != 'dependabot[bot]' }}`` as a "
        "*display* condition is still flagged because the rule "
        "can't tell display from gate; in practice the same "
        "expression is reused for both.",
    ),
    incident_refs=(
        "zizmor v1.25.2 ``bot-conditions`` audit: "
        "https://docs.zizmor.sh/audits/#bot-conditions",
    ),
    exploit_example=(
        "# Vulnerable: a maintainer who re-runs the workflow under\n"
        "# their own login still sees this job fire because the\n"
        "# actor was Dependabot at original-trigger time. Worse,\n"
        "# the re-run executes with the re-runner's write-scope\n"
        "# token even though the predicate claims to gate on\n"
        "# ``dependabot[bot]`` (a read-scope identity).\n"
        "on: pull_request\n"
        "jobs:\n"
        "  auto-merge:\n"
        "    if: ${{ github.actor == 'dependabot[bot]' }}\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { contents: write, pull-requests: write }\n"
        "    steps:\n"
        "      - run: gh pr merge --auto --squash \"${{ github.event."
        "pull_request.number }}\"\n"
        "\n"
        "# Safe: pair the login check with the account-type field,\n"
        "# which is set by GitHub from the registration record and\n"
        "# cannot be spoofed by a re-run.\n"
        "on: pull_request\n"
        "jobs:\n"
        "  auto-merge:\n"
        "    if: |\n"
        "      github.event.pull_request.user.type == 'Bot' &&\n"
        "      github.event.pull_request.user.login == 'dependabot[bot]'\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { contents: write, pull-requests: write }\n"
        "    steps:\n"
        "      - run: gh pr merge --auto --squash \"${{ github.event."
        "pull_request.number }}\""
    ),
)

#: Actor-side context fields whose values are observable but
#: spoofable across a workflow re-run.
_ACTOR_FIELDS: tuple[str, ...] = (
    "github.actor",
    "github.triggering_actor",
    "github.event.sender.login",
)

#: Equality / inequality with a literal ``*[bot]`` string. Captures
#: the comparator (``==`` / ``!=``) and the bot name. Quote style
#: is matched as either single or double; whitespace tolerated.
_BOT_EQ_RE = re.compile(
    r"(?P<lhs>github\.(?:actor|triggering_actor)|"
    r"github\.event\.sender\.login)\s*"
    r"(?P<op>==|!=)\s*"
    r"['\"](?P<bot>[A-Za-z0-9_-]+\[bot\])['\"]"
)

#: ``contains(github.actor, 'bot')`` / ``endsWith(github.actor,
#: '[bot]')`` and the swapped-argument variant ``contains(
#: 'dependabot[bot]', github.actor)``.
_BOT_FN_RE = re.compile(
    r"\b(?:contains|endsWith|startsWith)\s*\(\s*"
    r"(?:"
    r"(?:github\.(?:actor|triggering_actor)|github\.event\.sender\.login)\s*,"
    r"|"
    r"['\"][^'\"]*\[bot\][^'\"]*['\"]\s*,"
    r")"
)

#: ``user.type == 'Bot'`` paired-check carve-out: when this appears
#: on the same line as the actor comparison, the predicate is
#: authenticated and stays silent.
_USER_TYPE_BOT_RE = re.compile(
    r"github\.event\.[^.]+\.user\.type\s*==\s*['\"]Bot['\"]"
)


def _scan_expression(expr: str) -> list[str]:
    """Return offender labels for a single ``if:`` expression body.

    Empty list when the expression doesn't carry a spoofable
    actor-vs-bot predicate, or when each OR-clause carrying a bot
    comparison is paired with a ``user.type == 'Bot'`` authenticated
    check inside the same clause. The carve-out is evaluated per
    OR-clause so that ``A || (github.actor == 'dependabot[bot]')``
    still flags the unauthenticated half.
    """
    if not isinstance(expr, str) or not expr:
        return []
    out: list[str] = []
    for clause in re.split(r"\|\|", expr):
        if _USER_TYPE_BOT_RE.search(clause):
            continue
        for m in _BOT_EQ_RE.finditer(clause):
            out.append(
                f"``{m.group('lhs')} {m.group('op')} '{m.group('bot')}'``"
            )
        # Function-call shape: ``contains(github.actor, 'bot')``. We
        # don't extract a full label here, the canonical name is enough.
        if _BOT_FN_RE.search(clause):
            out.append("``contains/endsWith/startsWith(...bot...)``")
    return out


_AUTOMERGE_ACTIONS = (
    "hmarr/auto-approve-action",
    "peter-evans/enable-pull-request-automerge",
    "pascalgn/automerge-action",
    "reitermarkus/automerge",
)

_AUTOMERGE_CLI_RE = re.compile(
    r"gh\s+pr\s+(?:merge(?:\s+.*--auto)?|review\s+.*--approve)\b"
)


def _job_has_automerge(job: dict[str, Any]) -> bool:
    """True when the job contains an auto-approve or auto-merge step."""
    for step in iter_steps(job):
        uses = step.get("uses")
        if isinstance(uses, str):
            slug = uses.split("@", 1)[0].strip().lower()
            if any(slug == a for a in _AUTOMERGE_ACTIONS):
                return True
        run = step.get("run")
        if isinstance(run, str) and _AUTOMERGE_CLI_RE.search(run):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    has_confused_deputy = False
    for job_id, job in iter_jobs(doc):
        job_has_bot_gate = False
        job_if = job.get("if")
        for label in _scan_expression(job_if if isinstance(job_if, str) else ""):
            offenders.append(f"jobs.{job_id}.if: {label}")
            job_has_bot_gate = True
        for idx, step in enumerate(iter_steps(job)):
            step_if = step.get("if")
            for label in _scan_expression(
                step_if if isinstance(step_if, str) else "",
            ):
                offenders.append(f"jobs.{job_id}.steps[{idx}].if: {label}")
                job_has_bot_gate = True
        if job_has_bot_gate and _job_has_automerge(job):
            has_confused_deputy = True
    passed = not offenders
    severity = Severity.CRITICAL if has_confused_deputy else RULE.severity
    if passed:
        desc = (
            "No ``if:`` predicate gates on a spoofable bot-actor comparison."
        )
    elif has_confused_deputy:
        desc = (
            f"{len(offenders)} ``if:`` predicate(s) gate on a spoofable "
            f"bot-actor comparison: {'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. At least one of "
            f"these jobs also invokes an auto-approve or auto-merge "
            f"action, forming the Synacktiv confused-deputy primitive: "
            f"a maintainer re-running the workflow can approve and "
            f"merge arbitrary PRs under the bot's identity."
        )
    else:
        desc = (
            f"{len(offenders)} ``if:`` predicate(s) gate on a spoofable "
            f"bot-actor comparison: {'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. A maintainer "
            f"re-running the workflow can set the actor to the bot "
            f"login, bypassing the gate."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
