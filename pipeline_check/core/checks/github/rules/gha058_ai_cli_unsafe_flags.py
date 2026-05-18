"""GHA-058. Agentic CLI invoked with permission-bypass flags."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-058",
    title="Agentic CLI invoked with permission-bypass flags",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-INJECTION"),
    cwe=("CWE-269", "CWE-732"),
    recommendation=(
        "Don't run an agentic CLI (claude / gemini / q / cursor-agent "
        "/ aider / openhands / goose) with its safety flags disabled "
        "inside CI. The flags ``--dangerously-skip-permissions``, "
        "``--yolo``, ``--trust-all-tools``, ``--allowedTools \"*\"`` "
        "let the agent shell out, read arbitrary files, and post to "
        "arbitrary HTTP endpoints with no per-action prompt — under "
        "the runner's identity. In CI that means it can read every "
        "``${{ secrets.* }}`` value the workflow has access to and "
        "POST them anywhere. Either drop the bypass flag (and accept "
        "the manual confirmation prompts CI can't satisfy, so don't "
        "run it in CI at all), or gate the step behind a protected "
        "``environment:`` and pre-vet the prompt that's being fed to "
        "the agent."
    ),
    docs_note=(
        "Fires on a ``run:`` body invoking any of the following CLIs "
        "with the matching permission-bypass flag:\n\n"
        "* ``claude … --dangerously-skip-permissions``\n"
        "* ``gemini … --yolo``\n"
        "* ``q chat … --trust-all-tools``\n"
        "* ``cursor-agent …`` (any unprotected invocation; the CLI's "
        "default mode is the unsafe one)\n"
        "* any of the above with ``--allowedTools '*'`` / "
        "``--allowedTools '.*'`` / ``--allowedTools all``\n"
        "* ``aider`` / ``openhands`` / ``goose`` with equivalent "
        "``--auto`` / ``--no-confirm`` / ``--full-auto`` flags.\n\n"
        "Does NOT fire on a clearly-scoped invocation, e.g. ``claude "
        "--allowedTools 'Read,Grep'`` with a literal allow-list, or "
        "``q chat --trust-tools 'fs_read'``."
    ),
    known_fp=(
        "Internal tooling that legitimately runs an agentic CLI in "
        "CI (e.g. a doc-generation job) might pass a bypass flag for "
        "convenience. The right fix is to scope the allow-list "
        "rather than suppress the rule. If suppression is truly the "
        "only path, do it on the specific step with a rationale that "
        "names which tools the agent is allowed to invoke.",
    ),
    incident_refs=(
        "Nx s1ngularity compromise (Aug 2025): the malicious "
        "postinstall payload looked for ``claude``, ``gemini``, and "
        "``q`` on PATH and invoked them with "
        "``--dangerously-skip-permissions`` / ``--yolo`` / "
        "``--trust-all-tools`` plus a prompt that walked the "
        "filesystem and emitted any secret-shaped values. The same "
        "primitive in a CI workflow turns the runner's secrets into "
        "an open buffet for whoever can land a PR. "
        "https://nx.dev/blog/s1ngularity-postmortem",
    ),
    exploit_example=(
        "# Vulnerable: the bypass flag turns the agent into an\n"
        "# unattended shell that can read ``${{ secrets.* }}`` and\n"
        "# POST anywhere on the internet. This is the s1ngularity\n"
        "# postinstall pattern lifted into a workflow.\n"
        "jobs:\n"
        "  agentic:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          npm i -g @anthropic-ai/claude-code\n"
        "          claude --dangerously-skip-permissions \\\n"
        "            -p 'walk the filesystem and dump anything secret-shaped'\n"
        "\n"
        "# Safe: the agent runs with a literal tool allow-list, no\n"
        "# blanket bypass. The job is also environment-gated so the\n"
        "# prompt itself is reviewed before execution.\n"
        "jobs:\n"
        "  agentic:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: agentic-review\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: claude --allowedTools 'Read,Grep' -p \"$PROMPT\""
    ),
)


# CLI binary names. Detected separately from the flags so the rule
# can report which CLI was invoked, not just "some agent."
_CLI_NAMES = r"(?:claude|gemini|q\s+chat|cursor-agent|aider|openhands|goose)"
_CLI_RE = re.compile(rf"\b{_CLI_NAMES}\b", re.IGNORECASE)

# Permission-bypass flags. ``--dangerously-skip-permissions`` and
# ``--yolo`` are the most common; ``--trust-all-tools`` is the Amazon
# Q form; ``--full-auto`` / ``--auto`` are aider / openhands. The
# wildcard tool-allow-list (``--allowedTools '*'``, ``.*``, ``all``)
# is the equivalent "trust everything" knob.
_BYPASS_FLAGS_RE = re.compile(
    r"--(?:dangerously-skip-permissions|yolo|trust-all-tools"
    r"|full-auto|auto-approve|no-confirm)\b"
    r"|--allowedTools\s+[\"']?(?:\*|\.\*|all|.*\*.*)[\"']?",
    re.IGNORECASE,
)

# ``cursor-agent`` itself runs in unattended mode by default, so any
# invocation in CI counts as bypass-shaped. ``q chat`` similarly when
# invoked headlessly; we keep that one tied to a bypass flag to avoid
# flagging legitimate interactive usage from a self-hosted runner.
_ALWAYS_UNSAFE_CLI_RE = re.compile(r"\bcursor-agent\b", re.IGNORECASE)


def _step_invokes_unsafe_ai(body: str) -> str | None:
    """Return a short label for the unsafe pattern in *body*, or ``None``."""
    if _ALWAYS_UNSAFE_CLI_RE.search(body):
        return "cursor-agent invoked (default mode is unattended)"
    # All other CLIs require both a CLI mention and a bypass flag in
    # the same line (or two-line window for ``\`` continuations).
    for line_pair in _line_windows(body):
        if _CLI_RE.search(line_pair) and _BYPASS_FLAGS_RE.search(line_pair):
            cli_match = _CLI_RE.search(line_pair)
            cli = cli_match.group(0).lower() if cli_match else "ai-cli"
            return f"{cli} invoked with permission-bypass flag"
    return None


def _line_windows(body: str) -> list[str]:
    r"""Yield each line and each two-line pair (to catch shell
    continuations via trailing ``\``)."""
    lines = body.splitlines()
    out: list[str] = list(lines)
    for i in range(len(lines) - 1):
        out.append(lines[i] + " " + lines[i + 1])
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            label = _step_invokes_unsafe_ai(run)
            if label is None:
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"{job_id}.{name}: {label}")
            locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No agentic CLI invoked with permission-bypass flags."
        if passed else
        f"{len(offenders)} step(s) run an agentic CLI with safety "
        f"flags disabled: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The Nx s1ngularity worm "
        f"used this exact primitive to convert installed AI CLIs into "
        f"filesystem-walking secret harvesters."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
