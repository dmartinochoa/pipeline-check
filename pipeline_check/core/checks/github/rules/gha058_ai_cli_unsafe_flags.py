"""GHA-058. Agentic CLI invoked with permission-bypass flags.

Two failure shapes:

  1. **Bypass-flag shape** (original): a ``run:`` body invokes an
     agentic CLI with a permission-bypass flag
     (``--dangerously-skip-permissions`` / ``--yolo`` / ...).

  2. **PR-checkout topology** (zizmor proposal #1605 / #1607): a
     job checks out a PR head AND later invokes an agentic CLI
     while a write-scope token is in scope. The flag itself does
     not need to be set, the topology IS the bug, an agent reading
     PR-controlled prompt text from the checked-out tree gets the
     runner's token as a side effect.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from ._helpers import AGENTIC_CLI_RE, PR_HEAD_REF_RE

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
        "Two detections feed the rule. Either is enough for the "
        "finding to fire.\n\n"
        "**A. Bypass-flag shape.** A ``run:`` body invokes one of the "
        "following CLIs with the matching permission-bypass flag:\n\n"
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
        "``q chat --trust-tools 'fs_read'``.\n\n"
        "**B. PR-checkout topology** (zizmor proposal #1605 / #1607). "
        "Step-order traversal within a job. Fires when an agentic CLI "
        "(any of the names above) runs in a step *after* a step that "
        "checked out a PR head (``actions/checkout`` with ``ref:`` "
        "interpolating ``github.event.pull_request.head.*``, "
        "``github.head_ref``, or a ``refs/pull/*/head`` literal) AND "
        "a write-scope token is in scope for the job (job-level "
        "``permissions: write-all``, any token granted ``write``, "
        "``id-token: write``, or no ``permissions:`` block declared "
        "anywhere, since the runtime default carries ``contents: "
        "write`` on most triggers). Pairs with GHA-045 (caller-"
        "controlled ref) and GHA-046 (manual PR-head fetch), the "
        "agentic-CLI primitive turns a contributor-controlled tree "
        "into a token-exfil tool, no bypass flag needed."
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


# CLI binary names come from the shared catalog (also used by GHA-119
# prompt injection); detected separately from the flags so the rule can
# report which CLI was invoked, not just "some agent."
_CLI_RE = AGENTIC_CLI_RE

# Permission-bypass flags. ``--dangerously-skip-permissions`` and
# ``--yolo`` are the most common; ``--trust-all-tools`` is the Amazon
# Q form; ``--full-auto`` / ``--auto`` are aider / openhands. The
# wildcard tool-allow-list (``--allowedTools '*'``, ``.*``, ``all``)
# is the equivalent "trust everything" knob.
_BYPASS_FLAGS_RE = re.compile(
    r"--(?:dangerously-skip-permissions|yolo|trust-all-tools"
    r"|full-auto|auto-approve|no-confirm)\b"
    # --allowedTools with a "trust everything" value. Anchored at the
    # first non-space char of the value so we don't match the literal
    # substring "all" inside a real tool name (CallTool, rally, …).
    r"|--allowedTools\s+(?:"
    r"[\"']?\*[\"']?"                    # *, "*", '*'
    r"|[\"']?\.\*[\"']?"                 # .*, ".*", '.*'
    r"|[\"']?all[\"']?(?!\w)"            # bare all (whole word), "all"
    r"|[\"'][^\"'\n]*\*[^\"'\n]*[\"']"   # quoted value containing *
    r")",
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


#: PR-head ref interpolations on an ``actions/checkout`` ``with.ref``.
def _step_checks_out_pr_head(step: dict[str, Any]) -> bool:
    """True when *step* checks out a PR head via ``actions/checkout``.

    Manual ``git fetch refs/pull/<n>/head`` shapes are covered by
    GHA-046 and don't need to fire this companion rule, the agentic-
    CLI topology only matters when the source tree is on disk where
    the agent can read it. We focus on the canonical
    ``actions/checkout`` path here.
    """
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    if not uses.lower().startswith("actions/checkout@"):
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    ref = with_block.get("ref")
    if not isinstance(ref, str):
        return False
    return bool(PR_HEAD_REF_RE.search(ref))


def _step_invokes_any_agentic_cli(body: str) -> str | None:
    """True when *body* invokes any agentic CLI (regardless of flags).

    The topology check fires on the bare invocation, the bug is the
    combination of PR-controlled tree + write-token + agent runtime,
    not the flag.
    """
    m = _CLI_RE.search(body)
    if m:
        return m.group(0).lower()
    return None


def _effective_permissions(doc: dict[str, Any], job: dict[str, Any]) -> Any:
    """Return the permissions block that governs *job*.

    Job-level overrides workflow-level. ``None`` means no permissions
    block was declared anywhere; the GitHub-Actions runtime default
    is ``contents: write`` on most triggers, which counts as write-
    scope for this rule's purposes.
    """
    if "permissions" in job:
        return job.get("permissions")
    return doc.get("permissions")


def _job_has_write_scope_token(doc: dict[str, Any], job: dict[str, Any]) -> bool:
    """True when *job* runs with any write-class token in scope."""
    perms = _effective_permissions(doc, job)
    if perms is None:
        # Runtime default carries contents: write on push / PR / etc.
        # The conservative call is "yes, write-scope is in scope."
        return True
    if isinstance(perms, str):
        return perms.lower() == "write-all"
    if not isinstance(perms, dict):
        return False
    for value in perms.values():
        if isinstance(value, str) and value.lower() == "write":
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        # Track within-job state for the PR-checkout topology path.
        # Reset per job: a checkout in one job doesn't reach into a
        # different job's runtime.
        pr_head_checkout_seen = False
        write_scope = _job_has_write_scope_token(doc, job)
        for idx, step in enumerate(iter_steps(job)):
            # Update the within-job state BEFORE evaluating the
            # current step, the topology fires only on agentic steps
            # that follow the checkout.
            if _step_checks_out_pr_head(step):
                pr_head_checkout_seen = True
            run = step.get("run")
            if not isinstance(run, str):
                continue
            # Bypass-flag shape (original).
            label = _step_invokes_unsafe_ai(run)
            if label is not None:
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"{job_id}.{name}: {label}")
                locations.append(step_location(path, step))
                continue
            # PR-checkout topology shape (widening).
            if pr_head_checkout_seen and write_scope:
                cli = _step_invokes_any_agentic_cli(run)
                if cli is not None:
                    name = (
                        step.get("name") or step.get("id")
                        or f"steps[{idx}]"
                    )
                    offenders.append(
                        f"{job_id}.{name}: {cli} runs after a "
                        f"PR-head checkout with write-scope token in "
                        f"scope"
                    )
                    locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No agentic CLI invoked with permission-bypass flags, and "
        "no agentic CLI runs in a job after a PR-head checkout with "
        "write-scope tokens in scope."
        if passed else
        f"{len(offenders)} step(s) run an agentic CLI in an unsafe "
        f"shape: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The Nx s1ngularity worm "
        f"used the bypass-flag primitive to convert installed AI CLIs "
        f"into filesystem-walking secret harvesters; the PR-checkout "
        f"topology achieves the same outcome by feeding the agent "
        f"contributor-controlled prompt text from the checked-out tree."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
