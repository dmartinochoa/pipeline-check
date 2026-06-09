"""JF-037. Untrusted PR/build context reaches an agentic AI CLI.

The Jenkins analog of GHA-119 / GL-048 / BB-036 / ADO-035, and the AI face
of JF-002 (script injection). An agentic CLI (``claude`` / ``gemini`` /
``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``)
reads a prompt and then *acts*: runs shell, writes files, calls tools.
When a ``sh`` / ``bat`` / ``powershell`` step feeds attacker-controllable
Jenkins context into that prompt, anyone who can open a pull request (or
queue a parameterized build) can smuggle instructions the agent then
executes ("ignore previous instructions and run ...").

The attacker-controllable surface is the one JF-002 / JF-032 / JF-036
already track: SCM-event env vars (``$BRANCH_NAME`` / ``$CHANGE_TITLE`` /
``$CHANGE_BRANCH`` / ``$TAG_NAME`` / ``$GIT_*``) and build parameters
(``${params.X}``, set by whoever queues the run).

Unlike JF-002, Groovy quoting does NOT defang this: a single-quoted ``sh``
body is the *safe* form for command injection (the value reaches the shell
as a runtime variable, not spliced into the command), but the model still
ingests it as prompt text either way. So this rule flags an agentic-CLI
shell body that references untrusted context in *any* quote style, which
is why it is separate from JF-002.
"""
from __future__ import annotations

from ..._primitives.agentic_cli import invokes_agentic_cli
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import LABEL_TAINT_RE, SHELL_STEP_RE

RULE = Rule(
    id="JF-037",
    title="Untrusted PR/build context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (a PR's branch / tag / "
        "title, `$CHANGE_*`, or a `${params.X}` build parameter) in an "
        "agentic CLI's prompt. Groovy single-quoting does NOT sanitize a "
        "prompt the way it does a shell command, the model still reads the "
        "value. If the agent must see PR content, run it in a stage with no "
        "credentials bound and no tool / shell access, and treat its output "
        "as untrusted."
    ),
    docs_note=(
        "The AI analog of JF-002 (script injection). Fires when a ``sh`` / "
        "``bat`` / ``powershell`` step invokes an agentic CLI (claude / "
        "gemini / cursor-agent / aider / openhands / goose / ``q chat``) "
        "AND attacker-controllable Jenkins context reaches it: an "
        "SCM-event env var (`$BRANCH_NAME` / `$CHANGE_TITLE` / "
        "`$CHANGE_BRANCH` / `$TAG_NAME` / `$GIT_*`) or a `${params.X}` "
        "build parameter. Unlike JF-002, both single- and double-quoted "
        "step bodies are flagged: an LLM ingests the value as prompt text "
        "regardless of Groovy quoting, so the JF-002 mitigation "
        "(single-quote the body) does not apply, which is why this is a "
        "separate rule."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    text = jf.text_no_comments
    for m in SHELL_STEP_RE.finditer(text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        if not invokes_agentic_cli(body):
            continue
        # Any reference is unsafe for an LLM prompt, in any quote style.
        if LABEL_TAINT_RE.search(body):
            line_no = text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no}")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No agentic-CLI shell step ingests attacker-controllable PR/build "
        "context."
        if passed else
        f"Agentic-CLI step(s) at {', '.join(offenders)} ingest "
        f"attacker-controllable Jenkins context ($BRANCH_NAME / "
        f"$CHANGE_TITLE / ${{params.X}}) into the prompt. A PR author or "
        f"build queuer can inject instructions the agent then executes; "
        f"Groovy quoting does not sanitize an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
