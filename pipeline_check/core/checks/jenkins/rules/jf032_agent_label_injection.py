"""JF-032 — ``agent { label }`` interpolates an attacker-controllable Groovy expression."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile, _skip_string
from ._helpers import LABEL_TAINT_RE

RULE = Rule(
    id="JF-032",
    title="Agent label interpolates attacker-controllable value",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-345",),
    recommendation=(
        "Hard-code agent labels to a specific pool name. If label "
        "selection has to be parameterised, validate the candidate "
        "value against an explicit allowlist before the build starts "
        "(Groovy ``if`` guard at the top of the pipeline), and never "
        "inline ``${params.X}`` / ``${env.BRANCH_NAME}`` / "
        "``${env.CHANGE_BRANCH}`` directly into ``label \"...\"``."
    ),
    docs_note=(
        "JF-014 catches agent labels that aren't ephemeral; this rule "
        "catches the upstream targeting choice. When ``label`` inside "
        "an ``agent { ... }`` block is computed from a build parameter "
        "or an SCM-controlled environment variable, whoever queues the "
        "build (or pushes the branch / opens the PR) picks which "
        "agent the job lands on — including any privileged label the "
        "controller exposes. Two attacker surfaces are flagged: "
        "untrusted ``env.*`` refs (``BRANCH_NAME``, ``CHANGE_BRANCH``, "
        "``TAG_NAME``, …) and ``params.X`` references (caller-"
        "controlled at trigger time). The rule walks all four "
        "``agent { ... }`` shapes — direct ``label``, the ``node "
        "{ label … }`` form, and ``docker { label … }`` / "
        "``dockerfile { label … }`` — via brace-balanced scan so "
        "nested DSL blocks parse correctly."
    ),
    known_fp=(
        "Author-controlled environment refs like ``${env.JOB_NAME}`` "
        "or ``${env.BUILD_NUMBER}`` are intentionally not flagged — "
        "those values come from Jenkins itself, not from the "
        "triggerer. Pipelines that intentionally select agents via a "
        "vetted parameter and gate the assignment behind a Groovy "
        "validator should suppress with ``.pipelinecheckignore`` and "
        "a rationale rather than disable the rule everywhere.",
    ),
)


_AGENT_HEAD_RE = re.compile(r"\bagent\s*\{")
_LABEL_STR_RE = re.compile(
    r"\blabel\s+(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')"
)


def _agent_blocks(text: str) -> list[str]:
    """Return the body text of every ``agent { ... }`` block in *text*.

    Walks Groovy braces depth-aware (mirrors the shape of
    ``base._extract_stages``) so a block containing nested DSL —
    ``agent { docker { image "..." label "..." } }`` — is captured
    in full. String literals are skipped via ``_skip_string`` so
    braces inside strings don't desync the depth count.
    """
    out: list[str] = []
    for head in _AGENT_HEAD_RE.finditer(text):
        i = head.end()
        depth = 1
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch in ('"', "'"):
                i = _skip_string(text, i) + 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[head.end():i - 1] if depth == 0 else text[head.end():]
        out.append(body)
    return out


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments or jf.text
    offenders: list[str] = []
    for body in _agent_blocks(text):
        for m in _LABEL_STR_RE.finditer(body):
            label = m.group(1) if m.group(1) is not None else m.group(2)
            if LABEL_TAINT_RE.search(label):
                offenders.append(label)
    passed = not offenders
    desc = (
        "No agent label interpolates attacker-controllable values."
        if passed else
        f"{len(offenders)} agent label(s) compute the target executor "
        f"from attacker-controllable input: "
        f"{', '.join(sorted(set(offenders))[:5])}"
        f"{'…' if len(set(offenders)) > 5 else ''}. "
        f"Whoever queues the build (or pushes the branch / opens the "
        f"PR) picks which agent the job lands on — including "
        f"privileged labels the controller exposes."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
