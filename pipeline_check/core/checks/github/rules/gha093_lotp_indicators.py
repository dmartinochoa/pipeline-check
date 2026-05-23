"""GHA-093. Living-off-the-Pipeline indicators (workflow-command abuse).

Inspired by zizmor proposal #1948 (LOTP). Detection-evasion via
built-in GitHub-Actions primitives that look innocuous on review:

1. **STEP_SUMMARY exfil.** ``echo "$SECRET" >> $GITHUB_STEP_SUMMARY``
   writes the value into the workflow run's Summary tab, which is
   surfaced to PR readers. The masker doesn't always register the
   secret in time (e.g. an env value set from a third-party action's
   output, or piped from a file the masker never saw). Distinct from
   GHA-087, this rule fires on the *no-transform* shape that bypasses
   the derived-value catch.

2. **Workflow-command log injection.** ``::warning::`` /
   ``::notice::`` / ``::error::`` lines interpolating an attacker-
   controlled context (a PR title, body, branch name, label, comment)
   carry that string into log lines downstream tooling parses as
   structured signals. Build dashboards and monitoring rules trust
   the workflow-command syntax; LOTP turns those into a typed
   message-passing primitive an external attacker can drive.

3. **``::add-mask::`` after print.** ``echo "$SECRET"`` *before*
   ``echo "::add-mask::$SECRET"`` leaks: the masker registers the
   value only when it processes the add-mask line, which is too late
   for the earlier echo. Subsequent lines mask correctly; the first
   one already shipped to the log.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-093",
    title="Living-off-the-Pipeline indicators (workflow-command abuse)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS", "ESF-D-INJECTION"),
    cwe=("CWE-532", "CWE-117", "CWE-200"),
    recommendation=(
        "Don't route secret-shaped values through the Summary tab "
        "and don't interpolate PR-controlled text into workflow "
        "commands. ``$GITHUB_STEP_SUMMARY`` is rendered to anyone "
        "with read access to the workflow run; treat it like a "
        "public-readable surface. ``::warning::`` / ``::notice::`` "
        "/ ``::error::`` are typed log-line directives; interpolate "
        "only trusted values into them (or quote the untrusted "
        "value through an env var and let the shell escape it). "
        "Always ``::add-mask::`` *before* the first time the value "
        "could appear in a log line, the order matters."
    ),
    docs_note=(
        "Three independent failure shapes, the rule fires on any "
        "of them:\n\n"
        "1. **STEP_SUMMARY exfil.** A ``run:`` line that combines a "
        "secret reference (``${{ secrets.* }}`` context or a "
        "``$NAME`` / ``${NAME}`` expansion of a step ``env:`` "
        "value bound to ``secrets.*``) with a redirect to "
        "``$GITHUB_STEP_SUMMARY``. Disjoint from GHA-087: that "
        "rule fires on transform-then-sink; this one fires on the "
        "no-transform shape.\n"
        "2. **Workflow-command log injection.** A ``::warning::`` "
        "/ ``::notice::`` / ``::error::`` directive whose message "
        "interpolates one of the attacker-controlled context "
        "expressions (PR title / body / labels / branch name, "
        "comment body, head_ref, etc.).\n"
        "3. **``::add-mask::`` after print.** Within the same "
        "``run:`` block, a print of a variable (``echo $X`` / "
        "``echo \"$X\"`` / ``printf`` / ``$X`` on its own line) "
        "preceded by no ``::add-mask::$X`` directive AND a later "
        "line that calls ``::add-mask::`` on the same variable. "
        "The directive applies to future log lines only; the "
        "earlier print already shipped to the log unmasked.\n\n"
        "Pairs with GHA-033 (secret echoed in shell trace) and "
        "GHA-087 (derived-value of a secret printed)."
    ),
    known_fp=(
        "STEP_SUMMARY is the legitimate sink for human-readable "
        "build digest content; the rule only flags secret-shaped "
        "references written there. If you need to surface a "
        "non-secret value that happens to share a name with a "
        "secret-bound env var, rename the env var. Workflow-"
        "command log-injection can be suppressed when the "
        "interpolation is into a value that's been sanitized "
        "upstream (a step that resolved the PR title through a "
        "literal-escape step), with a rationale that names the "
        "sanitizer.",
    ),
    incident_refs=(
        "LOTP (Living-off-the-Pipeline) research: collected from "
        "red-team write-ups demonstrating that built-in workflow "
        "primitives can act as untraced exfil channels (Trail of "
        "Bits 2024 LOTP series, Synacktiv Octoscan paper). The "
        "Summary tab and the typed workflow-command directives "
        "are the canonical examples; the add-mask ordering bug "
        "appears in GitHub's own field reports.",
    ),
)


#: Attacker-controlled context expressions. Mirrors the
#: ``_UNTRUSTED_CONTEXTS`` list GHA-053 uses for ``if:`` predicates,
#: same threat shape: a value the YAML reader can substring-match
#: but which a contributor with PR / issue / comment permissions
#: can drive.
_UNTRUSTED_CONTEXTS: tuple[str, ...] = (
    "github.event.head_commit.message",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.head_ref",
    "github.event.pull_request.labels",
    "github.event.pull_request.milestone.title",
    "github.event.pull_request.milestone.description",
)

#: Direct ``${{ secrets.<name> }}`` context expression in a body.
_SECRET_CTX_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z_]\w*\s*\}\}")

#: Redirect into the Summary file, both spellings.
_SUMMARY_SINK_RE = re.compile(
    r">>?\s*\"?\$\{?GITHUB_STEP_SUMMARY\}?\"?",
)

#: Workflow-command directives that carry message text to log lines.
_WORKFLOW_CMD_RE = re.compile(
    r"::(?:warning|notice|error)(?:\s[^:]*)?::",
)

#: An ``::add-mask::`` directive with a named variable, captures the
#: variable name (without the leading ``$``).
_ADD_MASK_RE = re.compile(
    r"::add-mask::\s*\$\{?(?P<name>[A-Za-z_]\w*)\}?",
)

#: A bash print of a variable (``echo $X`` / ``printf X``). Captures
#: the variable name. ``$X``-only / ``"${X}"`` shapes covered.
_PRINT_VAR_RE = re.compile(
    r"\b(?:echo|printf|tee)\b[^\n]*?\$\{?(?P<name>[A-Za-z_]\w*)\}?",
)

#: A GitHub-Actions expression interpolation block (``${{ ... }}``).
#: Captures the expression body so untrusted-context detection can
#: scope the substring check to actual interpolations (not literal
#: prose that happens to mention a context key).
_INTERPOLATION_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)


def _secret_env_vars(env_block: Any) -> set[str]:
    """Names of env vars whose value references ``${{ secrets.* }}``."""
    out: set[str] = set()
    if not isinstance(env_block, dict):
        return out
    for name, value in env_block.items():
        if isinstance(value, str) and "secrets." in value and "${{" in value:
            out.add(str(name))
    return out


def _line_has_secret_ref(line: str, secret_names: set[str]) -> bool:
    """True when *line* references a secret context or a secret-bound env."""
    if _SECRET_CTX_RE.search(line):
        return True
    for name in secret_names:
        if re.search(
            rf"\$(?:\{{{re.escape(name)}\b|{re.escape(name)}\b)", line,
        ):
            return True
    return False


def _line_has_untrusted_ctx(line: str) -> bool:
    """True when *line* interpolates an untrusted context expression.

    Restricted to substrings inside ``${{ ... }}`` interpolation
    blocks; literal prose mentioning a context key (e.g., a log
    message that names ``github.event.pull_request.title``) is not
    attacker-driven and must not fire the rule.
    """
    for match in _INTERPOLATION_RE.finditer(line):
        body = match.group(1)
        for ctx in _UNTRUSTED_CONTEXTS:
            if ctx in body:
                return True
    return False


def _scan_step_summary(run: str, secret_names: set[str]) -> list[str]:
    """Return offending lines for shape 1 (STEP_SUMMARY exfil)."""
    out: list[str] = []
    for raw_line in run.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not _SUMMARY_SINK_RE.search(line):
            continue
        if _line_has_secret_ref(line, secret_names):
            out.append(line if len(line) <= 80 else line[:77] + "...")
    return out


def _scan_workflow_cmd_injection(run: str) -> list[str]:
    """Return offending lines for shape 2 (workflow-command injection)."""
    out: list[str] = []
    for raw_line in run.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not _WORKFLOW_CMD_RE.search(line):
            continue
        if _line_has_untrusted_ctx(line):
            out.append(line if len(line) <= 80 else line[:77] + "...")
    return out


def _scan_add_mask_after_print(run: str) -> list[str]:
    """Return offending variable names for shape 3 (add-mask after print).

    Walks the run body line by line. A line carrying ``::add-mask::$X``
    registers the mask for X and does NOT count as a print of X
    (the line itself is a directive, not a value-emitting echo).
    Any earlier line that printed X without a prior add-mask leaks.
    """
    printed_before_mask: set[str] = set()
    masked: set[str] = set()
    leaked: list[str] = []
    for raw_line in run.splitlines():
        line = raw_line
        mask_match = _ADD_MASK_RE.search(line)
        if mask_match:
            mask_var = mask_match.group("name")
            if mask_var in printed_before_mask and mask_var not in leaked:
                leaked.append(mask_var)
            masked.add(mask_var)
            # Skip print-extraction for this line. The echo wrapper
            # carrying the workflow directive is not a print of the
            # mask-target value, GitHub parses the line as a command
            # and never emits the value content.
            continue
        for pm in _PRINT_VAR_RE.finditer(line):
            name = pm.group("name")
            if name in masked:
                # Already mask-registered; printing it now is the
                # safe case, doesn't count.
                continue
            printed_before_mask.add(name)
    return leaked


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    workflow_secret_names = _secret_env_vars(doc.get("env"))
    for job_id, job in iter_jobs(doc):
        job_secret_names = _secret_env_vars(job.get("env"))
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            secret_names = (
                workflow_secret_names
                | job_secret_names
                | _secret_env_vars(step.get("env"))
            )
            shape1 = _scan_step_summary(run, secret_names)
            shape2 = _scan_workflow_cmd_injection(run)
            shape3 = _scan_add_mask_after_print(run)
            if not (shape1 or shape2 or shape3):
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            parts: list[str] = []
            if shape1:
                parts.append(
                    f"secret -> STEP_SUMMARY ({len(shape1)} line(s))"
                )
            if shape2:
                parts.append(
                    f"workflow-command + untrusted context "
                    f"({len(shape2)} line(s))"
                )
            if shape3:
                parts.append(
                    f"add-mask after print (vars: {', '.join(shape3)})"
                )
            offenders.append(f"{job_id}.{name}: {'; '.join(parts)}")
            locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No Living-off-the-Pipeline indicators detected."
        if passed else
        f"{len(offenders)} step(s) carry Living-off-the-Pipeline "
        f"indicators: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. Built-in workflow "
        f"primitives are turning into exfiltration / log-injection "
        f"channels."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
