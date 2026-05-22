"""GHA-071. ``shell: pwsh`` (or ``powershell``) on a Linux / macOS step.

zizmor proposal #288 (``powershell-on-linux``). A ``run:`` step's
shell defaults to ``bash`` on ``runs-on: ubuntu-*`` /
``macos-*``. An explicit ``shell: pwsh`` (or
``shell: powershell``) on a non-Windows runner silently flips
the language and tokenization rules. An injection that's a
no-op in bash (``$(cmd)`` evaluating to empty, or a stray
``;`` ignored) can be live in pwsh. Likewise an escaping rule
that's safe in pwsh (single-quoted strings without parameter
expansion) can be exploitable in bash.

The fix: name the shell explicitly on every step that does
non-trivial work, and use the shell that matches the runner's
OS. If multi-OS support is required, name two ``run:`` blocks
gated on ``runs-on:``.
"""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-071",
    title="``shell: pwsh`` / ``powershell`` on a Linux / macOS step",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-704",),  # Incorrect Type Conversion or Cast
    recommendation=(
        "Drop the explicit ``shell:`` on non-Windows runners so "
        "GitHub's default (``bash``) is used. If multiline "
        "PowerShell work is genuinely needed on Linux / macOS, "
        "isolate it in a separate job that pins ``runs-on:`` to a "
        "Windows image, OR name the shell explicitly per-step so "
        "the reviewer can confirm the language match. Mixing pwsh "
        "and bash semantics inside the same workflow is a "
        "low-impact-but-real source of escaping bugs."
    ),
    docs_note=(
        "Fires when a ``run:`` step (job-level or workflow-level "
        "default) declares ``shell: pwsh`` / ``shell: powershell`` "
        "while the job's ``runs-on:`` is a Linux or macOS image. "
        "Three sources are considered:\n\n"
        "1. ``jobs.<id>.steps[].shell:`` (step-level override).\n"
        "2. ``jobs.<id>.defaults.run.shell:`` (job-level "
        "default).\n"
        "3. ``defaults.run.shell:`` (workflow-level default).\n\n"
        "Out of scope: ``shell: bash`` / ``shell: sh`` on a "
        "Windows runner. Bash is preinstalled on every "
        "GitHub-hosted Windows image and the cross-shell language "
        "drift goes in the other direction (Windows-only built-"
        "ins missing). The risk-asymmetry is intentional: pwsh on "
        "Linux is the canonical zizmor advisory; the inverse is "
        "covered by reviewer attention rather than a rule."
    ),
    known_fp=(
        "PowerShell-heavy organizations standardizing on pwsh "
        "across all OS targets for tooling consistency. Suppress "
        "per-step via ignore-file when the operator has audited "
        "the workflow's escaping conventions against the pwsh "
        "tokenizer. The rule is LOW severity and advisory, the "
        "FP rate is acceptable for a default-fire posture.",
    ),
    incident_refs=(
        "zizmor proposal #288 (powershell-on-linux audit): "
        "https://github.com/zizmorcore/zizmor/issues/288",
    ),
    exploit_example=(
        "# Vulnerable: pwsh on Linux. A reviewer reads the\n"
        "# script with bash eyes, an injection in ``$INPUT``\n"
        "# might pass bash quoting but fire under pwsh parsing.\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    defaults:\n"
        "      run:\n"
        "        shell: pwsh\n"
        "    steps:\n"
        "      - run: Write-Output \"hello $env:INPUT\"\n"
        "\n"
        "# Safe: name the shell explicitly per-step on the OS\n"
        "# that ships it as default. Reviewers see the language\n"
        "# match the runner.\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - shell: bash\n"
        "        run: echo \"hello $INPUT\""
    ),
)


_POWERSHELL_SHELLS: frozenset[str] = frozenset({"pwsh", "powershell"})

_NON_WINDOWS_RUNNER_PREFIXES: tuple[str, ...] = (
    "ubuntu",
    "macos",
    "linux",
)


def _runs_on_is_non_windows(value: Any) -> bool:
    """True when the job's ``runs-on:`` names a Linux or macOS runner."""
    if isinstance(value, str):
        v = value.strip().lower()
        return any(v.startswith(p) for p in _NON_WINDOWS_RUNNER_PREFIXES)
    if isinstance(value, list):
        # Self-hosted-style label list: bail. We can't infer the OS
        # from a free-form label list; out of scope for this rule.
        return False
    if isinstance(value, dict):
        labels = value.get("labels")
        if isinstance(labels, str):
            v = labels.strip().lower()
            return any(v.startswith(p) for p in _NON_WINDOWS_RUNNER_PREFIXES)
    return False


def _shell_value(value: Any) -> str | None:
    """Normalize a ``shell:`` value to lowercase string or None."""
    if not isinstance(value, str):
        return None
    return value.strip().lower()


def _is_powershell(shell: str | None) -> bool:
    return shell is not None and shell in _POWERSHELL_SHELLS


def _workflow_default_shell(doc: dict[str, Any]) -> str | None:
    defaults = doc.get("defaults")
    if not isinstance(defaults, dict):
        return None
    run = defaults.get("run")
    if not isinstance(run, dict):
        return None
    return _shell_value(run.get("shell"))


def _job_default_shell(job: dict[str, Any]) -> str | None:
    defaults = job.get("defaults")
    if not isinstance(defaults, dict):
        return None
    run = defaults.get("run")
    if not isinstance(run, dict):
        return None
    return _shell_value(run.get("shell"))


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    workflow_default = _workflow_default_shell(doc)
    for job_id, job in iter_jobs(doc):
        if not _runs_on_is_non_windows(job.get("runs-on")):
            continue
        job_default = _job_default_shell(job)
        # Effective default = job override > workflow default.
        effective_default = job_default if job_default is not None else workflow_default
        # Check per-step shells. A step's explicit ``shell:`` wins
        # over the default; without one, the default applies.
        for idx, step in enumerate(iter_steps(job)):
            if step.get("run") is None:
                continue  # ``uses:`` steps don't pick a shell
            step_shell = _shell_value(step.get("shell"))
            effective = step_shell if step_shell is not None else effective_default
            if _is_powershell(effective):
                source = (
                    "step ``shell:``"
                    if step_shell is not None
                    else (
                        "job defaults"
                        if job_default is not None
                        else "workflow defaults"
                    )
                )
                offenders.append(f"{job_id}[{idx}] ({source}: {effective})")
                line = _line_of(step)
                if line is not None:
                    locations.append(Location(
                        path=path, start_line=line, end_line=line,
                    ))
    passed = not offenders
    desc = (
        "No ``shell: pwsh`` / ``powershell`` on a Linux / macOS step."
        if passed else
        f"{len(offenders)} step(s) run pwsh / powershell on a Linux "
        f"or macOS runner: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. Cross-shell "
        f"language drift is a low-impact source of escaping bugs."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
