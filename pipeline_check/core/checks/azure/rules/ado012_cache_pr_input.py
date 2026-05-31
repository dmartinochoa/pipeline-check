"""ADO-012. Cache@2 keys must not derive from PR-controlled variables."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import CACHE_TAINT_RE

RULE = Rule(
    id="ADO-012",
    title="Cache@2 key derives from $(System.PullRequest.*)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345",),
    recommendation=(
        "Build the cache key from values the PR can't control: "
        "`$(Agent.OS)`, lockfile hashes, the pipeline name. Never "
        "reference `$(System.PullRequest.*)` or "
        "`$(Build.SourceBranch*)` from a cache key namespace."
    ),
    docs_note=(
        "`Cache@2` (and older `CacheBeta@1`) restore by key. A key "
        "including PR-controlled variables on PR-validated pipelines "
        "lets a PR seed a poisoned cache entry that a later default-"
        "branch pipeline restores."
    ),
    exploit_example=(
        "# Vulnerable: Cache@2 key derives from a PR-controlled variable.\n"
        "steps:\n"
        "  - task: Cache@2\n"
        "    inputs:\n"
        "      key: 'npm | $(System.PullRequest.SourceBranch)'\n"
        "      path: $(npm_config_cache)\n"
        "  - script: npm ci\n"
        "\n"
        "# Attack: on a PR-validated pipeline the attacker controls\n"
        "# SourceBranch. Their PR run seeds a cache entry under their\n"
        "# key; a later default-branch pipeline that resolves the same\n"
        "# key restores the poisoned cache and treats it as clean.\n"
        "\n"
        "# Safe: key on the lockfile hash, not PR-controlled input.\n"
        "  - task: Cache@2\n"
        "    inputs:\n"
        "      key: 'npm | \"$(Agent.OS)\" | package-lock.json'\n"
        "      path: $(npm_config_cache)"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            task = step.get("task")
            if not isinstance(task, str) or not task.startswith(("Cache@", "CacheBeta@")):
                continue
            inputs = step.get("inputs") or {}
            if not isinstance(inputs, dict):
                continue
            for key_field in ("key", "restoreKeys"):
                raw = inputs.get(key_field)
                if raw is None:
                    continue
                text = raw if isinstance(raw, str) else "\n".join(
                    str(v) for v in (raw or [])
                )
                if CACHE_TAINT_RE.search(text):
                    offenders.append(f"{job_loc}.{step_loc}.inputs.{key_field}")
    passed = not offenders
    desc = (
        "No `Cache@2` key derives from PR-controlled variables."
        if passed else
        f"`Cache@2` task key/restoreKeys derive from PR-controlled "
        f"variables in: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
