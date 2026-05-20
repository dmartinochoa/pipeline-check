"""GHA-060. pip install without `--require-hashes`."""
from __future__ import annotations

from typing import Any

from ..._primitives.dep_verification import (
    has_hash_pinning_manager,
    has_real_pip_install,
    has_require_hashes,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-060",
    title="pip install without `--require-hashes` verification",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Pin every dependency with a SHA-256 hash and install with "
        "``pip install -r requirements.txt --require-hashes``. The "
        "hash-pinned mode refuses to install any package whose "
        "downloaded tarball doesn't match a recorded SHA-256, which "
        "is the equivalent of npm's lockfile-integrity guarantee for "
        "PyPI. Generate the hashes with ``pip-compile "
        "--generate-hashes`` (from ``pip-tools``) or migrate to a "
        "package manager that hash-pins by default: ``uv sync`` "
        "(reads ``uv.lock``), ``poetry install`` (reads "
        "``poetry.lock``), or ``pipenv install --deploy`` (reads "
        "``Pipfile.lock``). The rule silent-passes when any of those "
        "managers runs in the same workflow."
    ),
    docs_note=(
        "Fires once per workflow when:\n\n"
        "1. The workflow runs a real ``pip install`` invocation "
        "(``pip install``, ``pip3 install``, ``python -m pip "
        "install``, ``python3 -m pip install``) that isn't a "
        "tooling-bootstrap exempted by the allowlist;\n"
        "2. No invocation in the workflow passes "
        "``--require-hashes`` AND no step uses a lockfile-consuming "
        "manager (``uv sync`` / ``uv pip sync``, ``poetry install``, "
        "``pipenv install --deploy`` / ``pipenv sync``).\n\n"
        "Tooling-bootstrap allowlist (silent-passes): ``pip install "
        "--upgrade pip``, ``pip install --upgrade setuptools wheel "
        "virtualenv``, ``pip install --upgrade pip-tools``, "
        "``pip install pipx``, ``pip install pip-audit / "
        "cyclonedx-bom / semgrep``. These are the same shapes "
        "GL-022 / BB-022 exempt for the dep-update rule.\n\n"
        "Pairs with the per-file PYPI-002 rule (lockfile hash pin "
        "presence) on the package-side: PYPI-002 verifies *what* "
        "the requirements file pinned, GHA-060 verifies the install "
        "command actually consumes those pins."
    ),
    known_fp=(
        "Pipelines that build against a private index without "
        "SHA-256 hash records (legacy DevPI, self-hosted simple "
        "indexes without per-file hashes) cannot run "
        "``--require-hashes`` meaningfully. Suppress on the specific "
        "workflow with a rationale that names the private index.",
        "One-off tool installs that aren't on the allowlist but are "
        "genuinely bootstrap-only (e.g. ``pip install some-niche-"
        "linter``). The right fix is usually to install via the "
        "lockfile-managed venv; if not feasible, suppress on the "
        "specific step.",
    ),
    incident_refs=(
        "PyPI maintainer-account compromises (ctx 2022, "
        "requests-darwin-lite 2024) shipped malicious sdists / "
        "wheels under existing version pins. ``--require-hashes`` "
        "would have refused the swapped artifact because the "
        "recorded SHA-256 wouldn't match the malicious tarball.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    install_offenders: list[tuple[str, str, dict[str, Any]]] = []
    require_hashes_seen = False
    hash_pinning_manager_seen = False
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if has_require_hashes(run):
                require_hashes_seen = True
            if has_hash_pinning_manager(run):
                hash_pinning_manager_seen = True
            if has_real_pip_install(run):
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                install_offenders.append((job_id, name, step))
    if not install_offenders or require_hashes_seen or hash_pinning_manager_seen:
        desc = (
            "Workflow runs no real pip install commands; hash "
            "verification not applicable."
            if not install_offenders else
            "Workflow's pip installs are hash-pinned via "
            "``--require-hashes`` or a hash-pinning manager "
            "(uv / poetry / pipenv)."
        )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description=desc,
            recommendation=RULE.recommendation, passed=True,
        )
    locations = [step_location(path, step) for _job, _name, step in install_offenders]
    labels = [f"{job}.{name}" for job, name, _step in install_offenders[:5]]
    desc = (
        f"{len(install_offenders)} pip install step(s) run without "
        f"``--require-hashes`` and the workflow uses no hash-pinning "
        f"manager: {', '.join(labels)}"
        f"{'…' if len(install_offenders) > 5 else ''}. A registry "
        f"that swaps the tarball mid-flight (cache poisoning, "
        f"compromised maintainer account) ships arbitrary code "
        f"under the same version pin."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
