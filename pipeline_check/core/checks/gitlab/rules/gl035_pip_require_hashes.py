"""GL-035. pip install without `--require-hashes`."""
from __future__ import annotations

from typing import Any

from ..._primitives.dep_verification import (
    has_hash_pinning_manager,
    has_require_hashes,
    is_real_pip_install_line,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-035",
    title="pip install without `--require-hashes` verification",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Pin every dependency with a SHA-256 hash and install with "
        "``pip install -r requirements.txt --require-hashes``, or "
        "migrate to a manager that hash-pins by default: ``uv sync``, "
        "``poetry install``, ``pipenv install --deploy``. Hash-pinned "
        "install is the PyPI equivalent of npm's lockfile-integrity "
        "guarantee: it refuses to install any tarball whose SHA-256 "
        "doesn't match a recorded entry."
    ),
    docs_note=(
        "Fires once per pipeline file when:\n\n"
        "1. Some job's ``before_script:`` / ``script:`` / "
        "``after_script:`` runs a real ``pip install`` (``pip "
        "install``, ``pip3 install``, ``python -m pip install``) "
        "that isn't a tooling-bootstrap exempted by the allowlist;\n"
        "2. No job uses ``--require-hashes`` AND no job uses a "
        "lockfile-consuming manager (``uv sync`` / ``uv pip sync``, "
        "``poetry install``, ``pipenv install --deploy`` / ``pipenv "
        "sync``).\n\n"
        "Tooling-bootstrap allowlist (same as GHA-060)."
    ),
    known_fp=(
        "Pipelines that build against a private index without "
        "SHA-256 hash records (legacy DevPI, self-hosted simple "
        "indexes without per-file hashes) cannot run "
        "``--require-hashes`` meaningfully. Suppress on the specific "
        "pipeline with a rationale that names the private index.",
    ),
    incident_refs=(
        "PyPI maintainer-account compromises (ctx 2022, "
        "requests-darwin-lite 2024) shipped malicious sdists / "
        "wheels under existing version pins; ``--require-hashes`` "
        "would have refused the swap.",
    ),
)


def _global_script_lines(doc: dict[str, Any]) -> list[str]:
    """Top-level + ``default:`` ``before_script:`` / ``after_script:`` lines."""
    out: list[str] = []
    sources: list[dict[str, Any]] = [doc]
    default = doc.get("default")
    if isinstance(default, dict):
        sources.append(default)
    for src in sources:
        for key in ("before_script", "after_script"):
            v = src.get(key)
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        out.append(item)
            elif isinstance(v, str):
                out.append(v)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    require_hashes_seen = False
    hash_manager_seen = False
    for line in _global_script_lines(doc):
        if has_require_hashes(line):
            require_hashes_seen = True
        if has_hash_pinning_manager(line):
            hash_manager_seen = True
        if is_real_pip_install_line(line):
            offenders.append(f"<top-level>: {line.strip()[:60]}")
    for job_name, job in iter_jobs(doc):
        for line in job_scripts(job):
            if has_require_hashes(line):
                require_hashes_seen = True
            if has_hash_pinning_manager(line):
                hash_manager_seen = True
            if is_real_pip_install_line(line):
                offenders.append(f"{job_name}: {line.strip()[:60]}")
    if not offenders or require_hashes_seen or hash_manager_seen:
        desc = (
            "Pipeline runs no real pip install commands; hash "
            "verification not applicable."
            if not offenders else
            "Pipeline's pip installs are hash-pinned via "
            "``--require-hashes`` or a hash-pinning manager "
            "(uv / poetry / pipenv)."
        )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description=desc,
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        f"{len(offenders)} pip install step(s) run without "
        f"``--require-hashes`` and the pipeline uses no hash-pinning "
        f"manager: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A registry that swaps "
        f"the tarball mid-flight ships arbitrary code under the same "
        f"version pin."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
