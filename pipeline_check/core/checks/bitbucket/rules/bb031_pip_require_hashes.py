"""BB-031. pip install without `--require-hashes` (PYPI-007 from the roadmap)."""
from __future__ import annotations

from typing import Any

from ..._primitives.dep_verification import (
    has_hash_pinning_manager,
    has_require_hashes,
    is_real_pip_install_line,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts

RULE = Rule(
    id="BB-031",
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
        "guarantee."
    ),
    docs_note=(
        "Fires once per ``bitbucket-pipelines.yml`` when some step's "
        "``script:`` runs a real ``pip install`` (excluding the "
        "tooling-bootstrap allowlist) AND no step in the file uses "
        "``--require-hashes`` or a hash-pinning manager (``uv sync`` "
        "/ ``poetry install`` / ``pipenv install --deploy``)."
    ),
    known_fp=(
        "Pipelines that build against a private index without "
        "SHA-256 hash records cannot run ``--require-hashes`` "
        "meaningfully. Suppress with a rationale that names the "
        "private index.",
    ),
    incident_refs=(
        "PyPI maintainer-account compromises (ctx 2022, "
        "requests-darwin-lite 2023) shipped malicious sdists / "
        "wheels under existing version pins.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    install_seen = False
    require_hashes_seen = False
    hash_manager_seen = False
    for _loc, step in iter_steps(doc):
        for line in step_scripts(step):
            if has_require_hashes(line):
                require_hashes_seen = True
            if has_hash_pinning_manager(line):
                hash_manager_seen = True
            if is_real_pip_install_line(line):
                install_seen = True
    if not install_seen or require_hashes_seen or hash_manager_seen:
        desc = (
            "Pipeline runs no real pip install commands; hash "
            "verification not applicable."
            if not install_seen else
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
        "pip install step(s) run without ``--require-hashes`` and "
        "the pipeline uses no hash-pinning manager. A registry that "
        "swaps the tarball mid-flight ships arbitrary code under "
        "the same version pin."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
