"""BB-031. pip install without `--require-hashes` (PYPI-007 from the roadmap)."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity, blob_lower
from ...rule import Rule

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


_PIP_INSTALL_RE = re.compile(
    r"\b(?:pip3?|python3?\s+-m\s+pip)\s+install\b",
    re.IGNORECASE,
)
_TOOLING_INSTALL_RE = re.compile(
    r"\b(?:pip3?|python3?\s+-m\s+pip)\s+install\s+"
    r"(?:--upgrade\s+|-U\s+|--user\s+|-q\s+|--quiet\s+)*"
    r"(?:pip(?:\s|$)|setuptools(?:\s|$)|wheel(?:\s|$)|virtualenv(?:\s|$)"
    r"|pip-tools(?:\s|$)|pipx(?:\s|$)|pip-audit(?:\s|$)"
    r"|cyclonedx-bom(?:\s|$)|semgrep(?:\s|$)|poetry(?:\s|$)|uv(?:\s|$)"
    r"|pipenv(?:\s|$)|hatch(?:\s|$)|build(?:\s|$)|twine(?:\s|$))",
    re.IGNORECASE,
)
_REQUIRE_HASHES_RE = re.compile(r"--require-hashes\b", re.IGNORECASE)
_HASH_PINNING_MANAGER_RE = re.compile(
    r"\b(?:"
    r"uv\s+(?:sync|pip\s+install|pip\s+sync|run|tool\s+install)"
    r"|poetry\s+install"
    r"|pipenv\s+install\s+--deploy"
    r"|pipenv\s+sync"
    r"|hatch\s+env\s+create"
    r")\b",
    re.IGNORECASE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    # ``blob_lower`` lowercases — that's fine, our regexes are
    # case-insensitive but we need the raw lines to detect mixed
    # tooling/real installs reliably. Walk lines manually instead.
    install_seen = False
    require_hashes_seen = bool(_REQUIRE_HASHES_RE.search(blob))
    hash_manager_seen = bool(_HASH_PINNING_MANAGER_RE.search(blob))
    for line in blob.splitlines():
        if _PIP_INSTALL_RE.search(line) and not _TOOLING_INSTALL_RE.search(line):
            install_seen = True
            break
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
