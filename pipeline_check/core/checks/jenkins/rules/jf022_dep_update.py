"""JF-022, dependency update command bypasses lockfile pins."""
from __future__ import annotations

from ...base import Finding, Severity, has_dep_update
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-022",
    title="Dependency update command bypasses lockfile pins",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Remove dependency-update commands from CI. Use lockfile-pinned "
        "install commands (`npm ci`, `pip install -r requirements.txt`) "
        "and update dependencies via a dedicated PR pipeline (e.g. "
        "Dependabot, Renovate)."
    ),
    docs_note=(
        "Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, "
        "`bundle update`, `cargo update`, `go get -u`, and "
        "`composer update`. These commands bypass lockfile pins and pull "
        "whatever version is currently latest. Tooling upgrades "
        "(`pip install --upgrade pip`) are exempted."
    ),
    known_fp=(
        "Common build-tool bootstrapping idioms "
        "(``pip install --upgrade pip``, "
        "``pip install --upgrade setuptools wheel virtualenv``) "
        "and security-tool installs (``pip install --upgrade "
        "pip-audit / cyclonedx-bom / semgrep``) are exempted by "
        "the ``DEP_UPDATE_RE`` tooling allowlist. Other "
        "tooling-upgrade idioms not yet on the list can still "
        "trip the rule. Defaults to MEDIUM confidence so CI "
        "gates can require ``--min-confidence HIGH`` to ignore.",
    ),
)

def check(jf: Jenkinsfile) -> Finding:
    found = has_dep_update(jf.text.lower())
    passed = not found
    desc = (
        "No dependency-update commands detected."
        if passed else
        "Dependency-update commands detected that bypass lockfile pins."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
