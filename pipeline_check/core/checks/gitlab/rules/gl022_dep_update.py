"""GL-022, dependency update command bypasses lockfile pins."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity, has_dep_update
from ...rule import Rule

RULE = Rule(
    id="GL-022",
    title="Dependency update command bypasses lockfile pins",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Remove dependency-update commands from CI. Use lockfile-pinned "
        "install commands (`npm ci`, `pip install -r requirements.txt`) "
        "and update dependencies via a dedicated PR workflow (e.g. "
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


check = yaml_blob_check(
    RULE,
    scanner=has_dep_update,
    pass_desc="No dependency-update commands detected.",
    fail_desc=lambda _: (
        "Dependency-update commands detected that bypass lockfile pins."
    ),
)
