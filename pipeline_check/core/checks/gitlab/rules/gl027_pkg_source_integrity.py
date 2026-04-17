"""GL-027 — package install from git URL / local path / tarball URL."""
from __future__ import annotations

from typing import Any

from ..._primitives import lockfile_integrity
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GL-027",
    title="Package install bypasses registry integrity (git / path / tarball source)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin git dependencies to a commit SHA "
        "(``pip install git+https://…/repo@<sha>``, "
        "``cargo install --git … --rev <sha>``). Publish private "
        "packages to an internal registry instead of installing "
        "from a filesystem path or tarball URL."
    ),
    docs_note=(
        "Complements GL-021 (missing lockfile flag). Git URL installs "
        "without a commit pin, local-path installs, and direct tarball "
        "URLs all bypass the registry integrity controls the lockfile "
        "relies on — an attacker who can move a branch head, drop a "
        "sibling checkout, or change a served tarball can substitute "
        "code into the build."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    hits = lockfile_integrity.scan(blob)
    passed = not hits
    kinds = sorted({h.kind for h in hits})
    desc = (
        "No integrity-bypassing package installs detected in this pipeline."
        if passed else
        f"{len(hits)} integrity-bypassing package install(s) detected "
        f"({', '.join(kinds)}): "
        f"{'; '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
