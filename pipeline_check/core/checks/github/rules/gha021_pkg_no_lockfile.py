"""GHA-021 — package install without lockfile enforcement."""
from __future__ import annotations

from typing import Any

from ...base import PKG_NO_LOCKFILE_RE, Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-021",
    title="Package install without lockfile enforcement",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Use lockfile-enforcing install commands: `npm ci` instead of "
        "`npm install`, `pip install --require-hashes -r requirements.txt`, "
        "`yarn install --frozen-lockfile`, `bundle install --frozen`, "
        "and `go install tool@v1.2.3`."
    ),
    docs_note=(
        "Detects package-manager install commands that do not enforce a "
        "lockfile or hash verification. Without lockfile enforcement the "
        "resolver pulls whatever version is currently latest — exactly "
        "the window a supply-chain attacker exploits."
    ),
)

def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    matches = PKG_NO_LOCKFILE_RE.findall(blob)
    passed = not matches
    desc = (
        "All package install commands enforce lockfile integrity."
        if passed else
        f"Package install without lockfile enforcement detected: "
        f"{', '.join(m.strip() for m in matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
