"""JF-031 — package install from git URL / local path / tarball URL."""
from __future__ import annotations

from ..._primitives import lockfile_integrity
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-031",
    title="Package install bypasses registry integrity (git / path / tarball source)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin git dependencies to a commit SHA. Publish private "
        "packages to an internal registry (Artifactory, Nexus) "
        "instead of installing from a filesystem path or tarball URL."
    ),
    docs_note=(
        "Complements JF-021 (missing lockfile flag). Git URL installs "
        "without a commit pin, local-path installs, and direct tarball "
        "URLs bypass the registry integrity controls the lockfile "
        "relies on."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    hits = lockfile_integrity.scan(jf.text_no_comments)
    passed = not hits
    kinds = sorted({h.kind for h in hits})
    desc = (
        "No integrity-bypassing package installs detected in this Jenkinsfile."
        if passed else
        f"{len(hits)} integrity-bypassing package install(s) detected "
        f"({', '.join(kinds)}): "
        f"{'; '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
