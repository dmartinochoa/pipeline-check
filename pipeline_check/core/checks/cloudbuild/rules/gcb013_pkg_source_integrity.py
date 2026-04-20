"""GCB-013 — package install bypasses registry integrity.

Detects git-URL installs without a commit pin, local-path installs,
and tarball-URL installs. Each of these routes around the registry's
integrity controls — an attacker who can move a branch head, drop a
sibling checkout, or change a served tarball can substitute code into
the build.

Mirrors GHA-029 / GL-027 / BB-027 / ADO-028 / CC-028 / JF-031. Uses
the cross-provider ``_primitives.lockfile_integrity`` primitive so
the install-shape catalogue stays aligned.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import lockfile_integrity
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GCB-013",
    title="Package install bypasses registry integrity (git / path / tarball)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin git dependencies to a commit SHA "
        "(``pip install git+https://…/repo@<sha>``, "
        "``cargo install --git … --rev <sha>``). Publish private "
        "packages to Artifact Registry (or another internal registry) "
        "instead of installing from a filesystem path or tarball URL."
    ),
    docs_note=(
        "Complements GCB-012 (literal secrets) and GCB-010 (curl-pipe). "
        "Where those catch attacker content at fetch time, this rule "
        "catches installs that silently bypass the lockfile/registry "
        "integrity model — the build is technically reproducible but "
        "the source of truth is whatever the git ref / filesystem / "
        "tarball URL served most recently."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = lockfile_integrity.scan(blob_lower(doc))
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
