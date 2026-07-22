"""GCB-013, package install bypasses registry integrity.

Detects git-URL installs without a commit pin, local-path installs,
and tarball-URL installs. Each of these routes around the registry's
integrity controls, an attacker who can move a branch head, drop a
sibling checkout, or change a served tarball can substitute code into
the build.

Mirrors GHA-029 / GL-027 / BB-027 / ADO-028 / CC-028 / JF-031. Uses
the cross-provider ``_primitives.lockfile_integrity`` primitive so
the install-shape catalog stays aligned.
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
        "integrity model, the build is technically reproducible but "
        "the source of truth is whatever the git ref / filesystem / "
        "tarball URL served most recently."
    ),
    exploit_example=(
        "# Vulnerable: a build step installs a dependency straight\n"
        "# from a git branch, bypassing the registry and lockfile.\n"
        "steps:\n"
        "  - name: python:3.12@sha256:abc123...\n"
        "    entrypoint: bash\n"
        "    args:\n"
        "      - -c\n"
        "      - pip install git+https://github.com/acme/helper.git\n"
        "\n"
        "# Attack: the install resolves the branch head at build\n"
        "# time, so whoever can move that branch (a maintainer, a\n"
        "# repo compromise, a typosquatted fork) controls the code\n"
        "# that runs in the build with the build's service account\n"
        "# and any mounted secrets. No registry signature or lockfile\n"
        "# digest gates it.\n"
        "\n"
        "# Safe: pin the git dependency to an immutable commit (or\n"
        "# publish it to Artifact Registry and install from there).\n"
        "steps:\n"
        "  - name: python:3.12@sha256:abc123...\n"
        "    entrypoint: bash\n"
        "    args:\n"
        "      - -c\n"
        "      - pip install git+https://github.com/acme/helper.git@<commit-sha>"
    ),
)


def _step_args_blobs(doc: dict[str, Any]) -> list[str]:
    """Space-join each step's ``entrypoint`` + ``args`` list so an
    install verb and its target that sit on separate ``args`` entries
    (``entrypoint: pip, args: [install, "git+https://..."]``) end up
    adjacent for the scanner. ``blob_lower`` newline-joins list items,
    which splits them apart."""
    out: list[str] = []
    steps = doc.get("steps")
    if not isinstance(steps, list):
        return out
    for step in steps:
        if not isinstance(step, dict):
            continue
        parts: list[str] = []
        ep = step.get("entrypoint")
        if isinstance(ep, str):
            parts.append(ep)
        args = step.get("args")
        if isinstance(args, list):
            parts.extend(a for a in args if isinstance(a, str))
        elif isinstance(args, str):
            parts.append(args)
        if parts:
            out.append(" ".join(parts))
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    combined = "\n".join([blob_lower(doc), *_step_args_blobs(doc)]).lower()
    hits = lockfile_integrity.scan(combined)
    passed = not hits
    kinds = sorted({h.kind for h in hits})
    unique = {(h.kind, h.snippet) for h in hits}
    desc = (
        "No integrity-bypassing package installs detected in this pipeline."
        if passed else
        f"{len(unique)} integrity-bypassing package install(s) detected "
        f"({', '.join(kinds)}): "
        f"{'; '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
