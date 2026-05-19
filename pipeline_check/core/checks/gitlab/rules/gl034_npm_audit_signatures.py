"""GL-034. npm/pnpm install without `npm audit signatures` verification step."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-034",
    title="npm install without registry-signature verification step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add an ``npm audit signatures`` step (or ``pnpm audit "
        "signatures``) after the install. Lockfile pinning only "
        "guarantees the bytes installed match what the lockfile "
        "recorded; ``audit signatures`` is what verifies those bytes "
        "were signed by the maintainer the registry recognizes as the "
        "package's trusted publisher. Run it as a separate script "
        "line after ``npm ci`` and before any code from "
        "``node_modules/`` executes."
    ),
    docs_note=(
        "Fires once per pipeline file when:\n\n"
        "1. Some job's ``before_script:`` / ``script:`` / "
        "``after_script:`` runs an npm or pnpm install verb "
        "(``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, "
        "``pnpm i``, ``pnpm ci``);\n"
        "2. No job anywhere in the pipeline runs "
        "``npm audit signatures`` or ``pnpm audit signatures``.\n\n"
        "Yarn / Bun-only pipelines pass silently because the "
        "``audit signatures`` primitive is npm-CLI-specific (Yarn "
        "Berry's ``yarn npm audit`` does not yet verify registry "
        "trusted-publisher records). Pairs with the per-package "
        "lockfile rules NPM-002 / NPM-006: NPM-002 / NPM-006 verify "
        "*what* the lockfile pinned, GL-034 verifies the lockfile "
        "pinned what the maintainer actually signed."
    ),
    known_fp=(
        "Pipelines that build against a private registry without "
        "trusted-publisher records (legacy Artifactory, self-hosted "
        "Verdaccio without sigstore) cannot run ``audit signatures`` "
        "meaningfully. Suppress on the specific pipeline with a "
        "rationale that names the private registry.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026) / TanStack / axios patch-release "
        "compromises rode the gap between lockfile-pinned integrity "
        "and registry-signed-publisher provenance. ``npm audit "
        "signatures`` is the gate that consumes trusted-publisher "
        "records.",
    ),
)


_INSTALL_RE = re.compile(
    r"\b(?:npm|pnpm)\s+(?:ci|install|i)\b",
    re.IGNORECASE,
)
_AUDIT_SIGNATURES_RE = re.compile(
    r"\b(?:npm|pnpm)\s+audit\s+signatures\b",
    re.IGNORECASE,
)


def _global_script_lines(doc: dict[str, Any]) -> list[str]:
    """Top-level ``before_script:`` / ``after_script:`` lines.

    GitLab's top-level scripts apply to every job that doesn't
    override them; either an install or an audit-signatures line up
    there contributes to the same workflow-wide decision the rule
    makes.
    """
    out: list[str] = []
    for key in ("before_script", "after_script"):
        v = doc.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
        elif isinstance(v, str):
            out.append(v)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    audit_seen = False
    # Scan top-level scripts plus every job's scripts. We collect
    # install hits per-job for offender labeling, and a global
    # audit-seen flag because verification anywhere in the pipeline
    # is sufficient.
    for line in _global_script_lines(doc):
        if _AUDIT_SIGNATURES_RE.search(line):
            audit_seen = True
        if _INSTALL_RE.search(line):
            offenders.append(f"<top-level>: {line.strip()[:60]}")
    for job_name, job in iter_jobs(doc):
        for line in job_scripts(job):
            if _AUDIT_SIGNATURES_RE.search(line):
                audit_seen = True
            if _INSTALL_RE.search(line):
                offenders.append(f"{job_name}: {line.strip()[:60]}")
    if not offenders or audit_seen:
        desc = (
            "Pipeline declares no npm/pnpm install steps; signature "
            "verification not applicable."
            if not offenders else
            "Pipeline runs `npm audit signatures` after install; "
            "registry trusted-publisher records are verified before "
            "any installed code executes."
        )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description=desc,
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        f"{len(offenders)} npm/pnpm install step(s) run with no "
        f"`npm audit signatures` step in the pipeline: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Lockfile pinning "
        f"without signature verification confirms the bytes match "
        f"the lockfile, not that the bytes were signed by the "
        f"registry's trusted publisher for the package."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
