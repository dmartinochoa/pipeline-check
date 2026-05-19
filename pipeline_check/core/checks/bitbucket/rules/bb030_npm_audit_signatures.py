"""BB-030. npm/pnpm install without `npm audit signatures` verification step."""
from __future__ import annotations

from typing import Any

from ..._primitives.dep_verification import (
    has_npm_audit_signatures,
    has_npm_install,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts

RULE = Rule(
    id="BB-030",
    title="npm install without registry-signature verification step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add an ``npm audit signatures`` step (or ``pnpm audit "
        "signatures``) after the install. Lockfile pinning only "
        "guarantees the bytes installed match the lockfile; "
        "``audit signatures`` is what verifies those bytes were signed "
        "by the registry's trusted publisher for the package. Run it "
        "as a separate script line after ``npm ci`` and before any "
        "code from ``node_modules/`` executes."
    ),
    docs_note=(
        "Fires once per ``bitbucket-pipelines.yml`` when:\n\n"
        "1. Some step's ``script:`` runs an npm or pnpm install verb "
        "(``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, "
        "``pnpm i``, ``pnpm ci``);\n"
        "2. No step anywhere in the file runs ``npm audit "
        "signatures`` or ``pnpm audit signatures``.\n\n"
        "Yarn / Bun-only pipelines pass silently because the "
        "``audit signatures`` primitive is npm-CLI-specific (Yarn "
        "Berry's ``yarn npm audit`` does not yet verify registry "
        "trusted-publisher records). Pairs with the per-package "
        "lockfile rules NPM-002 / NPM-006."
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
        "and registry-signed-publisher provenance.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    install_seen = False
    audit_seen = False
    for _loc, step in iter_steps(doc):
        for line in step_scripts(step):
            if has_npm_audit_signatures(line):
                audit_seen = True
            if has_npm_install(line):
                install_seen = True
    if not install_seen or audit_seen:
        desc = (
            "Pipeline declares no npm/pnpm install steps; signature "
            "verification not applicable."
            if not install_seen else
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
        "npm/pnpm install step(s) run with no `npm audit signatures` "
        "step in the pipeline. Lockfile pinning without signature "
        "verification confirms the bytes match the lockfile, not that "
        "the bytes were signed by the registry's trusted publisher "
        "for the package."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
