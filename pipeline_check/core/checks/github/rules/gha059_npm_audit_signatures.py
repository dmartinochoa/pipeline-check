"""GHA-059. npm/pnpm install without `npm audit signatures` verification step."""
from __future__ import annotations

from typing import Any

from ..._primitives.dep_verification import (
    has_npm_audit_signatures,
    has_npm_install,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-059",
    title="npm install without registry-signature verification step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add an ``npm audit signatures`` step (or ``pnpm audit "
        "signatures``) after the install step. Lockfile pinning "
        "guarantees installed bytes match what the lockfile recorded; "
        "``audit signatures`` verifies those bytes were signed by the "
        "registry-trusted publisher for the package. Without it, a "
        "compromised maintainer account can publish a malicious "
        "version that the next lockfile refresh will pin and install "
        "without complaint, because integrity-only checks have no "
        "view into who actually signed the bytes. Place the step "
        "after ``npm ci`` / ``pnpm install`` and before any code from "
        "``node_modules/`` runs (``npm run build``, test, publish)."
    ),
    docs_note=(
        "Fires once per workflow when:\n\n"
        "1. The workflow runs at least one npm / pnpm install command "
        "(``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, "
        "``pnpm i``, ``pnpm ci``);\n"
        "2. No step anywhere in the workflow runs ``npm audit "
        "signatures`` or ``pnpm audit signatures``.\n\n"
        "Yarn / Bun-only workflows pass silently because the "
        "``audit signatures`` primitive is npm-CLI-specific (Yarn "
        "Berry's equivalent ``yarn npm audit`` does not yet verify "
        "registry trusted-publisher signatures; Bun has no equivalent "
        "step). The rule pairs with NPM-002 (lockfile entry missing "
        "integrity hash) and NPM-006 (known-compromised package "
        "version): NPM-002 / NPM-006 verify *what* the lockfile "
        "pinned, and GHA-059 verifies the lockfile pinned what the "
        "maintainer actually signed."
    ),
    known_fp=(
        "Workflows that build and test against a private registry "
        "without trusted-publisher records (legacy Artifactory, "
        "self-hosted Verdaccio without sigstore integration) cannot "
        "run ``npm audit signatures`` meaningfully — the registry has "
        "no signatures to verify against. Suppress this rule on the "
        "specific workflow with a rationale that names the private "
        "registry; revisit when the registry adds trusted-publisher "
        "support.",
        "Workflows whose only install command is ``npm install "
        "--no-save`` for a one-off tool (linter, doc generator) "
        "without a lockfile in the repo. Suppress if signature "
        "verification adds no signal because nothing is pinned in the "
        "first place; the right fix is usually to add the lockfile, "
        "not suppress the rule.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026) / TanStack / axios patch-release "
        "compromises: each abused the gap between lockfile-pinned "
        "integrity and registry-signed-publisher provenance. The "
        "lockfile faithfully pinned what the maintainer's account "
        "published; ``npm audit signatures`` would have flagged that "
        "the bytes weren't signed by the trusted-publisher record on "
        "file with the registry.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    install_steps: list[tuple[str, dict[str, Any], int]] = []
    audit_seen = False
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if has_npm_audit_signatures(run):
                audit_seen = True
            if has_npm_install(run):
                install_steps.append((job_id, step, idx))
    if not install_steps or audit_seen:
        desc = (
            "Workflow runs no npm/pnpm install steps; signature "
            "verification not applicable."
            if not install_steps else
            "Workflow runs `npm audit signatures` after install; "
            "registry trusted-publisher records are verified before "
            "any installed code executes."
        )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description=desc,
            recommendation=RULE.recommendation, passed=True,
        )
    locations = [
        step_location(path, step) for _job, step, _idx in install_steps
    ]
    offenders: list[str] = []
    for job_id, step, idx in install_steps[:5]:
        name = step.get("name") or step.get("id") or f"steps[{idx}]"
        offenders.append(f"{job_id}.{name}")
    desc = (
        f"{len(install_steps)} npm/pnpm install step(s) run with no "
        f"`npm audit signatures` step in the workflow: "
        f"{', '.join(offenders)}"
        f"{'…' if len(install_steps) > 5 else ''}. Lockfile pinning "
        f"without signature verification is integrity theater: it "
        f"confirms the bytes match the lockfile, not that the bytes "
        f"were signed by the registry's trusted publisher for the "
        f"package."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
