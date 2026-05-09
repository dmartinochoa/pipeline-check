"""STRIDE-mapped threat-model reporter.

Generates a Markdown threat-model document from the same scan
output the JSON / HTML / SARIF reporters consume: the list of
findings, optional inventory components, optional attack chains,
plus the scorer's overall grade. The document is shaped for
auditor and architecture-review consumption: assets, trust
boundaries, threats grouped by STRIDE category with their
mitigations, and a summary risk register.

Why STRIDE? The OWASP CICD Top 10 mapping every rule already
carries is the right vocabulary for a CI/CD audience but not the
one auditors / threat modelers prefer. STRIDE has been the lingua
franca of threat-modeling docs since Microsoft introduced it in
1999, and most compliance frameworks (SOC 2 CC, PCI 6.5, NIST
SSDF PW.1) speak it natively. The mapping is mechanical: each
OWASP category maps to one or more STRIDE categories with a
small set of CWE-driven refinements where OWASP alone is too
coarse (CICD-SEC-6 for example covers both leakage and identity
forgery, which split into Information Disclosure and Spoofing).

The module deliberately does NOT mutate the rule registry: rules
keep their OWASP / CWE / ESF tags as the authoritative metadata,
and STRIDE classification is derived per-finding at report time
so re-running with a different STRIDE policy is a pure-function
swap.

The ``Component`` inventory feeds the *Assets* section. When the
inventory is empty (e.g. ``--inventory`` was not enabled), the
reporter still produces a valid document, the Assets section
just notes that no inventory was captured.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from .chains import Chain
from .checks.base import Finding, severity_rank
from .inventory import Component
from .scorer import ScoreResult

# ── STRIDE categories ───────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StrideCategory:
    code: str          # one-letter STRIDE code
    name: str          # human label
    description: str   # one-line summary used in the document


STRIDE: dict[str, StrideCategory] = {
    "S": StrideCategory(
        "S", "Spoofing",
        "Authentication / identity forgery, token bypass, "
        "impersonation of users, services, or build artifacts.",
    ),
    "T": StrideCategory(
        "T", "Tampering",
        "Integrity of input, code, dependencies, or artifacts. "
        "Attacker modifies what flows through the pipeline.",
    ),
    "R": StrideCategory(
        "R", "Repudiation",
        "Inability to attribute or audit pipeline actions. "
        "Missing or insufficient logging / traceability.",
    ),
    "I": StrideCategory(
        "I", "Information Disclosure",
        "Unauthorized exposure of secrets, build logs, or "
        "internal artifacts. Leakage out of the pipeline.",
    ),
    "D": StrideCategory(
        "D", "Denial of Service",
        "Resource exhaustion, runaway builds, missing timeouts, "
        "queue starvation that blocks legitimate runs.",
    ),
    "E": StrideCategory(
        "E", "Elevation of Privilege",
        "Privileged execution, runner escape, scope expansion, "
        "operations beyond the intended permission boundary.",
    ),
}


# ── OWASP CICD Top 10 -> STRIDE primary map ─────────────────────────
#
# Each OWASP CI/CD category maps to one or more STRIDE codes. When
# more than one applies, the first is the primary; the rest serve
# as secondary tags so a finding doesn't get double-counted.

_OWASP_TO_STRIDE: dict[str, tuple[str, ...]] = {
    # Insufficient flow control: branch-protection bypass, untrusted
    # PR triggers landing on protected branches. Tampering primary
    # (the attacker modifies the build's effective shape) with
    # Elevation of Privilege secondary (bypassing the gate).
    "CICD-SEC-1":  ("T", "E"),
    # Inadequate IAM: weak SA / token / role binding. Spoofing
    # primary (impersonation surface) with EoP secondary (broader
    # scope than necessary).
    "CICD-SEC-2":  ("S", "E"),
    # Dependency chain abuse: poisoned action / image / package
    # source. Pure Tampering.
    "CICD-SEC-3":  ("T",),
    # Poisoned pipeline execution: untrusted input flowing into a
    # shell command, env var, or reusable workflow input. Tampering
    # of build behavior; the actual exploit path runs as the build
    # identity so EoP is secondary.
    "CICD-SEC-4":  ("T", "E"),
    # Insufficient PBAC: privileged steps, wildcard runner pools,
    # over-broad service tokens. Pure Elevation of Privilege.
    "CICD-SEC-5":  ("E",),
    # Insufficient credential hygiene: leaked secrets, token
    # persistence, hardcoded creds. Information Disclosure primary
    # (the secret itself leaks) with Spoofing secondary (a leaked
    # token enables impersonation of the build identity).
    "CICD-SEC-6":  ("I", "S"),
    # Insecure system configuration: missing isolation, weak
    # network policy, host bind mounts, unsafe defaults like
    # ``ALLOW_UNSECURE_COMMANDS``. EoP primary (the misconfig
    # widens the blast radius), DoS secondary for missing-timeout
    # variants.
    "CICD-SEC-7":  ("E", "D"),
    # Ungoverned 3rd-party services: floating-tag plugins, off-
    # registry dependencies. Tampering primary, EoP secondary.
    "CICD-SEC-8":  ("T", "E"),
    # Improper artifact integrity: missing signing, missing SBOM,
    # missing provenance. Pure Tampering, the integrity guarantee
    # is the missing control.
    "CICD-SEC-9":  ("T",),
    # Insufficient logging: missing audit trail, missing
    # build-event evidence. Pure Repudiation.
    "CICD-SEC-10": ("R",),
}


# ── CWE refinements ─────────────────────────────────────────────────
#
# Some CWEs are clearer signal than the OWASP category alone. When a
# finding's rule declares one of these CWEs and the OWASP map yields
# a more general answer, the CWE refinement *prepends* its STRIDE
# code so the primary classification reflects the finer-grained
# vulnerability shape. Order in the resulting tuple is preserved.

_CWE_PREPEND: dict[str, str] = {
    # Information disclosure family.
    "CWE-200":  "I",   # generic info exposure
    "CWE-522":  "I",   # insufficiently protected creds
    "CWE-552":  "I",   # files / dirs accessible to external parties
    "CWE-798":  "I",   # hardcoded credentials
    # Authentication / identity.
    "CWE-287":  "S",   # improper authentication
    "CWE-290":  "S",   # auth bypass by spoofing
    "CWE-345":  "T",   # integrity check missing
    # Tampering / integrity.
    "CWE-78":   "T",   # OS command injection (PPE class)
    "CWE-77":   "T",   # generic command injection
    "CWE-494":  "T",   # download of code without integrity check
    "CWE-829":  "T",   # functionality from untrusted control sphere
    "CWE-1357": "T",   # reliance on uncontrolled component
    # DoS.
    "CWE-400":  "D",   # uncontrolled resource consumption
    "CWE-770":  "D",   # alloc without limits
    # EoP.
    "CWE-269":  "E",   # improper privilege management
    "CWE-250":  "E",   # execution with unnecessary privileges
    # Repudiation.
    "CWE-778":  "R",   # insufficient logging
}


def stride_for_finding(f: Finding) -> tuple[str, ...]:
    """Return STRIDE codes for *f*, primary first, in priority order.

    Lookup logic:

    1. Start from the finding's first OWASP CICD Top 10 control,
       map via ``_OWASP_TO_STRIDE``. Multiple controls per finding
       get unioned in order.
    2. Apply CWE prepends, each matching CWE that yields a STRIDE
       code not already present prepends to the head.
    3. If no OWASP and no CWE produced anything, classify as
       Tampering (``T``) by default, the most common CI/CD failure
       mode.

    Returns a tuple of one or more STRIDE single-letter codes; the
    head is the primary classification.
    """
    seen: list[str] = []

    def _add(code: str, *, prepend: bool = False) -> None:
        if code not in seen:
            if prepend:
                seen.insert(0, code)
            else:
                seen.append(code)

    # 1. OWASP-derived classification.
    for ref in f.controls:
        if ref.standard != "owasp_cicd_top_10":
            continue
        for code in _OWASP_TO_STRIDE.get(ref.control_id, ()):
            _add(code)

    # 2. CWE refinements. Walk in declaration order so the first
    #    CWE wins the head slot when multiple apply.
    for cwe in f.cwe:
        # CWE numbers in the registry come as ``CWE-NNN``.
        normalized = cwe.upper().strip()
        prepend_code = _CWE_PREPEND.get(normalized)
        if prepend_code is not None:
            _add(prepend_code, prepend=True)

    if not seen:
        # 3. Default for findings with no OWASP / CWE tags
        #    (degraded-mode findings, custom-rule entries that
        #    skipped tagging).
        seen.append("T")

    return tuple(seen)


# ── Reporter ────────────────────────────────────────────────────────


_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _esc(s: str) -> str:
    """Escape characters that would corrupt a Markdown table row."""
    if not s:
        return ""
    return (
        s.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", "")
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _provider_summary(components: list[Component]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for c in components:
        out[c.provider] += 1
    return dict(sorted(out.items()))


def _trust_boundaries(components: list[Component]) -> list[str]:
    """Heuristic trust-boundary list keyed off provider mix.

    The threat-modeling discipline expects boundaries to be drawn
    between zones with different trust levels: between the developer
    workstation and CI, between CI and the registry, between CI and
    the production target. We approximate by listing a boundary for
    each (provider, downstream) pair the inventory implies.
    """
    providers = {c.provider for c in components}
    out: list[str] = []
    if "github" in providers or "gitlab" in providers or "bitbucket" in providers:
        out.append(
            "Pull-request author -> CI runner. Untrusted source-tree "
            "contents (PR-controlled YAML, scripts, dependency "
            "manifests) cross into a runner that holds CI secrets "
            "and (in privileged trigger modes) write-scope tokens."
        )
    if "github" in providers or "gitlab" in providers:
        out.append(
            "CI runner -> registry. Built artifacts (container "
            "images, packages, OCI manifests) cross from the runner "
            "into a registry whose downstream consumers trust the "
            "produced bytes."
        )
    if "kubernetes" in providers or "helm" in providers or "argo" in providers:
        out.append(
            "Build environment -> production cluster. Manifests / "
            "rendered templates cross from the build into a cluster "
            "namespace where runtime trust is governed by RBAC + "
            "PSA."
        )
    if "aws" in providers or "terraform" in providers or "cloudformation" in providers:
        out.append(
            "CI identity -> cloud account. The build's IAM role / "
            "OIDC federation crosses into the AWS account, where its "
            "session-scoped permissions become the effective blast "
            "radius."
        )
    if "oci" in providers:
        out.append(
            "Registry -> deploying environment. The OCI image "
            "manifest carries provenance / signing metadata that the "
            "deployer either verifies or implicitly trusts."
        )
    if not out:
        out.append(
            "No inventory captured (re-run with ``--inventory`` for "
            "a populated trust-boundary section)."
        )
    return out


def _assets_section(components: list[Component]) -> list[str]:
    """Render the Assets section from the inventory."""
    if not components:
        return [
            "_No inventory captured for this scan. Re-run with "
            "``--inventory`` to populate this section with the "
            "concrete pipelines, workflows, and components the "
            "scanner saw._",
            "",
        ]
    grouped: dict[tuple[str, str], list[Component]] = defaultdict(list)
    for c in components:
        grouped[(c.provider, c.type)].append(c)
    lines: list[str] = []
    for (provider, ctype), items in sorted(grouped.items()):
        lines.append(f"### {provider} / {ctype} ({len(items)})")
        lines.append("")
        lines.append("| Identifier | Source |")
        lines.append("|---|---|")
        for c in sorted(items, key=lambda x: x.identifier):
            lines.append(f"| {_esc(c.identifier)} | {_esc(c.source)} |")
        lines.append("")
    return lines


def _stride_grouping(
    findings: list[Finding],
) -> dict[str, list[Finding]]:
    """Bucket failing findings by primary STRIDE code."""
    out: dict[str, list[Finding]] = {code: [] for code in STRIDE}
    for f in findings:
        if f.passed:
            continue
        primary = stride_for_finding(f)[0]
        out[primary].append(f)
    return out


def _category_lines(
    cat: StrideCategory, findings: list[Finding],
) -> list[str]:
    """Render one ``### STRIDE: <Category>`` block."""
    lines: list[str] = [
        f"### {cat.code} -- {cat.name}",
        "",
        f"_{cat.description}_",
        "",
    ]
    if not findings:
        lines.append(
            "No threats in this category, every applicable check "
            "passed."
        )
        lines.append("")
        return lines
    # Group by check_id so 30 GHA-001 findings render as one threat
    # row with a count, not 30 rows.
    by_check: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_check[f.check_id].append(f)
    # Sort: severity desc, then by check_id alpha.
    def _sort_key(cid: str) -> tuple[int, str]:
        return (-severity_rank(by_check[cid][0].severity), cid)

    ordered = sorted(by_check, key=_sort_key)
    lines.append(
        "| Threat | Severity | Affected | Mitigation |"
    )
    lines.append("|---|---|---|---|")
    for cid in ordered:
        group = by_check[cid]
        sample = group[0]
        affected = len({f.resource for f in group}) or 1
        mitigation = _esc(sample.recommendation)[:200]
        if len(sample.recommendation) > 200:
            mitigation += "..."
        lines.append(
            f"| `{cid}` {_esc(sample.title)} | "
            f"{sample.severity.value} | "
            f"{affected} | {mitigation} |"
        )
    lines.append("")
    return lines


def _summary_section(score_result: ScoreResult) -> list[str]:
    summary = score_result.get("summary", {})
    failed_total = sum(b.get("failed", 0) for b in summary.values())
    passed_total = sum(b.get("passed", 0) for b in summary.values())
    lines: list[str] = [
        f"**Grade:** {score_result.get('grade', '?')} ",
        f"**Score:** {score_result.get('score', 0)}/100  ",
        f"**Failed checks:** {failed_total}  ",
        f"**Passing controls:** {passed_total}  ",
        "",
    ]
    by_sev: list[str] = []
    for sev in _SEVERITY_ORDER:
        bucket = summary.get(sev) or {}
        if not (bucket.get("passed") or bucket.get("failed")):
            continue
        by_sev.append(
            f"- **{sev}:** {bucket.get('failed', 0)} failed, "
            f"{bucket.get('passed', 0)} passing"
        )
    if by_sev:
        lines.append("Severity breakdown:")
        lines.append("")
        lines.extend(by_sev)
        lines.append("")
    return lines


def _risk_register(findings: list[Finding]) -> list[str]:
    """Top-N failing findings as a flat risk register."""
    fails = [f for f in findings if not f.passed]
    fails.sort(
        key=lambda f: (-severity_rank(f.severity), f.check_id, f.resource),
    )
    if not fails:
        return [
            "_No open risks, every applicable check passed._",
            "",
        ]
    top = fails[:25]
    lines = [
        "Top open risks (capped at 25):",
        "",
        "| # | Severity | STRIDE | Check | Resource |",
        "|---|---|---|---|---|",
    ]
    for n, f in enumerate(top, start=1):
        codes = "/".join(stride_for_finding(f)[:2])
        lines.append(
            f"| {n} | {f.severity.value} | {codes} | "
            f"`{f.check_id}` {_esc(f.title)[:60]} | "
            f"{_esc(f.resource)[:60]} |"
        )
    if len(fails) > 25:
        lines.append("")
        lines.append(
            f"_+{len(fails) - 25} more failing finding(s) not "
            f"shown. Re-run with ``--output json`` for the full "
            f"set._"
        )
    lines.append("")
    return lines


def _chain_section(chains: list[Chain]) -> list[str]:
    if not chains:
        return []
    lines = [
        f"## Attack chains ({len(chains)})",
        "",
        "_Multiple findings combine into a real attack path. "
        "Breaking any one finding in a chain breaks the chain._",
        "",
    ]
    for c in chains:
        lines.append(
            f"### `{c.chain_id}` {c.title} "
            f"_(severity {c.severity.value}, "
            f"confidence {c.confidence.value})_"
        )
        lines.append("")
        lines.append(c.summary)
        lines.append("")
        lines.append(
            "**Triggering checks:** "
            + " ".join(f"`{cid}`" for cid in c.triggering_check_ids)
        )
        if c.mitre_attack:
            lines.append(
                "**MITRE ATT&CK:** "
                + " ".join(f"`{m}`" for m in c.mitre_attack)
            )
        lines.append("")
    return lines


def report_threatmodel(
    findings: list[Finding],
    score_result: ScoreResult,
    *,
    inventory: list[Component] | None = None,
    chains: list[Chain] | None = None,
    tool_version: str = "",
    region: str = "",
    target: str = "",
) -> str:
    """Render *findings* + *inventory* as a STRIDE-mapped threat
    model in Markdown.

    The output is a self-contained document (H1 title at top,
    valid GFM throughout) suitable for posting to a wiki, attaching
    to a SOC 2 / PCI evidence package, or pasting into an
    architecture-review doc.
    """
    inventory = inventory or []
    chains = chains or []

    lines: list[str] = []
    lines.append("# Threat Model")
    lines.append("")
    bits = ["Generated by pipeline-check"]
    if tool_version:
        bits.append(f"v{tool_version}")
    bits.append(f"on {_now_iso()}")
    lines.append("_" + " ".join(bits) + "._")
    lines.append("")

    # ── Scope ────────────────────────────────────────────────────
    lines.append("## Scope")
    lines.append("")
    provider_counts = _provider_summary(inventory)
    if provider_counts:
        provider_str = ", ".join(
            f"{name} ({count})" for name, count in provider_counts.items()
        )
        lines.append(f"**Providers in scope:** {provider_str}")
    else:
        lines.append(
            "**Providers in scope:** _no inventory captured_"
        )
    if target:
        lines.append(f"**Target filter:** `{target}`")
    if region:
        lines.append(f"**Region:** `{region}`")
    lines.append("")
    lines.extend(_summary_section(score_result))

    # ── Trust boundaries ─────────────────────────────────────────
    lines.append("## Trust boundaries")
    lines.append("")
    lines.append(
        "Boundaries inferred from the inventory below. Each "
        "boundary represents a trust step where an attacker on "
        "the lower-trust side could compromise the higher-trust "
        "side if the listed mitigations fail."
    )
    lines.append("")
    for tb in _trust_boundaries(inventory):
        lines.append(f"- {tb}")
    lines.append("")

    # ── Assets ───────────────────────────────────────────────────
    lines.append("## Assets")
    lines.append("")
    lines.extend(_assets_section(inventory))

    # ── STRIDE analysis ──────────────────────────────────────────
    lines.append("## STRIDE analysis")
    lines.append("")
    lines.append(
        "Failing findings grouped by STRIDE category. The mapping "
        "is derived from each rule's OWASP CICD Top 10 tags with "
        "CWE refinements, see "
        "``pipeline_check/core/threatmodel_reporter.py`` for the "
        "policy table. Passing checks are surfaced as implemented "
        "controls in the next section."
    )
    lines.append("")
    grouped = _stride_grouping(findings)
    for code, cat in STRIDE.items():
        lines.extend(_category_lines(cat, grouped[code]))

    # ── Attack chains (optional) ─────────────────────────────────
    lines.extend(_chain_section(chains))

    # ── Implemented controls ─────────────────────────────────────
    lines.append("## Implemented controls")
    lines.append("")
    passed = sum(1 for f in findings if f.passed)
    if passed:
        lines.append(
            f"{passed} check(s) passed on this scan, evidencing "
            f"that the corresponding controls are in place. The "
            f"full passing-check list lives in the JSON / HTML "
            f"report; this section summarizes by STRIDE category."
        )
        lines.append("")
        passed_by_code: dict[str, int] = defaultdict(int)
        for f in findings:
            if not f.passed:
                continue
            primary = stride_for_finding(f)[0]
            passed_by_code[primary] += 1
        lines.append("| STRIDE | Controls evidenced |")
        lines.append("|---|---|")
        for code, cat in STRIDE.items():
            lines.append(
                f"| {cat.name} ({code}) | {passed_by_code.get(code, 0)} |"
            )
        lines.append("")
    else:
        lines.append("_No passing controls in this scan._")
        lines.append("")

    # ── Risk register ────────────────────────────────────────────
    lines.append("## Risk register")
    lines.append("")
    lines.extend(_risk_register(findings))

    # ── Methodology footer ───────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "This document is generated mechanically from the scanner "
        "output. STRIDE categories are derived from each rule's "
        "OWASP CICD Top 10 mapping with CWE refinements (see the "
        "``_OWASP_TO_STRIDE`` and ``_CWE_PREPEND`` tables in "
        "``threatmodel_reporter.py``). Trust boundaries are "
        "inferred from the inventory. The risk register caps at "
        "the top 25 failing findings; ``--output json`` carries "
        "the unbounded set for downstream tooling."
    )
    lines.append("")

    return "\n".join(lines)
