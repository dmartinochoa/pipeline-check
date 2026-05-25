"""Pure tool functions exposed by the MCP server.

Each function below maps 1:1 to a tool the MCP client sees. They
return JSON-serializable dicts (or lists of them); the server
harness in ``server.py`` is responsible for the async/MCP framing.
Keeping the tool bodies pure means we can unit-test every code
path without spinning up an MCP loop.

Why separate from ``server.py``? Two reasons:

1. The ``mcp`` SDK is an *optional* extra. ``server.py`` imports
   it; ``tools.py`` doesn't. Anything that wants to call a tool
   programmatically (the test suite, downstream Python users,
   future HTTP transport) can do so without paying the SDK
   cost.

2. The schema each tool advertises (``input_schema()``) lives
   alongside the implementation, so adding a new tool means
   editing one module.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.checks.base import (
    Confidence,
    Finding,
    Severity,
)
from ..core.checks.base import (
    severity_rank as _severity_rank,
)
from ..core.markdown_reporter import report_markdown
from ..core.scanner import Scanner
from ..core.scorer import score
from ..core.threatmodel_reporter import report_threatmodel, stride_for_finding

# Env var that widens the path-resolution boundary the MCP tools
# enforce. By default tools refuse to scan paths outside the server's
# working directory; setting this to a different root (or a
# platform-conventional pathsep-separated list of roots) lets sites
# that deploy the server alongside multiple repos opt in to those
# exact roots, without losing the protection against an MCP client
# pointing the scanner at ``/etc/passwd``.
_SCAN_ROOTS_ENV = "PIPELINE_CHECK_MCP_SCAN_ROOTS"


def _allowed_scan_roots() -> list[Path]:
    """Return the resolved scan-root boundaries for MCP tool calls.

    Falls back to ``[cwd]`` when the env var isn't set. Path separators
    are platform-conventional (``:`` on POSIX, ``;`` on Windows, via
    :data:`os.pathsep`).
    """
    override = os.environ.get(_SCAN_ROOTS_ENV)
    if not override:
        return [Path.cwd().resolve()]
    roots = [Path(r).expanduser().resolve() for r in override.split(os.pathsep) if r]
    return roots or [Path.cwd().resolve()]


# ── Provider catalog ────────────────────────────────────────────────


# Each provider's path-flag name. ``None`` means the provider takes
# no on-disk path (live AWS scans the account directly via boto3;
# scm fetches the repo over the wire via ``scm_platform`` + ``scm_repo``).
# Keep aligned with ``cli.py``'s flag set; if a new provider lands,
# add it here too. ``tests/test_mcp_server.py`` asserts parity with the
# rule registry so drift fails CI on the next provider add.
_PROVIDER_PATH_KW: dict[str, str | None] = {
    "github":         "gha_path",
    "gitlab":         "gitlab_path",
    "bitbucket":      "bitbucket_path",
    "azure":          "azure_path",
    "jenkins":        "jenkinsfile_path",
    "circleci":       "circleci_path",
    "cloudformation": "cfn_template",
    "terraform":      "tf_plan",
    "cloudbuild":     "cloudbuild_path",
    "buildkite":      "buildkite_path",
    "drone":          "drone_path",
    "tekton":         "tekton_path",
    "argo":           "argo_path",
    "argocd":         "argocd_path",
    "dockerfile":     "dockerfile_path",
    "kubernetes":     "k8s_path",
    "helm":           "helm_path",
    "oci":            "oci_manifest",
    "npm":            "npm_path",
    "pypi":           "pypi_path",
    "maven":          "maven_path",
    "nuget":          "nuget_path",
    "aws":            None,
    "scm":            None,
}

PROVIDERS: tuple[str, ...] = tuple(sorted(_PROVIDER_PATH_KW))


def _provider_kwarg(
    provider: str,
    path: str | None,
    *,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> dict[str, Any]:
    """Return the kwargs dict to forward to ``Scanner(...)``.

    Validates the provider name and the path requirement for that
    provider. Raises ``ValueError`` with a message safe to surface
    to the MCP client (no stack traces).

    The ``scm_*`` kwargs are only consumed when *provider* is ``scm``
    (live remote-repo scan); other providers ignore them.
    """
    if provider not in _PROVIDER_PATH_KW:
        raise ValueError(
            f"unknown provider {provider!r}. Valid: "
            + ", ".join(PROVIDERS)
        )
    flag = _PROVIDER_PATH_KW[provider]
    if flag is None:
        # ``scm`` is path-less but needs platform + repo (and optionally
        # a fixture dir for offline tests). ``aws`` and any other
        # path-less provider get the empty-kwargs path.
        if provider == "scm":
            if not scm_platform:
                raise ValueError(
                    "provider 'scm' requires scm_platform "
                    "(one of: github, gitlab, bitbucket)."
                )
            if not scm_repo or "/" not in scm_repo:
                raise ValueError(
                    "provider 'scm' requires scm_repo in 'owner/name' form."
                )
            out: dict[str, Any] = {
                "scm_platform": scm_platform,
                "scm_repo":     scm_repo,
            }
            if scm_fixture_dir:
                resolved_fx = Path(scm_fixture_dir).expanduser().resolve()
                roots = _allowed_scan_roots()
                if not any(_is_within(resolved_fx, root) for root in roots):
                    raise ValueError(
                        f"scm_fixture_dir {resolved_fx} is outside the MCP "
                        f"server's allowed scan roots ("
                        + ", ".join(str(r) for r in roots)
                        + f"). Set {_SCAN_ROOTS_ENV} to widen."
                    )
                if not resolved_fx.exists():
                    raise ValueError(
                        f"scm_fixture_dir does not exist: {resolved_fx}"
                    )
                out["scm_fixture_dir"] = str(resolved_fx)
            return out
        # AWS: no path, but accept ``path`` silently when supplied
        # so an agent guessing the call shape doesn't trip over it.
        return {}
    if not path:
        raise ValueError(
            f"provider {provider!r} requires a path argument "
            f"(maps to --{flag.replace('_', '-')})."
        )
    # Resolve symlinks and ``..`` segments, then bound the target to
    # the configured scan root (cwd by default). Prevents an untrusted
    # MCP client from pointing the scanner at ``/etc/passwd`` or a
    # sibling repo it shouldn't read. Deployments that mount multiple
    # repos can opt in to those exact roots via the
    # ``PIPELINE_CHECK_MCP_SCAN_ROOTS`` env var.
    resolved = Path(path).expanduser().resolve()
    roots = _allowed_scan_roots()
    if not any(_is_within(resolved, root) for root in roots):
        raise ValueError(
            f"path {resolved} is outside the MCP server's allowed scan "
            f"roots ({', '.join(str(r) for r in roots)}). Either run "
            f"the server from a parent directory that covers the path, "
            f"or set {_SCAN_ROOTS_ENV} to a colon/semicolon-separated "
            f"list of allowed roots."
        )
    if not resolved.exists():
        raise ValueError(
            f"path does not exist: {resolved}"
        )
    return {flag: str(resolved)}


def _is_within(candidate: Path, root: Path) -> bool:
    """True iff *candidate* equals *root* or sits inside it.

    ``Path.relative_to`` raises on a non-subpath, so it'd be awkward
    in a boolean predicate; this wrapper folds that into a clean
    ``bool``.
    """
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


# ── Tool: list_providers ────────────────────────────────────────────


def list_providers() -> dict[str, Any]:
    """Return every supported provider name plus its path requirement.

    The ``path_kwarg`` field is the matching CLI flag without the
    ``--`` prefix; ``null`` means the provider takes no on-disk
    path (live AWS scan).
    """
    return {
        "providers": [
            {
                "name": name,
                "path_kwarg": flag,
                "requires_path": flag is not None,
            }
            for name, flag in sorted(_PROVIDER_PATH_KW.items())
        ],
    }


# ── Tool: list_checks ───────────────────────────────────────────────


# Rules-package FQN per provider that exposes a discoverable
# ``rules/`` subpackage. Aligns with ``scripts/gen_provider_docs.py``'s
# ``SUPPORTED_PROVIDERS`` but lives here directly so the MCP tools
# don't depend on the ``scripts/`` directory, which is excluded from
# the pip distribution (``MANIFEST.in`` ``prune scripts``).
_RULES_FQN: dict[str, str] = {
    "github":         "pipeline_check.core.checks.github.rules",
    "gitlab":         "pipeline_check.core.checks.gitlab.rules",
    "bitbucket":      "pipeline_check.core.checks.bitbucket.rules",
    "azure":          "pipeline_check.core.checks.azure.rules",
    "jenkins":        "pipeline_check.core.checks.jenkins.rules",
    "circleci":       "pipeline_check.core.checks.circleci.rules",
    "cloudbuild":     "pipeline_check.core.checks.cloudbuild.rules",
    "kubernetes":     "pipeline_check.core.checks.kubernetes.rules",
    "buildkite":      "pipeline_check.core.checks.buildkite.rules",
    "tekton":         "pipeline_check.core.checks.tekton.rules",
    "argo":           "pipeline_check.core.checks.argo.rules",
    "argocd":         "pipeline_check.core.checks.argocd.rules",
    "drone":          "pipeline_check.core.checks.drone.rules",
    "oci":            "pipeline_check.core.checks.oci.rules",
    "dockerfile":     "pipeline_check.core.checks.dockerfile.rules",
    "helm":           "pipeline_check.core.checks.helm.rules",
    "cloudformation": "pipeline_check.core.checks.cloudformation.rules",
    "terraform":      "pipeline_check.core.checks.terraform.rules",
    "aws":            "pipeline_check.core.checks.aws.rules",
    "scm":            "pipeline_check.core.checks.scm.rules",
    "npm":            "pipeline_check.core.checks.npm.rules",
    "pypi":           "pipeline_check.core.checks.pypi.rules",
    "maven":          "pipeline_check.core.checks.maven.rules",
    "nuget":          "pipeline_check.core.checks.nuget.rules",
}


def _discover(fqn: str) -> list[Any]:
    """Return ``[(rule, check_fn), ...]`` for an importable rules
    package."""
    discover = importlib.import_module(
        "pipeline_check.core.checks.rule"
    ).discover_rules
    return list(discover(fqn))


def _rule_to_dict(rule: Any, provider: str) -> dict[str, Any]:
    return {
        "id":             rule.id,
        "title":          rule.title,
        "severity":       rule.severity.value,
        "provider":       provider,
        "owasp":          list(rule.owasp),
        "esf":            list(rule.esf),
        "cwe":            list(rule.cwe),
        "recommendation": rule.recommendation,
        "docs_note":      rule.docs_note,
        "known_fp":       (
            list(rule.known_fp)
            if rule.known_fp
            else []
        ),
    }


def list_checks(provider: str | None = None) -> dict[str, Any]:
    """List every registered check.

    If *provider* is given, scope the result to that provider's
    rule pack. If omitted, walk every supported provider.
    """
    if provider is not None and provider not in _RULES_FQN:
        raise ValueError(
            f"unknown provider {provider!r}. Valid: "
            + ", ".join(sorted(_RULES_FQN))
        )
    targets: list[tuple[str, str]]
    if provider is not None:
        targets = [(provider, _RULES_FQN[provider])]
    else:
        targets = sorted(_RULES_FQN.items())
    out: list[dict[str, Any]] = []
    for name, fqn in targets:
        for rule, _ in _discover(fqn):
            out.append({
                "id":       rule.id,
                "title":    rule.title,
                "severity": rule.severity.value,
                "provider": name,
            })
    return {"checks": out, "count": len(out)}


# ── Tool: explain_check ─────────────────────────────────────────────


def explain_check(check_id: str) -> dict[str, Any]:
    """Return the full reference for one check id."""
    target = check_id.upper().strip()
    for name, fqn in sorted(_RULES_FQN.items()):
        for rule, _ in _discover(fqn):
            if rule.id.upper() == target:
                return _rule_to_dict(rule, name)
    raise ValueError(
        f"unknown check id {check_id!r}. Try the list_checks "
        f"tool for the full catalog."
    )


# ── Tool: list_chains / explain_chain ───────────────────────────────


def list_chains() -> dict[str, Any]:
    """Return every registered attack chain (id, title, severity)."""
    chains_mod = importlib.import_module("pipeline_check.core.chains")
    out: list[dict[str, Any]] = []
    for c in chains_mod.list_rules():
        out.append({
            "id":       c.id,
            "title":    c.title,
            "severity": c.severity.value,
        })
    return {"chains": out, "count": len(out)}


def explain_chain(chain_id: str) -> dict[str, Any]:
    """Full reference for one attack chain id."""
    chains_mod = importlib.import_module("pipeline_check.core.chains")
    target = chain_id.upper().strip()
    for c in chains_mod.list_rules():
        if c.id.upper() == target:
            return {
                "id":                   c.id,
                "title":                c.title,
                "severity":             c.severity.value,
                "summary":              c.summary,
                "triggering_check_ids": list(c.triggering_check_ids),
                "mitre_attack":         list(c.mitre_attack),
                "kill_chain_phase":     c.kill_chain_phase,
                "providers":            list(c.providers),
                "references":           list(c.references),
                "recommendation":       c.recommendation,
            }
    raise ValueError(
        f"unknown chain id {chain_id!r}. Try the list_chains tool."
    )


# ── Tool: list_standards ────────────────────────────────────────────


def list_standards() -> dict[str, Any]:
    """Return every registered compliance standard."""
    std_mod = importlib.import_module("pipeline_check.core.standards")
    standards = []
    for s in std_mod.resolve():
        standards.append({
            "name":     s.name,
            "title":    s.title,
            "version":  getattr(s, "version", "") or "",
            "url":      getattr(s, "url", "") or "",
            "controls": len(getattr(s, "controls", {}) or {}),
        })
    return {"standards": standards, "count": len(standards)}


# ── Tool: scan ──────────────────────────────────────────────────────


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {
        "check_id":       f.check_id,
        "title":          f.title,
        "severity":       f.severity.value,
        "confidence":     f.confidence.value,
        "passed":         f.passed,
        "resource":       f.resource,
        "description":    f.description,
        "recommendation": f.recommendation,
        "controls": [
            {
                "standard":   c.standard,
                "control_id": c.control_id,
            }
            for c in f.controls
        ],
        "cwe":            list(f.cwe),
        "stride":         list(stride_for_finding(f)),
    }
    if f.locations:
        out["locations"] = [
            {
                "path":       loc.path,
                "start_line": loc.start_line,
                "end_line":   loc.end_line,
            }
            for loc in f.locations
        ]
    return out


# Confidence rank shared by every tool. Mirrors ``confidence_rank``
# from the CLI but inlined to keep ``tools.py`` decoupled from
# ``cli.py``.
_CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


def _run_scan(
    provider: str,
    path: str | None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    chains_enabled: bool = True,
    checks: list[str] | None = None,
    standards: list[str] | None = None,
    min_confidence: str = "LOW",
    severity_threshold: str | None = None,
    diff_base: str | None = None,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> tuple[Scanner, list[Finding]]:
    """Build a Scanner, run it, apply CLI-equivalent filters.

    Returns the Scanner and the (filtered) list of Finding
    dataclass instances so callers can both render findings as
    JSON and pass them through to the markdown / threat-model
    reporters without a serialize / re-hydrate round trip.
    """
    kwargs = _provider_kwarg(
        provider, path,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )
    threshold_rank = _CONFIDENCE_ORDER[Confidence(min_confidence.upper())]

    scanner = Scanner(
        pipeline=provider,
        region=region,
        profile=profile,
        chains_enabled=chains_enabled,
        diff_base=diff_base,
        **kwargs,
    )
    findings = scanner.run(
        checks=list(checks) if checks else None,
        standards=list(standards) if standards else None,
    )
    findings = [
        f for f in findings
        if _CONFIDENCE_ORDER[f.confidence] >= threshold_rank
    ]
    if severity_threshold:
        sev_rank = _severity_rank(Severity(severity_threshold.upper()))
        findings = [
            f for f in findings
            if _severity_rank(f.severity) >= sev_rank
        ]
    return scanner, findings


def scan(
    provider: str,
    path: str | None = None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    checks: list[str] | None = None,
    standards: list[str] | None = None,
    no_chains: bool = False,
    min_confidence: str = "low",
    severity_threshold: str | None = None,
    diff_base: str | None = None,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> dict[str, Any]:
    """Run a scan and return findings + score + chains.

    The shape mirrors ``--output json`` so an agent can parse the
    same structure for both this MCP tool and a stand-alone CLI
    invocation. Confidence and severity filters are applied here so
    the agent sees the same trimmed set the CLI gate would.

    ``diff_base`` mirrors the CLI ``--diff-base`` flag: only files
    touched since that git ref are scanned. Pair it with a feature
    branch to mimic a PR-time scan; use ``scan_pr_diff`` for the
    full base-vs-HEAD finding delta.

    ``scm_platform`` / ``scm_repo`` are only consumed when
    ``provider`` is ``scm``.
    """
    scanner, findings = _run_scan(
        provider, path,
        region=region, profile=profile,
        chains_enabled=not no_chains,
        checks=checks, standards=standards,
        min_confidence=min_confidence,
        severity_threshold=severity_threshold,
        diff_base=diff_base,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )
    score_result = score(findings)
    chains_out: list[dict[str, Any]] = []
    for c in getattr(scanner, "chains", []) or []:
        chains_out.append({
            "id":       c.chain_id,
            "title":    c.title,
            "severity": c.severity.value,
            "summary":  c.summary,
            "triggering_check_ids": list(c.triggering_check_ids),
        })
    return {
        "provider": provider,
        "path":     path or "",
        "score":    dict(score_result),
        "findings": [_finding_to_dict(f) for f in findings],
        "chains":   chains_out,
        "summary": {
            "total":   len(findings),
            "failed":  sum(1 for f in findings if not f.passed),
            "passed":  sum(1 for f in findings if f.passed),
            "by_severity": _severity_summary(findings),
        },
    }


def _severity_summary(findings: list[Finding]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {
        s.value: {"failed": 0, "passed": 0} for s in Severity
    }
    for f in findings:
        bucket = "passed" if f.passed else "failed"
        out[f.severity.value][bucket] += 1
    return out


# ── Tool: inventory ─────────────────────────────────────────────────


def inventory(
    provider: str,
    path: str | None = None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    type_pattern: str | None = None,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> dict[str, Any]:
    """Return the component inventory for *provider*."""
    kwargs = _provider_kwarg(
        provider, path,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )
    scanner = Scanner(
        pipeline=provider,
        region=region,
        profile=profile,
        chains_enabled=False,
        **kwargs,
    )
    components = scanner.inventory(
        type_patterns=[type_pattern] if type_pattern else None,
    )
    return {
        "provider": provider,
        "components": [
            {
                "provider":   c.provider,
                "type":       c.type,
                "identifier": c.identifier,
                "source":     c.source,
                "metadata":   c.metadata,
            }
            for c in components
        ],
        "count": len(components),
    }


# ── Tool: threat_model ──────────────────────────────────────────────


def threat_model(
    provider: str,
    path: str | None = None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    standards: list[str] | None = None,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> dict[str, Any]:
    """Run a scan and return the STRIDE threat-model markdown.

    Convenience wrapper over ``scan`` + ``inventory`` +
    ``threatmodel_reporter``. Lets an agent ask one tool for the
    document instead of stitching the three together.
    """
    scanner, findings = _run_scan(
        provider, path,
        region=region, profile=profile,
        chains_enabled=True,
        standards=standards,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )
    score_result = score(findings)
    components = scanner.inventory()
    chains = list(getattr(scanner, "chains", []) or [])
    md = report_threatmodel(
        findings, score_result,
        inventory=components, chains=chains,
    )
    return {
        "provider": provider,
        "path":     path or "",
        "markdown": md,
        "summary": {
            "grade":  score_result.get("grade", "?"),
            "score":  score_result.get("score", 0),
            "failed": sum(1 for f in findings if not f.passed),
            "passed": sum(1 for f in findings if f.passed),
        },
    }


# ── Tool: scan_markdown ─────────────────────────────────────────────


def scan_markdown(
    provider: str,
    path: str | None = None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    scm_platform: str | None = None,
    scm_repo: str | None = None,
    scm_fixture_dir: str | None = None,
) -> dict[str, Any]:
    """Run a scan and return the GitHub-Flavored Markdown report.

    Useful when the agent wants a human-shaped summary to paste
    into a PR comment without re-rendering the JSON itself.
    """
    scanner, findings = _run_scan(
        provider, path, region=region, profile=profile,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )
    score_result = score(findings)
    chains = list(getattr(scanner, "chains", []) or [])
    md = report_markdown(findings, score_result, chains=chains)
    return {
        "provider": provider,
        "path":     path or "",
        "markdown": md,
        "summary": {
            "total":  len(findings),
            "failed": sum(1 for f in findings if not f.passed),
            "passed": sum(1 for f in findings if f.passed),
        },
    }


# ── Tool: scan_pr_diff ──────────────────────────────────────────────


def _build_pr_diff_argv(
    *,
    provider: str,
    path: str | None,
    checks: list[str] | None,
    standards: list[str] | None,
    severity_threshold: str | None,
    min_confidence: str,
) -> list[str]:
    """Build the minimal argv the BASE subprocess scan needs.

    Mirrors the flags ``cli.py``'s ``_build_pr_diff_subprocess_argv``
    propagates, scoped to the parameters the MCP ``scan_pr_diff`` tool
    accepts. Anything that would shift the BASE finding set has to be
    here; gate / output / fix / inventory flags are deliberately out.
    """
    argv: list[str] = ["--pipeline", provider]
    flag = _PROVIDER_PATH_KW.get(provider)
    if path and flag:
        argv.extend([f"--{flag.replace('_', '-')}", path])
    for c in checks or ():
        argv.extend(["--checks", c])
    for s in standards or ():
        argv.extend(["--standard", s])
    if severity_threshold:
        argv.extend(["--severity-threshold", severity_threshold.upper()])
    argv.extend(["--min-confidence", min_confidence.upper()])
    # Chains aren't compared by the delta layer yet; suppressing them
    # mirrors the CLI subprocess (faster, no functional difference).
    argv.append("--no-chains")
    return argv


def scan_pr_diff(
    provider: str,
    base_ref: str,
    path: str | None = None,
    *,
    region: str = "us-east-1",
    profile: str | None = None,
    checks: list[str] | None = None,
    standards: list[str] | None = None,
    min_confidence: str = "LOW",
    severity_threshold: str | None = None,
) -> dict[str, Any]:
    """Compute the PR-diff delta between *base_ref* and HEAD.

    Mirrors the CLI ``--pr-diff REF`` flow: scan HEAD in-process,
    materialize *base_ref* in a throwaway ``git worktree``, scan that
    in a subprocess, then partition findings into introduced /
    resolved / preserved. Returns both the structured delta and the
    rendered Markdown an agent can paste into a PR comment.

    Notes for callers:

    * Live providers (``aws``, ``scm``) don't have a meaningful BASE
      side and are rejected up front, the CLI rejects the same
      combination.
    * ``fail-on`` semantics aren't applied here; the agent can read
      ``summary.introduced_by_severity`` and decide itself whether
      to block the PR.
    """
    if provider in ("aws", "scm"):
        raise ValueError(
            f"provider {provider!r} has no local BASE ref to diff against; "
            f"scan_pr_diff is only meaningful for file-based providers."
        )
    # Lazy import so a bare ``import pipeline_check.mcp_server.tools``
    # doesn't pull in the pr_diff module's git/subprocess plumbing.
    from .. import __version__ as _version
    from ..core.pr_diff import (
        any_at_or_above as _any_at_or_above,
    )
    from ..core.pr_diff import (
        run_pr_diff,
    )
    from ..core.pr_diff import (
        severity_counts as _severity_counts,
    )
    from ..core.pr_diff_reporter import report_pr_diff

    _scanner, head_findings = _run_scan(
        provider, path,
        region=region, profile=profile,
        chains_enabled=False,
        checks=checks, standards=standards,
        min_confidence=min_confidence,
        severity_threshold=severity_threshold,
    )
    head_findings_raw = [f.to_dict() for f in head_findings]
    forwarded_argv = _build_pr_diff_argv(
        provider=provider,
        path=path,
        checks=checks,
        standards=standards,
        severity_threshold=severity_threshold,
        min_confidence=min_confidence,
    )
    delta = run_pr_diff(
        base_ref,
        head_findings_raw,
        forwarded_argv,
        cwd=".",
    )
    markdown = report_pr_diff(delta, tool_version=_version)
    return {
        "provider":   provider,
        "base_ref":   delta.base_ref,
        "base_commit": delta.base_commit,
        "head_commit": delta.head_commit,
        "markdown":   markdown,
        "introduced": [_finding_ref_to_dict(f) for f in delta.introduced],
        "resolved":   [_finding_ref_to_dict(f) for f in delta.resolved],
        "preserved":  [_finding_ref_to_dict(f) for f in delta.preserved],
        "warnings":   list(delta.warnings),
        "summary": {
            "introduced": len(delta.introduced),
            "resolved":   len(delta.resolved),
            "preserved":  len(delta.preserved),
            "introduced_by_severity": dict(_severity_counts(delta.introduced)),
            "gate_high_or_above": _any_at_or_above(delta.introduced, "HIGH"),
            "gate_critical":      _any_at_or_above(delta.introduced, "CRITICAL"),
        },
    }


def _finding_ref_to_dict(f: Any) -> dict[str, Any]:
    """Project a ``pr_diff.FindingRef`` onto a JSON-safe dict."""
    return {
        "check_id":       f.check_id,
        "title":          f.title,
        "severity":       f.severity,
        "confidence":     f.confidence,
        "resource":       f.resource,
        "description":    f.description,
        "recommendation": f.recommendation,
        "location_line":  f.location_line,
    }


# ── Tool registry ───────────────────────────────────────────────────


# Each entry binds an MCP tool name to its implementation function
# and a JSON-Schema input schema. The server harness consumes this
# table directly.

_PROVIDER_ENUM = list(PROVIDERS)


def _enum_severity() -> list[str]:
    return [s.value for s in Severity]


def _enum_confidence() -> list[str]:
    return [c.value for c in Confidence]


# Shared schema fragments. Inlined into each tool's ``input_schema``
# at module-import time so the JSON-Schema view a client sees is
# self-contained (no $ref indirection).
_SCM_PROPS: dict[str, Any] = {
    "scm_platform": {
        "type": "string",
        "enum": ["github", "gitlab", "bitbucket"],
        "description": (
            "Live SCM platform. Required when ``provider`` is "
            "``scm``; ignored otherwise."
        ),
    },
    "scm_repo": {
        "type": "string",
        "description": (
            "``owner/name`` slug of the live SCM repo. Required "
            "when ``provider`` is ``scm``."
        ),
    },
    "scm_fixture_dir": {
        "type": "string",
        "description": (
            "Optional local fixture directory used in place of "
            "live SCM API calls (offline / replay testing). "
            "Honored only when ``provider`` is ``scm``."
        ),
    },
}


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "list_providers",
        "description": (
            "List every provider pipeline-check supports plus "
            "its path-argument requirement. Call this first when "
            "you don't know which providers are available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "fn": lambda **_kw: list_providers(),
    },
    {
        "name": "list_checks",
        "description": (
            "List every registered security check, optionally "
            "scoped to one provider. Returns id / title / "
            "severity / provider triples."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": _PROVIDER_ENUM,
                    "description": (
                        "Optional provider filter. Omit to "
                        "list every check."
                    ),
                },
            },
            "additionalProperties": False,
        },
        "fn": lambda **kw: list_checks(provider=kw.get("provider")),
    },
    {
        "name": "explain_check",
        "description": (
            "Get the full reference for one check id (severity, "
            "OWASP / CWE / ESF mappings, recommendation, "
            "docs_note, known false-positive modes)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "check_id": {
                    "type": "string",
                    "description": (
                        "The check id, e.g. ``GHA-001`` / "
                        "``GL-002`` / ``DR-011``."
                    ),
                },
            },
            "required": ["check_id"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: explain_check(check_id=kw["check_id"]),
    },
    {
        "name": "list_chains",
        "description": (
            "List every registered attack chain (id, title, "
            "severity). Chains correlate multiple findings into "
            "real attack paths and map to MITRE ATT&CK."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "fn": lambda **_kw: list_chains(),
    },
    {
        "name": "explain_chain",
        "description": (
            "Get the full reference for one attack chain id."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "chain_id": {
                    "type": "string",
                    "description": "The chain id, e.g. ``AC-001`` / ``XPC-001``.",
                },
            },
            "required": ["chain_id"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: explain_chain(chain_id=kw["chain_id"]),
    },
    {
        "name": "list_standards",
        "description": (
            "List every registered compliance standard (OWASP "
            "CICD Top 10, NIST SSDF, SLSA, PCI DSS, SOC 2, ...) "
            "plus how many controls each one tracks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "fn": lambda **_kw: list_standards(),
    },
    {
        "name": "scan",
        "description": (
            "Run a scan against a path and return findings, "
            "score, and any matched attack chains. The shape "
            "mirrors --output json so the same parser works "
            "for both."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": _PROVIDER_ENUM,
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Path to the file or directory to scan. "
                        "Required for every provider except "
                        "``aws`` (live account scan) and ``scm`` "
                        "(live SCM-repo scan via scm_platform / "
                        "scm_repo)."
                    ),
                },
                "region": {"type": "string", "default": "us-east-1"},
                "profile": {"type": "string"},
                "checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional list of check ids to run "
                        "exclusively (e.g. ``[\"GHA-001\"]``)."
                    ),
                },
                "standards": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional standards filter.",
                },
                "no_chains": {"type": "boolean", "default": False},
                "min_confidence": {
                    "type": "string",
                    "enum": _enum_confidence(),
                    "default": "LOW",
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": _enum_severity(),
                    "description": (
                        "Optional minimum severity. Findings "
                        "below this severity are dropped from "
                        "the result."
                    ),
                },
                "diff_base": {
                    "type": "string",
                    "description": (
                        "Optional git ref. When set, only files "
                        "touched since this ref are scanned "
                        "(mirrors --diff-base). For the full "
                        "base-vs-HEAD finding delta use "
                        "``scan_pr_diff`` instead."
                    ),
                },
                **_SCM_PROPS,
            },
            "required": ["provider"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: scan(**kw),
    },
    {
        "name": "inventory",
        "description": (
            "Return the component inventory for a provider + "
            "path. The inventory is the list of resources / "
            "files / workflows the scanner discovered."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": _PROVIDER_ENUM,
                },
                "path": {"type": "string"},
                "region": {"type": "string", "default": "us-east-1"},
                "profile": {"type": "string"},
                "type_pattern": {
                    "type": "string",
                    "description": (
                        "Optional glob pattern to filter the "
                        "component type field."
                    ),
                },
                **_SCM_PROPS,
            },
            "required": ["provider"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: inventory(**kw),
    },
    {
        "name": "threat_model",
        "description": (
            "Run a scan and return the STRIDE-mapped Markdown "
            "threat-model document. Convenience wrapper over "
            "scan + inventory + the threatmodel reporter."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": _PROVIDER_ENUM,
                },
                "path": {"type": "string"},
                "region": {"type": "string", "default": "us-east-1"},
                "profile": {"type": "string"},
                "standards": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                **_SCM_PROPS,
            },
            "required": ["provider"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: threat_model(**kw),
    },
    {
        "name": "scan_markdown",
        "description": (
            "Run a scan and return the GitHub-Flavored Markdown "
            "summary. Useful for pasting into a PR comment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": _PROVIDER_ENUM,
                },
                "path": {"type": "string"},
                "region": {"type": "string", "default": "us-east-1"},
                "profile": {"type": "string"},
                **_SCM_PROPS,
            },
            "required": ["provider"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: scan_markdown(**kw),
    },
    {
        "name": "scan_pr_diff",
        "description": (
            "Compute the PR-time finding delta between a git base ref "
            "and HEAD (mirrors --pr-diff). HEAD is scanned in-process; "
            "BASE is scanned in a throwaway ``git worktree`` "
            "subprocess. Returns structured introduced / resolved / "
            "preserved lists plus the rendered Markdown PR comment. "
            "Not supported for the ``aws`` or ``scm`` live providers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": [
                        p for p in _PROVIDER_ENUM
                        if p not in ("aws", "scm")
                    ],
                },
                "base_ref": {
                    "type": "string",
                    "description": (
                        "Git ref to diff against (branch, tag, or "
                        "commit). Common values: ``origin/main``, "
                        "``HEAD~1``, the PR's merge-base."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Path to scan on the HEAD side; the BASE "
                        "scan re-uses the same path inside the "
                        "worktree."
                    ),
                },
                "region": {"type": "string", "default": "us-east-1"},
                "profile": {"type": "string"},
                "checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional list of check ids to run "
                        "exclusively on both sides."
                    ),
                },
                "standards": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional standards filter.",
                },
                "min_confidence": {
                    "type": "string",
                    "enum": _enum_confidence(),
                    "default": "LOW",
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": _enum_severity(),
                    "description": (
                        "Optional minimum severity applied to "
                        "both sides before delta computation."
                    ),
                },
            },
            "required": ["provider", "base_ref"],
            "additionalProperties": False,
        },
        "fn": lambda **kw: scan_pr_diff(**kw),
    },
]


def get_tool_fn(name: str) -> Callable[..., dict[str, Any]]:
    """Return the implementation function for a tool name.

    Raises ``KeyError`` for unknown names; the server harness
    catches and converts to an MCP-shaped error.
    """
    for spec in TOOL_SPECS:
        if spec["name"] == name:
            return spec["fn"]  # type: ignore[no-any-return]
    raise KeyError(f"unknown tool: {name}")


def mcp_available() -> bool:
    """Return True when the optional ``mcp`` SDK is importable."""
    return importlib.util.find_spec("mcp") is not None
