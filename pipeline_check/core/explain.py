"""Per-check reference renderer, the body of ``pipeline_check explain``.

``--help`` lists every flag; ``--man TOPIC`` is the narrative per
subsystem; ``explain CHECK-ID`` is the narrative per check. The three
are orthogonal: when a finding fires in CI and the engineer wants to
know *why this specific rule* and *how to fix it*, they reach for
``explain`` rather than source-diving ``docs/providers/<provider>.md``
or the rule module.

The renderer accepts a rule-based ``Rule`` directly when the provider
has one, and falls back to a docstring-parsed stub for class-based
modules (AWS core services, Terraform core) where only ``id`` /
``title`` / ``severity`` are recoverable without running the check.

Output is plain text, no ANSI, no rich markup, so it reads the same
through ``less``, piped to a file, or copy-pasted into a PR comment.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .autofix import available_fixers
from .checks._confidence import confidence_for
from .checks.base import Severity
from .checks.rule import Rule, discover_rules
from .standards import resolve_for_check

if TYPE_CHECKING:
    from .chains.base import ChainRule


@dataclass(frozen=True, slots=True)
class _CheckMeta:
    """Everything ``explain`` needs to render a check, either derived
    from a ``Rule`` or from a class-based module's docstring."""

    id: str
    title: str
    severity: Severity
    source: str  # "rule" or "class"
    rule: Rule | None = None
    docstring: str = ""


# Rule-based packages: ``Rule`` metadata fully populated. Every
# provider whose checks live under ``<provider>/rules/`` belongs
# here, the regression test in ``tests/test_cli_explain.py``
# asserts that every discovered rule across these packs renders
# successfully, so a missing entry is caught at CI time.
_RULE_PACKAGES: tuple[str, ...] = (
    "pipeline_check.core.checks.github.rules",
    "pipeline_check.core.checks.gitlab.rules",
    "pipeline_check.core.checks.bitbucket.rules",
    "pipeline_check.core.checks.azure.rules",
    "pipeline_check.core.checks.jenkins.rules",
    "pipeline_check.core.checks.circleci.rules",
    "pipeline_check.core.checks.aws.rules",
    "pipeline_check.core.checks.cloudbuild.rules",
    "pipeline_check.core.checks.buildkite.rules",
    "pipeline_check.core.checks.tekton.rules",
    "pipeline_check.core.checks.argo.rules",
    "pipeline_check.core.checks.dockerfile.rules",
    "pipeline_check.core.checks.kubernetes.rules",
    "pipeline_check.core.checks.helm.rules",
    "pipeline_check.core.checks.oci.rules",
    "pipeline_check.core.checks.drone.rules",
)

# Class-based packages: ID/TITLE/SEV recoverable via docstring table.
_CLASS_PACKAGES: tuple[str, ...] = (
    "pipeline_check.core.checks.aws",
    "pipeline_check.core.checks.terraform",
    "pipeline_check.core.checks.cloudformation",
)

# Matches a row in the class-based module docstring table:
#     CB-001  Secrets in plaintext environment variables      CRITICAL  ...
_ROW_RE = re.compile(
    r"^\s*(?P<id>[A-Z]+-\d+)\s{2,}(?P<title>.+?)\s{2,}"
    r"(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
    re.MULTILINE,
)


_CACHE: dict[str, _CheckMeta] | None = None

#: Lazy chain-by-check-id index. ``None`` until the first call to
#: :func:`_chains_for_check_id`. Cached because the chains registry
#: is small (~20 entries) and immutable for the process lifetime,
#: and the explain renderer is potentially called once per check ID.
_CHAINS_BY_CHECK_ID: dict[str, list[ChainRule]] | None = None


def _chains_for_check_id(check_id: str) -> list[ChainRule]:
    """Return chain rules whose ``triggering_check_ids`` contains *check_id*.

    Result is sorted by chain id for deterministic explain output.
    Lazily builds and caches the inverted index on first call.
    """
    global _CHAINS_BY_CHECK_ID
    if _CHAINS_BY_CHECK_ID is None:
        # Local import, chains pulls in checks.base, which the
        # explain module already depends on, but the inverse import
        # path is cleaner to keep lazy in case the chains pkg ever
        # depends on explain.
        from .chains import list_rules

        index: dict[str, list[ChainRule]] = {}
        for chain_rule in list_rules():
            for cid in chain_rule.triggering_check_ids:
                index.setdefault(cid, []).append(chain_rule)
        # Sort each list by chain id so the explain output is
        # stable across Python's import-order quirks.
        for cid in index:
            index[cid].sort(key=lambda cr: cr.id)
        _CHAINS_BY_CHECK_ID = index
    return _CHAINS_BY_CHECK_ID.get(check_id, [])


#: Topic clusters for the ``[Related rules]`` cross-reference. Each
#: entry groups checks that an operator landing on one ID is likely
#: to also want to know about, same threat / different layer or same
#: control / different provider.
#:
#: A check may belong to multiple clusters; the rendered cross-ref is
#: the union of all matching clusters minus the check itself, deduped
#: and sorted. Adding a new cluster: append a new key with a tuple of
#: check IDs. ``test_topic_clusters_reference_real_check_ids`` walks
#: every entry and asserts every ID resolves through the explain index,
#: so a typo trips at CI time.
_TOPIC_CLUSTERS: dict[str, tuple[str, ...]] = {
    # Container runtime hardening.
    "k8s_security_context": (
        "K8S-005", "K8S-006", "K8S-007", "K8S-035",
    ),
    "k8s_host_namespaces": (
        "K8S-002", "K8S-003", "K8S-004", "K8S-013", "K8S-014",
    ),
    "k8s_rbac": (
        "K8S-019", "K8S-020", "K8S-021", "K8S-029",
    ),
    "k8s_namespace_posture": (
        "K8S-023", "K8S-031", "K8S-032", "K8S-033",
    ),
    "k8s_service_account": (
        "K8S-011", "K8S-012", "K8S-034", "ARGO-013",
    ),
    "k8s_runtime_priv_escalation": (
        "ARGO-002", "TKN-002", "TKN-013",
    ),
    # Cross-provider CI/CD families.
    "ci_literal_secrets": (
        "GHA-008", "GL-008", "BB-008", "ADO-003", "ADO-008",
        "JF-008", "CC-008", "BK-002", "TKN-005", "ARGO-006",
    ),
    "ci_script_injection": (
        "GHA-003", "GL-002", "BB-002", "ADO-002",
        "JF-002", "CC-002",
    ),
    "ci_image_pinning": (
        "GHA-001", "GL-001", "BB-001", "ADO-001", "ADO-005",
        "JF-001", "CC-001", "BK-001", "TKN-001", "ARGO-001",
    ),
    "ci_signing": (
        "GHA-006", "GL-006", "BB-006", "ADO-006",
        "JF-006", "CC-006", "BK-009", "TKN-009", "ARGO-009",
    ),
    "ci_sbom": (
        "GHA-007", "GL-007", "BB-007", "ADO-007",
        "JF-007", "CC-007", "BK-010", "TKN-010", "ARGO-010",
    ),
    "ci_slsa_provenance": (
        "GHA-024", "GL-024", "BB-024", "ADO-024",
        "JF-028", "CC-024", "BK-011", "TKN-011", "ARGO-011",
    ),
    "ci_vuln_scanning": (
        "GHA-020", "GL-019", "BB-015", "ADO-020",
        "JF-020", "CC-020", "BK-012", "TKN-012", "ARGO-012",
    ),
    "ci_tls_bypass": (
        "GHA-023", "GL-023", "BB-023", "ADO-023",
        "JF-023", "CC-023", "BK-008",
    ),
    "ci_curl_pipe": (
        "GHA-016", "GL-016", "BB-012", "ADO-016",
        "JF-016", "CC-016", "BK-004", "TKN-008", "ARGO-008",
    ),
    "ci_deploy_gate": (
        "GHA-014", "GL-004", "BB-004", "ADO-004",
        "JF-005", "CC-009", "BK-007", "BK-013",
    ),
    "ci_self_hosted_ephemeral": (
        "GHA-012", "GL-014", "BB-016", "ADO-013",
        "JF-014", "CC-010",
    ),
    "ci_token_persistence": (
        "GHA-019", "GL-020", "BB-017",
    ),
}

#: Lazy inverted index: check_id -> tuple of related check_ids (sorted,
#: deduped, with the check_id itself removed). Built on first call.
_RELATED_BY_CHECK_ID: dict[str, tuple[str, ...]] | None = None


def _related_check_ids(check_id: str) -> tuple[str, ...]:
    """Return the union of all ``_TOPIC_CLUSTERS`` containing *check_id*.

    Empty when the ID isn't in any cluster. The result excludes
    ``check_id`` itself and is sorted for stable output.
    """
    global _RELATED_BY_CHECK_ID
    if _RELATED_BY_CHECK_ID is None:
        index: dict[str, set[str]] = {}
        for members in _TOPIC_CLUSTERS.values():
            members_set = set(members)
            for member in members:
                index.setdefault(member, set()).update(members_set)
        # Drop self-references and freeze to a sorted tuple per ID.
        _RELATED_BY_CHECK_ID = {
            cid: tuple(sorted(others - {cid}))
            for cid, others in index.items()
        }
    return _RELATED_BY_CHECK_ID.get(check_id, ())


def _build_index() -> dict[str, _CheckMeta]:
    """Discover every known check ID and return ID → _CheckMeta.

    Cached after the first call. Rule-based providers win when an ID
    appears in both (e.g. a class-based module that has since been
    migrated to a rule, the newer Rule wins).
    """
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    index: dict[str, _CheckMeta] = {}

    # Class-based first, rule-based registrations below overwrite.
    for class_pkg_name in _CLASS_PACKAGES:
        try:
            pkg = importlib.import_module(class_pkg_name)
        except Exception:  # pragma: no cover - defensive
            continue
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_") or info.name == "rules":
                continue
            try:
                mod = importlib.import_module(f"{class_pkg_name}.{info.name}")
            except Exception:
                continue
            doc = mod.__doc__ or ""
            for m in _ROW_RE.finditer(doc):
                cid = m["id"]
                try:
                    sev = Severity(m["sev"])
                except ValueError:
                    continue
                index[cid] = _CheckMeta(
                    id=cid,
                    title=m["title"].strip(),
                    severity=sev,
                    source="class",
                    docstring=doc,
                )

    # Rule-based, definitive for any ID they cover.
    for pkg_fqn in _RULE_PACKAGES:
        try:
            for rule, _check in discover_rules(pkg_fqn):
                index[rule.id] = _CheckMeta(
                    id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    source="rule",
                    rule=rule,
                )
        except Exception:  # pragma: no cover - defensive
            continue

    _CACHE = index
    return index


def available_ids() -> list[str]:
    """Every check ID this scanner knows about, sorted."""
    return sorted(_build_index())


def _suggest(unknown: str, ids: list[str], limit: int = 5) -> list[str]:
    """Offer near-matches for an unknown ID, prefix match wins over
    fuzzy so ``GHA-100`` suggests ``GHA-001 … GHA-099`` first."""
    u = unknown.upper()
    # Same prefix (e.g. "GHA-") first.
    dash = u.find("-")
    prefix = u[: dash + 1] if dash > 0 else ""
    prefix_hits = [i for i in ids if prefix and i.startswith(prefix)][:limit]
    if prefix_hits:
        return prefix_hits
    # Fallback: substring match.
    return [i for i in ids if u in i][:limit]


def render(check_id: str) -> tuple[str, int]:
    """Render the explain body for *check_id*.

    Returns ``(text, exit_code)``. Unknown IDs render a suggestion
    list and return exit code 3 so shell scripts can detect typos.
    """
    cid = check_id.strip().upper()
    index = _build_index()
    meta = index.get(cid)
    if meta is None:
        ids = available_ids()
        suggestions = _suggest(cid, ids)
        lines = [f"Unknown check ID: {check_id!r}.", ""]
        if suggestions:
            lines.append("Did you mean:")
            for s in suggestions:
                lines.append(f"  {s}  {index[s].title}")
            lines.append("")
        lines.append(
            "Run ``pipeline_check --pipeline <provider> --list-checks`` "
            "to see all IDs for a provider, or ``pipeline_check "
            "--man`` for the manual index."
        )
        return "\n".join(lines) + "\n", 3

    return _render_meta(meta), 0


def _render_meta(meta: _CheckMeta) -> str:
    """Plain-text body for one check."""
    lines: list[str] = []
    confidence = confidence_for(meta.id)

    header = (
        f"{meta.id}  ·  {meta.severity.value}  ·  {confidence.value} confidence"
    )
    lines.append(header)
    lines.append(meta.title)
    lines.append("")

    # Compliance cross-references, grouped by standard.
    refs = resolve_for_check(meta.id)
    if refs:
        by_std: dict[str, list[str]] = {}
        std_titles: dict[str, str] = {}
        for r in refs:
            by_std.setdefault(r.standard, []).append(r.control_id)
            std_titles[r.standard] = r.standard_title
        col_width = max(len(s) for s in by_std) + 2
        for std in sorted(by_std):
            ctrls = ", ".join(sorted(set(by_std[std])))
            lines.append(f"  {std:<{col_width}}{ctrls}")
        lines.append("")

    # Rule-based content, the fully-populated path.
    if meta.source == "rule" and meta.rule is not None:
        rule = meta.rule
        if rule.cwe:
            lines.append(f"  CWE: {', '.join(rule.cwe)}")
            lines.append("")
        if rule.docs_note:
            lines.append("[What it checks]")
            for para in rule.docs_note.strip().splitlines():
                lines.append(f"  {para}" if para else "")
            lines.append("")
        if rule.known_fp:
            lines.append("[Known false-positive modes]")
            for mode in rule.known_fp:
                lines.append(f"  * {mode}")
            lines.append("")
        if rule.recommendation:
            lines.append("[How to fix]")
            for para in rule.recommendation.strip().splitlines():
                lines.append(f"  {para}" if para else "")
            lines.append("")
    else:
        # Class-based fallback, the docstring table we matched the
        # row from is the most reliable thing we have.
        lines.append("[What it checks]")
        lines.append(
            "  Reference implementation lives in a class-based check "
            "module; run the scanner to see the exact resource match "
            "or consult the provider reference doc."
        )
        lines.append("")

    # Cross-reference any attack chains whose triggering_check_ids
    # include this rule. Surfaces the rule -> chain relationship so
    # an operator reading ``--explain GHA-001`` sees that the
    # finding feeds into AC-009 / AC-018 / AC-003 etc.
    triggering_chains = _chains_for_check_id(meta.id)
    if triggering_chains:
        lines.append("[Triggers attack chains]")
        for chain_rule in triggering_chains:
            lines.append(
                f"  {chain_rule.id}  {chain_rule.title}  "
                f"[{chain_rule.severity.value}]"
            )
        lines.append(
            "  Run ``pipeline_check --explain AC-NNN`` for the full "
            "kill-chain narrative."
        )
        lines.append("")

    # Topic-clustered cross-references, same threat / different layer
    # or same control / different provider. Keeps the operator from
    # fixing GHA-008 in isolation when GL-008 / BB-008 / etc. share
    # the same root cause across the rest of the repo.
    related = _related_check_ids(meta.id)
    if related:
        index = _build_index()
        # Drop entries the index doesn't know about, guards against
        # a cluster typo or a deleted-but-not-removed-from-cluster
        # ID surfacing in user output. ``test_topic_clusters_*`` traps
        # the same drift at CI time.
        known = [cid for cid in related if cid in index]
        if known:
            lines.append("[Related rules]")
            for cid in known:
                title = index[cid].title
                sev = index[cid].severity.value
                lines.append(f"  {cid}  {title}  [{sev}]")
            lines.append(
                "  Same threat / different layer or same control / "
                "different provider, fixing only the rule you opened "
                "leaves these uncovered. Run ``pipeline_check --explain "
                "<id>`` for any of them."
            )
            lines.append("")

    # Whether the rule has a registered autofixer. The user can run
    # ``--fix`` to emit the patch and ``--apply`` to write it in
    # place; some autofixers are comment-only (drop a TODO marker
    # above the line) where text rewriting can't safely synthesize
    # the structural fix. The exact shape is visible in the patch.
    if meta.id.upper() in available_fixers():
        lines.append("[Autofixable]")
        lines.append(
            "  Yes, run ``pipeline_check --fix`` to emit the patch, "
            "or ``--fix --apply`` to write it in place."
        )
        lines.append("")

    # Cross-references surfaced at the end so the body stays skimmable.
    lines.append("[See also]")
    lines.append(
        "  pipeline_check --pipeline <provider> --list-checks  "
        "(every check for the provider)"
    )
    lines.append("  pipeline_check --man                             "
                 "(manual topic index)")

    return "\n".join(lines) + "\n"


def print_explain(check_id: str) -> int:
    """CLI entry point, print and return the exit code."""
    body, code = render(check_id)
    sys.stdout.write(body)
    return code
