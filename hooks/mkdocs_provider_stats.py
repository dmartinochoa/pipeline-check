"""MkDocs hook that injects per-provider rule counts into markdown.

Pages can write tokens like ``{{ providers.github.checks }}`` and this
hook swaps them out at build time with a live "N checks" label parsed
from the rule modules under
``pipeline_check/core/checks/<name>/rules/``.

Why count files instead of importing: the docs CI environment installs
MkDocs Material from ``requirements-docs.txt`` but does not install the
package itself, so ``from pipeline_check.core.checks import …`` isn't
available. Counting one-rule-per-file modules under each provider's
``rules/`` directory matches the rule-discovery contract documented in
``tests/test_doc_claims.py`` and stays robust against a package the
docs build can't import.

Two provider categories produce non-numeric labels:

- **Helm** aggregates the chart-supply-chain ``HELM-*`` pack with the
  rendered-manifest ``K8S-*`` pack (a Helm scan renders charts and runs
  the K8s rule pack on the output). The label is
  ``"N checks (M K8S + K HELM)"`` so a reader sees the combined total
  and the breakdown.
- **Terraform** and **CloudFormation** are class-based, not
  rule-file-based. The label is ``"AWS-parity"`` / ``"~N class-based"``
  since both registries are AWS-derived by design.

Registered via the ``hooks:`` key in ``mkdocs.yml``.
"""
from __future__ import annotations

import re
from pathlib import Path

_CHECKS_DIR = (
    Path(__file__).resolve().parent.parent
    / "pipeline_check" / "core" / "checks"
)

_TOKEN_RE = re.compile(
    r"\{\{\s*providers\.(?P<name>[a-z0-9_]+)\.(?P<field>checks)\s*\}\}"
)

#: Cell label for class-based packs. The number for CloudFormation is
#: a rounded estimate; the actual count is verified by
#: ``tests/test_doc_claims.py::test_total_check_floor`` so it can drift
#: ±5 without flagging. The Terraform label is qualitative because the
#: pack is exact AWS-parity by design.
_CLASS_BASED_LABELS = {
    "terraform": "AWS-parity",
    "cloudformation": "~63 class-based",
}


def _count_rule_files(provider_slug: str) -> int:
    """Count one-rule-per-file modules under ``<provider>/rules/``.

    Returns 0 when the provider isn't present (a token in an unrelated
    page won't crash the build).
    """
    rules_dir = _CHECKS_DIR / provider_slug / "rules"
    if not rules_dir.is_dir():
        return 0
    n = 0
    for p in rules_dir.iterdir():
        if p.suffix != ".py":
            continue
        if p.name == "__init__.py" or p.name.startswith("_"):
            continue
        n += 1
    return n


def _build_index() -> dict[str, dict[str, str]]:
    """Snapshot the per-provider label for every provider on disk.

    Computed once at hook-load time. Adding a new rule means re-running
    ``mkdocs build`` for the count to refresh, same contract as the
    standards-stats hook.
    """
    out: dict[str, dict[str, str]] = {}
    if not _CHECKS_DIR.exists():
        return out
    for prov in _CHECKS_DIR.iterdir():
        if not prov.is_dir():
            continue
        if prov.name.startswith("_") or prov.name == "__pycache__":
            continue
        if prov.name in _CLASS_BASED_LABELS:
            out[prov.name] = {"checks": _CLASS_BASED_LABELS[prov.name]}
            continue
        n = _count_rule_files(prov.name)
        if n == 0:
            continue
        out[prov.name] = {"checks": f"{n} checks"}

    # Helm's tile shows the combined K8S + HELM total to match how a
    # Helm scan actually behaves (chart rendered, K8s rule pack run on
    # the output). Override the plain "10 checks" derived above.
    helm = _count_rule_files("helm")
    k8s = _count_rule_files("kubernetes")
    if helm and k8s:
        out["helm"] = {
            "checks": f"{helm + k8s} checks ({k8s} K8S + {helm} HELM)"
        }

    return out


_INDEX = _build_index()


def on_page_markdown(markdown: str, **_kwargs: object) -> str:
    if "{{ providers." not in markdown:
        return markdown

    def _sub(m: re.Match[str]) -> str:
        info = _INDEX.get(m.group("name"))
        if info is None:
            return m.group(0)  # unknown provider — leave token in place
        return info.get(m.group("field"), "")

    return _TOKEN_RE.sub(_sub, markdown)
