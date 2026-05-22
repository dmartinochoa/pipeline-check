"""Generate the per-chain detail catalog inside ``docs/attack_chains.md``.

The handwritten part of the doc (intro, registered-chains table,
output format, gating, confidence inheritance, "adding a new chain")
stays untouched. This script injects the per-chain detail block
between sentinel markers:

    <!-- chain-catalog:start -->
    …generated cards…
    <!-- chain-catalog:end -->

Each card is keyed off the ``ChainRule`` dataclass exposed by every
module under ``pipeline_check/core/chains/rules/``: severity chip +
MITRE ATT&CK technique pills + kill-chain phase tag + summary +
references + recommendation. Same visual language as the per-rule
cards in provider docs, so a user moving from a provider page to
the chains page sees a consistent design.

Usage
-----
    python scripts/gen_attack_chains_doc.py            # rewrites docs/attack_chains.md in place
    python scripts/gen_attack_chains_doc.py --check    # exit 1 if the file would change
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pipeline_check.core.chains import engine  # noqa: E402

DOC_PATH = REPO_ROOT / "docs" / "attack_chains.md"
START = "<!-- chain-catalog:start -->"
END = "<!-- chain-catalog:end -->"


# Provider rule-id prefix → provider doc slug, mirrors the table in
# scripts/link_standards_check_ids.py. Triggering checks rendered in
# narrative blocks become click-through links to the provider rule
# pages where possible. Keep in sync with the linker. We don't
# share the table because that script lives at script-runtime,
# while this one runs at doc-gen-time and we want it standalone.
_PREFIX_TO_PROVIDER: dict[str, str] = {
    "GHA": "github", "GL": "gitlab", "BB": "bitbucket", "ADO": "azure",
    "JF": "jenkins", "CC": "circleci", "GCB": "cloudbuild",
    "DF": "dockerfile", "K8S": "kubernetes",
    "TF": "terraform", "CF": "cloudformation",
}
_ANCHORED_PROVIDERS = frozenset(_PREFIX_TO_PROVIDER.values())


def _severity_chip(severity: str) -> str:
    sev_lc = severity.lower()
    return f'<span class="pg-sev pg-sev--{sev_lc}">{severity}</span>'


def _render_chain(rule) -> str:
    """One ``<div class="pg-rule pg-rule--<sev>">`` card per chain."""
    sev = rule.severity.value
    sev_lc = sev.lower()
    anchor = rule.id.lower()
    parts: list[str] = []

    parts.append(f'<div class="pg-rule pg-rule--{sev_lc}" markdown>\n\n')
    parts.append(f"### {rule.id}: {rule.title} {{ #{anchor} }}\n\n")

    # Chip row: severity + MITRE techniques + kill-chain phase
    chips: list[str] = [_severity_chip(sev)]
    for tech in rule.mitre_attack:
        chips.append(
            f'<span class="pg-tag" title="MITRE ATT&CK technique">'
            f'MITRE {tech}</span>'
        )
    if rule.kill_chain_phase:
        chips.append(
            f'<span class="pg-tag" title="kill-chain phase">'
            f'{rule.kill_chain_phase}</span>'
        )
    if rule.providers:
        for prov in rule.providers:
            chips.append(f'<span class="pg-tag pg-tag--owasp">{prov}</span>')
    parts.append('<div class="pg-rule__tags">\n')
    parts.append(" ".join(chips) + "\n")
    parts.append("</div>\n\n")

    if rule.summary:
        parts.append(rule.summary.strip() + "\n\n")

    if rule.references:
        parts.append("**References**\n\n")
        for ref in rule.references:
            parts.append(f"- <{ref}>\n")
        parts.append("\n")

    if rule.recommendation:
        parts.append('<div class="pg-rule__rec" markdown>\n\n')
        parts.append("**Recommended action**\n\n")
        parts.append(rule.recommendation.strip() + "\n\n")
        parts.append("</div>\n\n")

    parts.append("</div>\n\n")
    return "".join(parts)


def _render_catalog() -> str:
    """All chain cards stitched together, sorted by chain id."""
    rules = sorted(engine.list_rules(), key=lambda r: r.id)
    out = ["## Chain catalog\n\n"]
    out.append(
        "Click any chain in the [registered chains](#registered-chains) "
        "table above to jump to its detail card below. Each card "
        "carries the chain's severity, MITRE ATT&CK techniques, "
        "kill-chain phase, summary prose, references, and the "
        "remediation that breaks the chain.\n\n"
    )
    for rule in rules:
        out.append(_render_chain(rule))
    return "".join(out)


def _splice(original: str, generated: str) -> str:
    if START not in original or END not in original:
        # First-time injection, append after the file's existing
        # content, with a blank line before the start sentinel.
        return original.rstrip() + f"\n\n{START}\n\n{generated}\n{END}\n"
    pre, _, rest = original.partition(START)
    _, _, post = rest.partition(END)
    return f"{pre}{START}\n\n{generated}\n{END}{post}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the file would change. Useful in CI.",
    )
    args = parser.parse_args()

    original = DOC_PATH.read_text(encoding="utf-8")
    generated = _render_catalog()
    new = _splice(original, generated)

    if args.check:
        if new != original:
            print(
                f"[gen-chains] {DOC_PATH.name}: out of sync. "
                f"Re-run scripts/gen_attack_chains_doc.py to update.",
                file=sys.stderr,
            )
            return 1
        print(f"[gen-chains] {DOC_PATH.name}: in sync")
        return 0

    if new == original:
        print(f"[gen-chains] {DOC_PATH.name}: no changes needed")
        return 0
    DOC_PATH.write_text(new, encoding="utf-8")
    rules_n = len(list(engine.list_rules()))
    print(f"[gen-chains] {DOC_PATH.name}: {rules_n} chain(s) injected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
