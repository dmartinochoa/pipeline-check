"""GHA-088. Action ``uses:`` slug is a one or two character edit from a top action.

Mirrors zizmor's ``typosquat-uses`` audit. Offline edit-distance
check against a curated top-actions list in
``_primitives/top_actions.py``. Catches the canonical foot-guns:

  - ``actions/check0ut`` (digit zero instead of ``o``)
  - ``actons/checkout`` (missing ``i``)
  - ``actions/checkouts`` (trailing ``s``)
  - ``actions/setup-nodejs`` (suffix swap from ``setup-node``)

Pairs with GHA-040 (compromised SHA / tag), GHA-001 (unpinned
``uses:``), and GHA-091 (repojacking). Pure offline,
no network call. The list is hand-curated and intentionally biased
toward first-party / heavily-trafficked actions, edit-distance on a
long tail produces false positives that drown the rule.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..._primitives.top_actions import find_typosquat
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-088",
    title="Action ``uses:`` slug is a near-edit of a top-traffic action",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin the intended action. If the ``uses:`` slug above is "
        "what you meant, ignore this finding with a rationale; if "
        "it isn't, replace it with the canonical owner / repo "
        "named in the description, then pin to a 40-char commit "
        "SHA (GHA-001 covers the pin) and confirm the SHA is not "
        "on the curated compromised list (GHA-040). Typosquat "
        "actions are usually long-lived clones with a single "
        "modification, the exfiltration step the attacker added; "
        "the file count and lineage tell you which workflow "
        "primitive was substituted."
    ),
    docs_note=(
        "Edit-distance check over the parsed ``owner/repo`` slug "
        "of every ``uses:`` reference in the workflow, against the "
        "curated list in "
        "``pipeline_check.core.checks._primitives.top_actions``. "
        "Both step-level ``uses:`` (action references) and job-"
        "level ``uses:`` (reusable workflow references) are "
        "covered, slug comparison is case-insensitive, and "
        "Damerau-Levenshtein (transposition counts as one edit) "
        "handles ``actions/cehckout`` alongside ``actions/check0ut``. "
        "Distance ceiling is 2 by design, distance-3 false-"
        "positives are common on legitimate forks. Exact matches "
        "against any list entry never fire, so the rule is silent "
        "on canonical references. Refresh the list by PR with a "
        "citing public-stats source. Local refs (``./.github/...``) "
        "and docker step refs (``docker://...``) are out of scope."
    ),
    known_fp=(
        "Legitimate forks or community variants that intentionally "
        "carry a near-miss name (e.g., an internal fork named "
        "``acme/checkout`` mirroring ``actions/checkout``). "
        "Suppress per-finding with a rationale that names the fork "
        "and links the source. The rule cannot distinguish a "
        "well-known fork from a typosquat; intentional naming "
        "collisions are the operator's call.",
    ),
    incident_refs=(
        "OWASP CICD-SEC-3 (Dependency Chain Abuse) lists action-"
        "namespace squatting as a canonical attack shape; the "
        "curated industry examples (``actons/checkout``, "
        "``actions/check0ut``) appear in red-team reports and "
        "honey-action research from Aikido, Wiz, and "
        "JFrog Security Research.",
    ),
    exploit_example=(
        "# Vulnerable: ``actons/checkout`` (missing ``i``) compiles\n"
        "# fine and pulls from a namespace that anyone could have\n"
        "# registered. Reviewer eyes skim past the typo.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actons/checkout@v4\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: canonical action, SHA-pinned.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f4...        # v4.1.7\n"
        "      - run: ./build.sh"
    ),
)


def _iter_uses_refs(
    doc: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any] | None]]:
    """Yield ``(label, raw_uses, location_step)`` for every parseable
    remote ``uses:`` in *doc*.

    ``label`` is the ``job_id`` or ``job_id[step_index]`` handle for
    the finding description. ``location_step`` is the step dict (or
    ``None`` for job-level reusable refs) so the caller can build a
    :class:`Location` via :func:`step_location`.
    """
    for job_id, job in iter_jobs(doc):
        # Job-level reusable workflow uses.
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            yield job_id, job_uses, None
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if isinstance(uses, str):
                yield f"{job_id}[{idx}]", uses, step


def check(path: str, doc: dict[str, Any]) -> Finding:
    typosquats: list[str] = []
    locations: list[Location] = []
    for label, raw, step in _iter_uses_refs(doc):
        ref = parse_uses(raw)
        if ref is None:
            continue
        if ref.kind in ("local-action", "local-workflow", "docker"):
            continue
        if not ref.owner or not ref.repo:
            continue
        slug = f"{ref.owner}/{ref.repo}"
        match = find_typosquat(slug)
        if match is None:
            continue
        typosquats.append(f"{label}: {slug} (near-edit of {match})")
        if step is not None:
            locations.append(step_location(path, step))
        else:
            locations.append(Location(path=path))
    passed = not typosquats
    desc = (
        "No ``uses:`` slug is within edit-distance 2 of a curated "
        "top-traffic action."
        if passed else
        f"{len(typosquats)} ``uses:`` reference(s) are one or two "
        f"character edits from a top-traffic action: "
        f"{'; '.join(typosquats[:3])}"
        f"{'...' if len(typosquats) > 3 else ''}. Typosquat action "
        f"namespaces are a documented supply-chain attack shape."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
