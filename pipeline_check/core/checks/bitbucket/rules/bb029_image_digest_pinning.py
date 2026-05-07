"""BB-029 — ``image:`` (step or service) not pinned by sha256 digest."""
from __future__ import annotations

from typing import Any

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-029",
    title="image: (step or service) not pinned by sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve every ``image:`` reference to its current digest "
        "(``docker buildx imagetools inspect <ref>`` or ``crane "
        "digest <ref>``) and pin via ``image: name@sha256:<digest>``. "
        "Floating tags (``:latest``, ``:3``, no tag) silently swap "
        "the runtime image — the build's reproducibility invariant "
        "is broken and a registry-side compromise lands inside CI "
        "without any local change."
    ),
    docs_note=(
        "BB-001 / BB-009 only inspect ``pipe:`` references inside "
        "``script:`` lists. Step ``image:`` directives and "
        "``definitions.services.<name>.image:`` define the runtime "
        "container the build executes inside (and the auxiliary "
        "containers the step talks to over the loopback network). "
        "Both surfaces ship code into the build context — a "
        "compromised service image (the postgres container, the "
        "selenium-grid container, …) can exfiltrate every secret "
        "the step touches just as easily as the step image itself. "
        "This rule reuses ``_primitives.image_pinning.classify`` so "
        "the floating-tag semantics match GHA-001 / GL-001 / JF-009 "
        "/ ADO-009 / CC-003 / K8S-001."
    ),
    known_fp=(
        "Bitbucket-vendored helper images (``atlassian/`` namespace) "
        "are still treated as third-party — the registry can move "
        "the tag. Pin them too rather than suppressing the rule "
        "globally.",
    ),
)


def _walk_image_refs(doc: dict[str, Any]) -> list[tuple[str, str]]:
    """Yield ``(location, image_ref)`` tuples for every ``image:`` in *doc*.

    Two surfaces are walked:

    1. Step-level ``image:`` (the runtime container for the step).
       Iterated through the existing ``iter_steps`` helper so the
       location label matches every other Bitbucket rule (e.g.
       ``branches.main[0]``).
    2. Top-level ``definitions.services.<name>.image:``. The
       location label is ``definitions.services.<name>`` so the
       finding points operators at the right block.
    """
    refs: list[tuple[str, str]] = []
    # ── Step images ──────────────────────────────────────────────
    for loc, step in iter_steps(doc):
        image = step.get("image")
        if isinstance(image, str):
            refs.append((loc, image))
        elif isinstance(image, dict):
            # ``image: { name: foo:bar, run-as-user: 1001 }`` —
            # the same long form the Bitbucket schema documents.
            name = image.get("name")
            if isinstance(name, str):
                refs.append((loc, name))
    # ── Service images ───────────────────────────────────────────
    definitions = doc.get("definitions")
    if isinstance(definitions, dict):
        services = definitions.get("services")
        if isinstance(services, dict):
            for svc_name, svc in services.items():
                if not isinstance(svc, dict):
                    continue
                image = svc.get("image")
                if isinstance(image, str):
                    refs.append((f"definitions.services.{svc_name}", image))
                elif isinstance(image, dict):
                    name = image.get("name")
                    if isinstance(name, str):
                        refs.append((
                            f"definitions.services.{svc_name}", name,
                        ))
    return refs


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    for loc, ref in _walk_image_refs(doc):
        pin = classify(ref)
        if pin is PinKind.DIGEST:
            continue
        unpinned.append(f"{loc}: {ref}")
    passed = not unpinned
    desc = (
        "Every ``image:`` reference (step + service) is pinned by "
        "sha256 digest."
        if passed else
        f"{len(unpinned)} ``image:`` reference(s) are not digest-"
        f"pinned: {', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}. "
        f"A registry-side tag move silently swaps the container that "
        f"runs the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
