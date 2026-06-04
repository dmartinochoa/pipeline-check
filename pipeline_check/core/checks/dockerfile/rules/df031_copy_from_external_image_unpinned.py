"""DF-031, `COPY --from=<external image>` not pinned to a sha256 digest."""
from __future__ import annotations

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-031",
    title="COPY --from external image not pinned to sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin the image in ``COPY --from=<image>`` (and "
        "``ADD --from=<image>``) to an immutable ``@sha256:<digest>``, "
        "the same way DF-001 requires for ``FROM``. A ``--from`` that "
        "names an external image (not an earlier ``FROM ... AS <stage>``) "
        "pulls that image at build time and copies bytes out of it, so a "
        "floating tag lets the registry serve different content under the "
        "same reference, and a typosquatted / taken-over name ships an "
        "attacker's binary straight into the final image. Resolve the "
        "digest (``docker buildx imagetools inspect <ref>``) and let "
        "Renovate / Dependabot refresh it. For first-party content, copy "
        "from a named build stage instead."
    ),
    docs_note=(
        "Fires when a ``COPY`` / ``ADD`` carries ``--from=<X>`` where "
        "``X`` is an external image reference (it contains a registry / "
        "tag / digest separator and does not match an earlier "
        "``FROM ... AS <stage>`` name or a numeric stage index) and ``X`` "
        "is not ``@sha256:``-pinned. DF-001 only inspects ``FROM``, so an "
        "unpinned ``COPY --from=<image>`` (a common way to pull "
        "``cosign`` / ``kubectl`` / a CA bundle into the build) sidesteps "
        "it entirely. Reuses ``_primitives/image_pinning.classify`` so a "
        "floating tag and a pinned-but-mutable tag are both treated as "
        "unpinned, matching DF-001. A ``--from=<stage>`` (a named or "
        "numbered build stage) and a bare build-context name are not "
        "flagged."
    ),
    exploit_example=(
        "# Vulnerable: COPY --from pulls an external image by floating\n"
        "# tag and copies a binary out of it into the final image. The\n"
        "# registry can serve different content under that tag, and a\n"
        "# namespace takeover ships an attacker's binary into the build.\n"
        "FROM gcr.io/distroless/static@sha256:abc123...\n"
        "COPY --from=sigstore/cosign:latest /ko-app/cosign /usr/local/bin/cosign\n"
        "ENTRYPOINT [\"/entrypoint.sh\"]\n"
        "\n"
        "# Attack: the cosign tag is repointed (or the namespace taken\n"
        "# over) to an image whose /ko-app/cosign is a backdoored binary.\n"
        "# The next build copies it into the shipped image, no FROM line\n"
        "# changed, so DF-001 never sees it.\n"
        "\n"
        "# Safe: pin the external image to a digest (or copy from a\n"
        "# named, first-party build stage).\n"
        "COPY --from=sigstore/cosign@sha256:def456... /ko-app/cosign /usr/local/bin/cosign"
    ),
)

# Characters that only appear in an image REFERENCE, never in a Docker
# build-stage name (``[a-z0-9._-]+``) or a ``--build-context`` name. Their
# presence is what distinguishes ``--from=alpine:3.18`` / ``--from=ghcr.io/x/y``
# from ``--from=builder`` (a stage) or ``--from=mycontext`` (a build context).
_IMAGE_REF_CHARS = ("/", ":", "@")


def _stage_names(df: Dockerfile) -> set[str]:
    names: set[str] = set()
    for ins in iter_instructions(df, directive="FROM"):
        toks = ins.args.split()
        for i, tok in enumerate(toks):
            if tok.lower() == "as" and i + 1 < len(toks):
                names.add(toks[i + 1].lower())
    return names


def _copy_add_from_refs(df: Dockerfile) -> list[tuple[int, str, str]]:
    """Return ``[(line_no, directive, from_value), ...]`` for COPY/ADD --from."""
    out: list[tuple[int, str, str]] = []
    for ins in df.instructions:
        if ins.directive not in ("COPY", "ADD"):
            continue
        for tok in ins.args.split():
            if tok.lower().startswith("--from="):
                out.append((ins.line_no, ins.directive, tok.split("=", 1)[1]))
                break
    return out


def check(df: Dockerfile) -> Finding:
    stages = _stage_names(df)
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, directive, value in _copy_add_from_refs(df):
        low = value.lower()
        if low in stages or value.isdigit():
            continue  # named or numbered build stage, not an image
        if not any(c in value for c in _IMAGE_REF_CHARS):
            continue  # bare name: a build stage / build context, not flagged
        kind = classify(value)
        if kind is PinKind.DIGEST:
            continue
        offenders.append(f"L{line_no}: {directive} --from={value} ({kind.value})")
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every ``COPY``/``ADD --from`` external image is digest-pinned."
        if passed else
        f"{len(offenders)} ``--from`` external image(s) are not digest-"
        f"pinned: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The image is pulled at "
        f"build time and bytes copied into the final image; a mutable "
        f"tag lets the registry swap that content."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
