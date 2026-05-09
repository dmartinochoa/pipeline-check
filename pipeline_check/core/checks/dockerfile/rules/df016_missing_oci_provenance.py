"""DF-016. Image lacks OCI provenance labels."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-016",
    title="Image lacks OCI provenance labels",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE", "ESF-S-IMMUTABLE"),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a ``LABEL`` line carrying at least "
        "``org.opencontainers.image.source`` (the URL of the source "
        "repo) and ``org.opencontainers.image.revision`` (the commit "
        "SHA built into the image). Most registries surface those "
        "fields in the UI and on ``manifest inspect``, which closes "
        "the source-to-image gap that GHA-006 / SLSA Build-L2 "
        "provenance attestation also addresses."
    ),
    docs_note=(
        "The OCI image-spec annotation set is a small de facto "
        "standard maintained by the OCI working group. Only "
        "``image.source`` and ``image.revision`` are checked because "
        "they're the two whose absence makes incident response "
        "materially harder; ``image.title`` / ``image.description`` "
        "are nice-to-have but the rule doesn't fire on those."
    ),
    known_fp=(
        "A multi-stage build's intermediate stages don't need "
        "provenance labels, only the final image ships. The rule "
        "fires per Dockerfile, not per stage; suppress for files "
        "where the final ``FROM`` is intentional throwaway scratch.",
    ),
)


_REQUIRED_LABELS: tuple[str, ...] = (
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
)


# A LABEL line can carry multiple key=value pairs. Match each key
# token (with either ``=`` or whitespace separator). Quoted keys are
# rare but valid; tolerate single + double quotes around the key.
_LABEL_KEY_RE = re.compile(
    r"""
    (?<![\w.-])
    [\"']?
    (?P<key>[\w.-]+)
    [\"']?
    \s*=
    """,
    re.VERBOSE,
)


def _present_labels(df: Dockerfile) -> set[str]:
    keys: set[str] = set()
    for ins in iter_instructions(df, directive="LABEL"):
        for m in _LABEL_KEY_RE.finditer(ins.args):
            keys.add(m.group("key"))
    return keys


def check(df: Dockerfile) -> Finding:
    present = _present_labels(df)
    missing = [k for k in _REQUIRED_LABELS if k not in present]
    passed = not missing
    desc = (
        "Image declares both org.opencontainers.image.source and "
        "image.revision provenance labels."
        if passed else
        f"Image is missing OCI provenance label(s): "
        f"{', '.join(missing)}. Without them an image pulled from "
        f"the registry can't be traced back to a source revision."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
