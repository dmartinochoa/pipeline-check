"""DF-019 — ``COPY`` / ``ADD`` source path looks like a credential file."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

#: Filenames that almost always carry a long-lived credential.
#: Match is performed on the basename of each source path. Avoid bare
#: ``config.json`` / ``credentials`` / ``config`` — those are too
#: ambiguous on their own; the path-tail set below catches the
#: canonical credential locations for those names.
_CREDENTIAL_BASENAMES: frozenset[str] = frozenset({
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".env",
    ".git-credentials",
    "terraform.tfvars",
    "kubeconfig",
})

#: Matched against the *full* path tail (case-insensitive) since a bare
#: ``credentials`` is too ambiguous to flag without context.
_CREDENTIAL_PATH_TAILS: tuple[str, ...] = (
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".ssh/id_rsa",
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",
)

#: File-extension patterns that strongly suggest private-key material.
_KEY_EXT_RE = re.compile(r"\.(pem|key|p12|pfx|jks)$", re.IGNORECASE)


RULE = Rule(
    id="DF-019",
    title="COPY/ADD source path looks like a credential file",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-538",),
    recommendation=(
        "Don't ``COPY`` credential files into an image. Anything baked "
        "into a layer is recoverable by anyone who can pull the image, "
        "even if a later step deletes the file. For build-time secrets "
        "(npm tokens, registry credentials, SSH deploy keys), use "
        "``RUN --mount=type=secret,id=<name>`` so the value lives only "
        "for the duration of the step. For runtime secrets, mount them "
        "from the orchestrator (Kubernetes Secret, ECS task role, "
        "Vault sidecar) instead."
    ),
    docs_note=(
        "Fires on any ``COPY`` or ``ADD`` whose source basename is a "
        "well-known credential filename (``id_rsa``, ``.npmrc``, "
        "``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path "
        "tail matches a canonical credential location "
        "(``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). "
        "Files with private-key extensions (``.pem``, ``.key``, ``.p12``, "
        "``.pfx``, ``.jks``) are also flagged. Globs are not expanded — "
        "the rule reads the literal source token."
    ),
    known_fp=(
        "Empty placeholder files (``.env`` shipped as a template, "
        "``config.json`` carrying only public flags). Suppress with a "
        "brief ``.pipelinecheckignore`` rationale and prefer an "
        "explicit non-secret name (``.env.example``).",
    ),
)


def _is_credential_source(src: str) -> bool:
    if not src or src.startswith("--"):
        return False
    norm = src.replace("\\", "/")
    lower = norm.lower()
    if any(lower.endswith(tail) for tail in _CREDENTIAL_PATH_TAILS):
        return True
    if _KEY_EXT_RE.search(lower):
        return True
    basename = norm.rsplit("/", 1)[-1]
    return basename in _CREDENTIAL_BASENAMES


def _sources(args: str) -> list[str]:
    """Return COPY/ADD source tokens (everything except the destination
    and any leading ``--flag=value`` tokens)."""
    tokens = args.split()
    # Drop leading flags (``--from=...``, ``--chown=...``, ``--chmod=...``).
    while tokens and tokens[0].startswith("--"):
        tokens.pop(0)
    # Final token is the destination; preceding ones are sources.
    return tokens[:-1] if len(tokens) >= 2 else []


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for ins in iter_instructions(df):
        if ins.directive not in ("COPY", "ADD"):
            continue
        for src in _sources(ins.args):
            if _is_credential_source(src):
                offenders.append(f"L{ins.line_no}: {ins.directive} {src}")
    passed = not offenders
    desc = (
        "No ``COPY`` / ``ADD`` source looks like a credential file."
        if passed else
        f"{len(offenders)} directive(s) bake credential-shaped files "
        f"into image layers: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anything copied into "
        f"a layer is recoverable from a pulled image."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
