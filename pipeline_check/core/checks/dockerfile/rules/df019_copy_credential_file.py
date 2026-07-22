"""DF-019, ``COPY`` / ``ADD`` source path looks like a credential file."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

#: Filenames that almost always carry a long-lived credential.
#: Match is performed on the basename of each source path. Avoid bare
#: ``config.json`` / ``credentials`` / ``config``. Those are too
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
        "``.pfx``, ``.jks``) are also flagged. Globs are not expanded, "
        "the rule reads the literal source token."
    ),
    known_fp=(
        "Empty placeholder files (``.env`` shipped as a template, "
        "``config.json`` carrying only public flags). Suppress with a "
        "brief ``.pipelinecheckignore`` rationale and prefer an "
        "explicit non-secret name (``.env.example``).",
    ),
    exploit_example=(
        "# Vulnerable: ``COPY .npmrc`` (or ``.aws/credentials`` /\n"
        "# ``.kube/config`` / ``.netrc``) bakes the host's local\n"
        "# credential file into the image. Anyone who pulls the\n"
        "# image extracts the credential via\n"
        "# ``docker save | tar xf -``; the secret rides the image\n"
        "# everywhere it's distributed.\n"
        "FROM node@sha256:abc123...\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "COPY .npmrc /root/.npmrc    # carries auth token into layer\n"
        "RUN npm ci && npm run build\n"
        "\n"
        "# Safe: use BuildKit's ``--mount=type=secret`` so the\n"
        "# credential file is mounted only for the RUN that needs\n"
        "# it. The secret never lands in any layer; ``docker save``\n"
        "# returns an image with no trace.\n"
        "# syntax=docker/dockerfile:1.7\n"
        "FROM node@sha256:abc123...\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \\\n"
        "    npm ci && npm run build"
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
    and any leading ``--flag=value`` tokens).

    Handles both the shell form (``COPY src dest``) and the JSON-array
    exec form (``COPY ["src", "dest"]``).
    """
    tokens = args.split()
    # Drop leading flags (``--from=...``, ``--chown=...``, ``--chmod=...``).
    while tokens and tokens[0].startswith("--"):
        tokens.pop(0)
    rest = " ".join(tokens).strip()
    if rest.startswith("[") and rest.endswith("]"):
        # JSON-array exec form: strip brackets/quotes off each element.
        tokens = [
            t.strip().strip("\"'")
            for t in rest[1:-1].split(",")
            if t.strip()
        ]
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
