"""DF-006, ``ENV`` / ``ARG`` carries a credential-shaped literal value."""
from __future__ import annotations

from ..._primitives.secret_shapes import (
    SECRETISH_KEY_RE,
    aws_key_in,
    is_placeholder_value,
)
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-006",
    title="ENV or ARG carries a credential-shaped literal value",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Never hard-code credentials in a Dockerfile. ``ENV`` values "
        "are baked into the image layer history, even if the value is "
        "later overwritten, ``docker history --no-trunc`` reads the "
        "original. Use ``RUN --mount=type=secret`` for build-time "
        "secrets or runtime env injection (``docker run -e SECRET=…``) "
        "for runtime ones. Rotate any secret already exposed."
    ),
    docs_note=(
        "Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed "
        "AWS keys outright (the literal AWS access-key shape) and "
        "credential-named keys (``API_KEY``, ``DB_PASSWORD``, "
        "``SECRET_TOKEN``) when the value is a non-empty literal."
    ),
    exploit_example=(
        "# Vulnerable: ``API_KEY=sk_live_...`` lands in the image's\n"
        "# layer history. ``docker history --no-trunc <image>`` (any\n"
        "# user who can pull the image) prints the literal value\n"
        "# even when a later layer overwrites or unsets it. Public\n"
        "# images on Docker Hub are pulled and inspected en masse by\n"
        "# secret scanners; private images leak the same way to\n"
        "# anyone who exfils the registry credentials.\n"
        "FROM node:20-alpine@sha256:abc123...\n"
        "ENV API_KEY=sk_live_abc123def456ghi789\n"
        "COPY . /app\n"
        "RUN cd /app && npm ci\n"
        "\n"
        "# Safe: keep the secret out of the image entirely. Use\n"
        "# BuildKit's ``--mount=type=secret`` for build-time access\n"
        "# (the secret never lands in any layer), and runtime\n"
        "# injection (``docker run -e API_KEY=$VAULT_API_KEY``) for\n"
        "# the running container. The Dockerfile only references\n"
        "# the secret by mount path or env-var name.\n"
        "# syntax=docker/dockerfile:1.7\n"
        "FROM node:20-alpine@sha256:abc123...\n"
        "COPY . /app\n"
        "RUN --mount=type=secret,id=api_key \\\n"
        "    cd /app && API_KEY=$(cat /run/secrets/api_key) npm ci"
    ),
)


def _looks_literal(value: str) -> bool:
    """A non-empty value that doesn't look like a build-arg / env-var
    indirection. Indirection forms (``$VAR``, ``${VAR}``, ``''``) are
    safe. They receive their actual content at build / run time."""
    if not value:
        return False
    if value.startswith("$"):
        return False
    if value in ("", '""', "''"):
        return False
    return True


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, key, value in env_pairs(df):
        hit = False
        # Direct AWS-key shape match, flag regardless of key name.
        if aws_key_in(value):
            offenders.append(f"L{line_no}: {key} (AKIA-shaped value)")
            hit = True
        # Secret-named key + literal value.
        elif (
            SECRETISH_KEY_RE.search(key)
            and _looks_literal(value)
            and not is_placeholder_value(value)
        ):
            offenders.append(f"L{line_no}: {key} (literal credential-shaped name)")
            hit = True
        if hit:
            locations.append(Location(
                path=df.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No ``ENV`` / ``ARG`` directive carries a credential-shaped literal."
        if passed else
        f"{len(offenders)} directive(s) bake credential-shaped values "
        f"into image layers: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``docker history`` "
        f"surfaces the original value even if it's later overwritten."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
