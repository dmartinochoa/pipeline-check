"""DF-006, ``ENV`` / ``ARG`` carries a credential-shaped literal value."""
from __future__ import annotations

from ..._primitives.secret_shapes import AWS_KEY_RE, SECRETISH_KEY_RE
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
        if AWS_KEY_RE.search(value):
            offenders.append(f"L{line_no}: {key} (AKIA-shaped value)")
            hit = True
        # Secret-named key + literal value.
        elif SECRETISH_KEY_RE.search(key) and _looks_literal(value):
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
