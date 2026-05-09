"""DF-020, ``ARG`` declares a credential-named build argument."""
from __future__ import annotations

from ..._primitives.secret_shapes import SECRETISH_KEY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-020",
    title="ARG declares a credential-named build argument",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532",),
    recommendation=(
        "Don't pass secrets through ``ARG``. Build arguments are "
        "recorded in ``docker history`` whether the value comes from "
        "a default or from ``--build-arg`` at build time, so a "
        "credential-named ARG leaks the secret to anyone who can pull "
        "the image. Use ``RUN --mount=type=secret,id=<name>`` and "
        "feed the value with BuildKit's ``--secret`` flag, the "
        "secret never lands in a layer or in the build history."
    ),
    docs_note=(
        "Complements DF-006 (which flags an ENV/ARG with a literal "
        "credential-shaped value). This rule fires on the *name* "
        "alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, "
        "``ARG DB_PASSWORD``, even when no default is set, because "
        "BuildKit records the resolved value in the image's history "
        "the moment ``--build-arg`` supplies one. Names are matched "
        "via the same ``_primitives/secret_shapes`` regex used by "
        "the other secret-name rules."
    ),
    known_fp=(
        "An ``ARG`` whose name matches the regex but is a non-secret "
        "config knob (a counter-example like ``ARG TOKEN_LIMIT``). "
        "Rare; rename or suppress the finding with a brief "
        "rationale.",
    ),
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    seen: set[tuple[int, str]] = set()
    for ins in iter_instructions(df, directive="ARG"):
        body = ins.args
        # ``ARG`` accepts only one variable per directive but the value
        # may carry an ``=default``. Take the part before ``=`` as the
        # name; trim any quotes / whitespace.
        name = body.split("=", 1)[0].strip().strip('"').strip("'")
        if not name or not SECRETISH_KEY_RE.search(name):
            continue
        key = (ins.line_no, name)
        if key in seen:
            continue
        seen.add(key)
        offenders.append(f"L{ins.line_no}: ARG {name}")
    passed = not offenders
    desc = (
        "No ``ARG`` declares a credential-named build argument."
        if passed else
        f"{len(offenders)} ``ARG`` directive(s) carry a credential-"
        f"shaped name: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``--build-arg`` "
        f"values land in ``docker history``; switch to "
        f"``RUN --mount=type=secret``."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
