"""ADO-030, ``pool:`` interpolates an attacker-controllable value."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import POOL_TAINT_RE

RULE = Rule(
    id="ADO-030",
    title="pool interpolates attacker-controllable value",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-345",),
    recommendation=(
        "Hard-code ``pool:`` to a specific agent pool name (or "
        "``vmImage:`` for Microsoft-hosted). If pool selection has to "
        "be parameterised, validate the candidate against an explicit "
        "allowlist before the job runs (e.g. a ``condition:`` guard "
        "against a vetted set), and never inline ``$(Build.*)`` / "
        "``$(System.PullRequest.*)`` / ``${{ parameters.X }}`` values "
        "as the pool name or as a demand."
    ),
    docs_note=(
        "ADO-013 catches self-hosted pools that aren't ephemeral; "
        "this rule catches the upstream targeting choice. When "
        "``pool:`` (or its ``name`` / ``demands`` sub-fields) is "
        "computed from an attacker-controllable expression, whoever "
        "triggers the pipeline picks where the job runs, including "
        "any agent pool the project exposes (``deploy-prod``, "
        "``signer``, ``hsm`` …). Two attacker surfaces are flagged: "
        "runtime SCM macros (``$(Build.SourceBranchName)``, "
        "``$(System.PullRequest.SourceBranch)``, …) and caller-"
        "controlled template parameters (``${{ parameters.X }}``, "
        "the value comes from whoever queued the run). The rule "
        "walks all three pool shapes, string scalar, dict "
        "``{ name, vmImage, demands }``, and the ``demands`` list "
        "form."
    ),
    known_fp=(
        "Pipelines that intentionally select agent pools via a vetted "
        "``variables:`` block (``POOL_NAME: prod-pool``) are out of "
        "scope, pipeline variables defined in the same file are "
        "author-controlled. Static custom names are not flagged. The "
        "rule only matches the curated runtime-macro catalog and the "
        "literal ``${{ parameters.X }}`` template-parameter shape.",
    ),
    exploit_example=(
        "# Vulnerable: pool name computed from caller-controlled parameter.\n"
        "# Queuing via the REST API lets the caller choose any agent pool\n"
        "# the project exposes, including privileged self-hosted pools.\n"
        "#\n"
        "#   POST .../_apis/pipelines/42/runs\n"
        "#   { \"templateParameters\": { \"targetPool\": \"signer-hsm\" } }\n"
        "#\n"
        "# The job lands on ``signer-hsm``; build.sh runs on a host with\n"
        "# the signing key mounted and can exfiltrate it.\n"
        "parameters:\n"
        "  - name: targetPool\n"
        "    type: string\n"
        "    default: linux-pool\n"
        "jobs:\n"
        "  - job: build\n"
        "    pool:\n"
        "      name: ${{ parameters.targetPool }}\n"
        "    steps:\n"
        "      - bash: ./scripts/build.sh\n"
        "\n"
        "# Safe: hard-code the pool to a literal name.\n"
        "jobs:\n"
        "  - job: build\n"
        "    pool:\n"
        "      name: linux-pool\n"
        "    steps:\n"
        "      - bash: ./scripts/build.sh"
    ),
)


def _pool_strings(pool: Any) -> list[str]:
    """Return every string value contributing to a *pool* declaration.

    Three shapes are walked:

    * scalar, ``pool: prod-pool``
    * dict, ``pool: { name: prod-pool, vmImage: ubuntu-latest }``
    * dict with demands, ``pool: { name: …, demands: [a -equals b] }``

    ``vmImage`` is intentionally excluded because Microsoft-hosted
    images aren't a privileged-runner targeting surface. Non-string
    entries (a malformed pipeline with an int demand) are skipped
    silently, the YAML loader already accepted them, so the
    surface for injection is what matters here, not the schema.
    """
    out: list[str] = []
    if isinstance(pool, str):
        out.append(pool)
    elif isinstance(pool, dict):
        name = pool.get("name")
        if isinstance(name, str):
            out.append(name)
        demands = pool.get("demands")
        if isinstance(demands, str):
            out.append(demands)
        elif isinstance(demands, list):
            for item in demands:
                if isinstance(item, str):
                    out.append(item)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan(pool: Any, where: str) -> None:
        for value in _pool_strings(pool):
            if POOL_TAINT_RE.search(value):
                offenders.append(where)
                return

    _scan(doc.get("pool"), "<top>")
    # Stage-level ``pool:`` applies to every job in the stage and is
    # a separate declaration site from job-level. ``iter_jobs``
    # flattens stages → jobs so it doesn't yield the stage dict
    # itself; walk the stages list explicitly.
    stages = doc.get("stages")
    if isinstance(stages, list):
        for i, stage in enumerate(stages):
            if not isinstance(stage, dict):
                continue
            stage_loc = str(stage.get("stage") or f"stage{i}")
            _scan(stage.get("pool"), stage_loc)
    for job_loc, job in iter_jobs(doc):
        _scan(job.get("pool"), job_loc)
    passed = not offenders
    desc = (
        "No ``pool:`` declaration interpolates attacker-controllable values."
        if passed else
        f"{len(offenders)} ``pool:`` declaration(s) compute the "
        f"target agent from attacker-controllable input: "
        f"{', '.join(sorted(set(offenders))[:5])}"
        f"{'…' if len(set(offenders)) > 5 else ''}. "
        f"A trigger (or anyone whose PR / branch the pipeline "
        f"consumes) can route the job onto any agent pool the "
        f"project exposes, including privileged self-hosted pools."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
