"""BB-034. Production deployment in a pull-request pipeline."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import PROD_ENV_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-034",
    title="Production deployment on a pull-request pipeline",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Don't bind a `pull-requests:` step to a production "
        "`deployment:` environment. A pull-request pipeline runs the PR "
        "branch's code, so this ships unreviewed (and on fork PRs, "
        "untrusted) changes straight to production with the production "
        "environment's scoped credentials, before any reviewer or "
        "merge gate. On pull requests deploy only to an ephemeral "
        "preview or `test` environment; move the production "
        "`deployment:` into the `branches:` section for your default "
        "branch (or a manual `custom:` pipeline) so it runs against "
        "merged, reviewed code with the environment's required "
        "reviewers enforced."
    ),
    docs_note=(
        "Fires when a step under the `pull-requests:` section declares a "
        "production-tier `deployment:` environment (a name matching "
        "`production` / `prod`). The PR branch's code reaches production "
        "before it is reviewed or merged, and the production "
        "deployment's scoped variables are exposed to PR-controlled "
        "pipeline steps. Steps under `branches:` / `default:` / "
        "`custom:` / `tags:` are out of scope, and per-PR preview, "
        "`test`, or `staging` environments don't fire, only a "
        "production-tier name on the pull-request-triggered section."
    ),
    known_fp=(
        "A repo that intentionally publishes a per-PR preview deployment "
        "to an environment it happens to have named `production`. Rename "
        "it to a preview / review tier, or suppress with a rationale. A "
        "production environment configured under a custom name (not "
        "`production` / `prod`) can't be recognized from the YAML alone "
        "and won't fire.",
    ),
    exploit_example=(
        "# Vulnerable: every pull request deploys to production.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step:\n"
        "          name: deploy\n"
        "          deployment: production\n"
        "          script:\n"
        "            - ./deploy.sh\n"
        "\n"
        "# Attack: a contributor opens a PR that edits deploy.sh (or any\n"
        "# build step); the PR pipeline runs it with the production\n"
        "# deployment's credentials and ships the change live before\n"
        "# review.\n"
        "\n"
        "# Safe: PRs deploy only to an ephemeral preview environment;\n"
        "# production deploys from the default branch post-merge.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step:\n"
        "          deployment: preview\n"
        "          script: [./deploy-preview.sh]\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          deployment: production\n"
        "          script: [./deploy.sh]"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for location, step in iter_steps(doc):
        if not location.startswith("pull-requests"):
            continue
        dep = step.get("deployment")
        if isinstance(dep, str) and PROD_ENV_RE.match(dep.strip()):
            offenders.append(location)
    passed = not offenders
    desc = (
        "No pull-request pipeline step deploys to a production environment."
        if passed else
        f"{len(offenders)} pull-request pipeline step(s) deploy to a "
        f"production environment: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The PR branch's code "
        f"ships to production with the deployment's scoped credentials, "
        f"before the change is reviewed or merged."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
