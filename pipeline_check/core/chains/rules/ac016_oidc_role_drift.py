"""AC-016. OIDC role drift: ungated trust + over-broad permissions.

GitHub Actions OIDC federation lets a workflow assume an AWS IAM
role without storing long-lived credentials. The trust is split
across two sides:

- **GitHub side** decides *who* is allowed to request the OIDC
  token (the workflow file, the job, the environment, the branch).
  The strongest gate is GitHub's environment protection, required
  reviewers, deployment branches, which only fires for jobs that
  declare an ``environment:`` key.
- **AWS side** decides *what* the assumed role can do. The trust
  policy's ``token.actions.githubusercontent.com:sub`` claim
  filters which workflow can assume; the role's attached policies
  decide the action surface.

When **GHA-030** fires (a job uses ``id-token: write`` to mint an
OIDC token without an ``environment:`` gate) AND **IAM-002** fires
(the role being assumed has ``Action: '*'`` somewhere), the two
together remove both halves of the gate at once: any branch / any
PR can request the token, and once assumed the role does whatever
it wants. This is the load-bearing pattern behind the "long-lived
keys are gone, surely we're safer" misconception that has shipped
several public AWS breaches in the last two years.

Mirrors AC-011 / AC-015 in shape: each leg is a HIGH finding on
its own; the chain captures that the *combination* removes every
layer of defense the OIDC pattern was supposed to provide.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-016",
    title="OIDC role drift: ungated GitHub trust meets wildcard AWS authority",
    severity=Severity.CRITICAL,
    summary=(
        "A GitHub Actions workflow requests an OIDC token without an "
        "``environment:`` gate (GHA-030) AND the AWS IAM role it "
        "assumes carries a wildcard ``Action`` (IAM-002). Together, "
        "any branch, including a fork PR if the workflow is "
        "fork-runnable, can mint a token that maps to a role with "
        "broad authority over the account."
    ),
    mitre_attack=(
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1556",      # Modify Authentication Process
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
    ),
    kill_chain_phase="initial-access -> credential-access -> privilege-escalation",
    references=(
        "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        "https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-and-Access-Management",
    ),
    recommendation=(
        "Close either leg to break the chain. On the GitHub side: "
        "require an ``environment:`` key on every job that uses "
        "``id-token: write``, and configure that environment with "
        "required reviewers + deployment-branch restrictions. On "
        "the AWS side: scope the role's policies to specific "
        "actions and resources, replace ``Action: '*'`` with the "
        "narrow set the workflow actually needs. Best is both: "
        "environment gate + least-privilege role + a "
        "``token.actions.githubusercontent.com:sub`` condition in "
        "the role's trust policy that names the specific repo/ref."
    ),
    providers=("github", "aws"),
    triggering_check_ids=("GHA-030", "IAM-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "GHA-030"):
        return []
    if not has_failing(findings, "IAM-002"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"GHA-030", "IAM-002"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this scan:\n"
        "  1. A GitHub Actions job requests an OIDC token "
        "(``permissions: id-token: write``) without an "
        "``environment:`` key on the job (GHA-030). GitHub's "
        "environment protection, required reviewers, deployment "
        "branches, only enforces against jobs that declare an "
        "environment, so this job's token-mint is reachable from "
        "any branch the workflow runs on, including fork PRs if "
        "the trigger allows.\n"
        "  2. An AWS IAM role attached to the CI/CD principal set "
        "carries an ``Action: '*'`` (or service-prefix wildcard "
        "like ``s3:*``) in an attached policy (IAM-002). Whatever "
        "scope the wildcard covers becomes the role's effective "
        "authority.\n"
        "  3. If the trust policy on the wildcard-action role "
        "accepts the OIDC token from this workflow's repo (and the "
        "token claim filters don't carve out fork PRs), an "
        "attacker who lands a workflow change has both "
        "the token-mint surface (from the ungated workflow) and "
        "the action authority (from the wildcard policy). The OIDC "
        "pattern was supposed to replace long-lived keys with "
        "tightly-scoped, short-lived ones. This combination "
        "preserves the short-lived part without the tight-scope "
        "part."
    )
    return [Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=min_confidence(triggers),
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["GHA-030", "IAM-002"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
