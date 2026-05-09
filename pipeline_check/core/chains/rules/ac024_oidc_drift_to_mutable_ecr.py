"""AC-024. GHA OIDC drift meets ECR mutable tag.

The third composition rooted in GHA-030 ("OIDC token requested
without environment-protected job"), and the second one rooted in
ECR-002 ("Image tags are mutable"). Each existing chain captures a
different end-to-end story:

- AC-016 = GHA-030 + IAM-002 (wildcard authority). Drift on the
  trust side meets too-broad authority on the AWS side. Failure
  mode: any compromised principal that satisfies the loose trust
  policy gets the keys to the kingdom.

- AC-017 = GHA-011 + ECR-002 (cache poisoning). Compromise on the
  build side meets a writable surface on the registry side.
  Failure mode: a poisoned cache entry produces an artifact that
  silently overwrites a tag.

- AC-024 = GHA-030 + ECR-002. Drift on the trust side meets a
  writable surface on the registry side. Failure mode: any branch
  or fork PR that triggers the workflow gets short-lived AWS
  credentials with no required-reviewer gate, and pushes a
  substituted image under an existing tag that downstream
  consumers pull by name. Different attack vector from AC-017
  (no cache primitive needed; the workflow itself is the
  injection point), and different blast radius from AC-016 (the
  authority isn't wildcard, it's narrowly scoped to ECR, but
  the mutable-tag policy lets that narrow authority become a
  supply-chain primitive).

The chain fires when a scan turns up both legs in the same
session: GHA-030 on a workflow that requests an OIDC token
without an ``environment:`` gate, and ECR-002 on any ECR
repository in the AWS account. The combination doesn't require
proof that the *specific* workflow pushes to the *specific*
repository, repository-to-workflow attribution lives across two
different planes (CI config + AWS state), and an attacker only
needs *some* CI workflow with the trust drift and *some* mutable
ECR repo whose image is consumed in production.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-024",
    title="OIDC trust drift lands on a mutable ECR tag",
    severity=Severity.CRITICAL,
    summary=(
        "A GitHub Actions workflow requests an OIDC token without "
        "an environment-protected job (GHA-030) AND an ECR "
        "repository has mutable image tags (ECR-002). Any branch "
        "or fork PR that triggers the workflow obtains short-lived "
        "AWS credentials with no required-reviewer gate; if those "
        "credentials reach an ECR push role, the mutable-tag policy "
        "lets the workflow overwrite an existing tag (``:latest``, "
        "``:v1.2.3``) and the substituted image propagates to "
        "every downstream consumer that pulls by name."
    ),
    mitre_attack=(
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1195.002",  # Supply Chain Compromise: Software Supply Chain
        "T1525",      # Implant Internal Image
    ),
    kill_chain_phase="initial-access -> credential-access -> impact",
    references=(
        "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",
        "https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#deployment-protection-rules",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
    ),
    recommendation=(
        "Either fix breaks the chain. On the GitHub side: bind any "
        "job that requests ``id-token: write`` to a GitHub "
        "Environment with required-reviewer protection, and pin "
        "the IAM trust policy's ``token.actions.githubusercontent."
        "com:sub`` claim to a specific repo + ref pattern (``repo:"
        "owner/repo:ref:refs/heads/main``) so a fork PR can't "
        "redeem the role. On the AWS side: set "
        "``imageTagMutability=IMMUTABLE`` on every ECR repository "
        "consumed in production, and reference images by digest "
        "(``@sha256:...``) in deployment manifests so tag "
        "substitution can't propagate even if a push slips "
        "through. Best is both: gated OIDC + immutable tags + "
        "digest-pinned consumers."
    ),
    providers=("github", "aws"),
    triggering_check_ids=("GHA-030", "ECR-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "GHA-030"):
        return []
    if not has_failing(findings, "ECR-002"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"GHA-030", "ECR-002"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this scan:\n"
        "  1. A GitHub Actions workflow requests an OIDC token "
        "(``permissions: id-token: write``) without an "
        "``environment:`` binding on the requesting job (GHA-030). "
        "GitHub's environment-protection rules (required "
        "reviewers, deployment-branch restrictions, wait timers) "
        "only apply to jobs that opt in. Any branch the workflow "
        "runs on (and any fork PR if the workflow is fork-runnable) "
        "redeems the OIDC token with no human in the loop. The "
        "AWS side typically pairs this with a trust policy that "
        "doesn't pin the ``sub:`` claim to a specific repo / ref, "
        "so the redemption succeeds for any GitHub-hosted runner "
        "presenting a token issued for the repository.\n"
        "  2. At least one ECR repository in this account has "
        "mutable image tags (ECR-002). Without "
        "``imageTagMutability=IMMUTABLE``, the same tag (``:latest"
        "``, ``:stable``, ``:v1.2.3``) can be re-pushed with "
        "different image content silently, no digest reference "
        "for clients to compare against.\n"
        "  3. If the OIDC-redeemed role can write to the ECR repo "
        "(typical CI roles carry ``ecr:PutImage`` /"
        " ``ecr:BatchCheckLayerAvailability``), an attacker who "
        "can trigger the workflow (by opening a PR, pushing a "
        "branch, or crafting a malicious commit) pushes a "
        "substituted image under an existing tag. Every "
        "downstream consumer that pulls the tag by name (k8s "
        "``Deployment`` with ``imagePullPolicy: Always``, ECS "
        "task definition, Lambda image, EKS node bootstrap) "
        "receives the substituted image on the next pull, and "
        "tag-only references can't detect the swap. Gate the "
        "OIDC job with an ``environment:`` (and pin the trust "
        "policy ``sub:`` claim) or set the ECR repo to "
        "IMMUTABLE. Either fix breaks the chain."
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
        triggering_check_ids=["GHA-030", "ECR-002"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
