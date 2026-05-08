"""AC-017 — Build cache poisoning that lands on a mutable tag.

GitHub Actions' ``actions/cache`` keys the cache by a string the
workflow author chooses. When that string is derived from
attacker-controllable input — the PR head SHA, the issue body, the
ref name on a workflow_run trigger — a fork PR can populate the
cache with arbitrary content and the next default-branch build
restores it. The poisoned cache typically holds compiled artifacts,
``node_modules``, a pip wheelhouse, or a Docker layer cache, all of
which feed straight into the build output.

When that build output is then pushed to ECR under a mutable tag
(:latest, :stable, :v1.0 — anything where IMMUTABLE isn't set on
the repository), the poisoned image silently replaces the previous
content of the tag. Every consumer downstream that pulls
``myapp:latest`` (k8s deployments, Lambda images, EC2 cloud-init,
ECS task defs) gets the substituted image on the next pull, and
mutable tags don't carry a digest reference for clients to compare
against.

The chain fires when a scan turns up both legs in the same
session: GHA-011 on the workflow that produces the artifact, and
ECR-002 on the registry the workflow pushes to.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-017",
    title="Build cache poisoning that lands on a mutable ECR tag",
    severity=Severity.HIGH,
    summary=(
        "A GitHub Actions workflow's cache key derives from "
        "attacker-controllable input (GHA-011) AND the ECR "
        "repository it pushes to has mutable image tags "
        "(ECR-002). A fork-PR-driven cache poisoning lands "
        "compiled artifacts on the cache; the next default-branch "
        "build restores them and pushes the resulting image under "
        "a tag that consumers pull by name, replacing the "
        "previous content for every downstream deployment."
    ),
    mitre_attack=(
        "T1195.001",  # Supply Chain Compromise: Compromise Software Dependencies
        "T1546",      # Event Triggered Execution
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase="initial-access -> persistence -> impact",
    references=(
        "https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/",
        "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",
        "https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows",
    ),
    recommendation=(
        "Close either leg to break the chain. On the GitHub side: "
        "the cache key must be deterministic from the build's own "
        "inputs (lockfile hash, source-tree hash) — never from "
        "PR-controlled context (``github.head_ref``, "
        "``github.event.*.title``, etc.). On the AWS side: set "
        "``imageTagMutability=IMMUTABLE`` on the ECR repository "
        "and reference images by digest in deployment manifests. "
        "Best is both: deterministic cache keys + immutable tags + "
        "digest-pinned consumers."
    ),
    providers=("github", "aws"),
    triggering_check_ids=("GHA-011", "ECR-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "GHA-011"):
        return []
    if not has_failing(findings, "ECR-002"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"GHA-011", "ECR-002"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this scan:\n"
        "  1. A GitHub Actions workflow keys its ``actions/cache`` "
        "entry on attacker-controllable input (GHA-011) — the "
        "PR head SHA, ``github.head_ref``, an issue or comment "
        "body, or the ref name on a ``workflow_run`` trigger. "
        "Whoever opens a PR (or a fork PR, if the workflow is "
        "fork-runnable) can populate the cache with arbitrary "
        "content; the next default-branch build restores it.\n"
        "  2. An ECR repository in this account has mutable image "
        "tags (ECR-002). Without ``imageTagMutability=IMMUTABLE``, "
        "the same tag (``:latest``, ``:stable``, ``:v1.0``) can be "
        "re-pushed with different image content silently.\n"
        "  3. If the cache-poisoned build's output is what gets "
        "pushed to that ECR repo under a mutable tag, the "
        "substituted content propagates to every consumer that "
        "pulls the tag — k8s ``Deployment``, Lambda image, ECS "
        "task definition, ``docker pull`` from a developer's "
        "laptop. None of those consumers can detect the "
        "substitution from the tag alone, since mutable tags "
        "don't carry a digest reference."
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
        triggering_check_ids=["GHA-011", "ECR-002"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
