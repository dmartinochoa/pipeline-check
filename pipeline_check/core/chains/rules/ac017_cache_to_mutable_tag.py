"""AC-017. Build cache poisoning that lands on a mutable tag.

GitHub Actions' ``actions/cache`` keys the cache by a string the
workflow author chooses. When that string is derived from
attacker-controllable input, the PR head SHA, the issue body, the
ref name on a workflow_run trigger, a fork PR can populate the
cache with arbitrary content and the next default-branch build
restores it. The poisoned cache typically holds compiled artifacts,
``node_modules``, a pip wheelhouse, or a Docker layer cache, all of
which feed straight into the build output.

When that build output is then pushed to ECR under a mutable tag
(:latest, :stable, :v1.0, anything where IMMUTABLE isn't set on
the repository), the poisoned image silently replaces the previous
content of the tag. Every consumer downstream that pulls
``myapp:latest`` (k8s deployments, Lambda images, EC2 cloud-init,
ECS task defs) gets the substituted image on the next pull, and
mutable tags don't carry a digest reference for clients to compare
against.

The chain fires when a scan turns up both legs in the same
session: GHA-011 on the workflow that produces the artifact, and
ECR-002 on the registry the workflow pushes to.

ResourceAnchor phase 1: prefers a confirmed pairing when the
GHA-011 workflow text references the same canonical ECR URI
that ECR-002 flagged as mutable. GHA-011 scans every string in
the workflow doc for ``<acct>.dkr.ecr.<region>.amazonaws.com/<repo>``
shapes and emits one ``ecr_repo`` anchor per match (covers
``docker push``, ``docker/build-push-action`` ``tags:`` inputs,
and ``aws ecr`` invocations alike); ECR-002 emits the canonical
URI from the boto3 ``describe_repositories`` payload. Each
matched repo composes ONE confirmed chain with
``confirmed_reachable=True``, ``Confidence.HIGH``, and the repo
URI as the chain resource. Falls back to scan-level co-occurrence
when no anchor matches (templated tags, indirect pushes through
intermediate registries, or the workflow references a different
repo than the one ECR-002 flagged) so the legacy "cache poisoning
+ mutable tag somewhere" signal survives.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

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
        "inputs (lockfile hash, source-tree hash), never from "
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


def _base_narrative() -> str:
    return (
        "  1. A GitHub Actions workflow keys its ``actions/cache`` "
        "entry on attacker-controllable input (GHA-011), the "
        "PR head SHA, ``github.head_ref``, an issue or comment "
        "body, or the ref name on a ``workflow_run`` trigger. "
        "Whoever opens a PR (or a fork PR, if the workflow is "
        "fork-runnable) can populate the cache with arbitrary "
        "content; the next default-branch build restores it.\n"
        "  2. An ECR repository in this account has mutable image "
        "tags (ECR-002). Without ``imageTagMutability=IMMUTABLE``, "
        "the same tag (``:latest``, ``:stable``, ``:v1.0``) can be "
        "re-pushed with different image content silently.\n"
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing when the GHA-011
    # workflow text mentions the same ECR repo URI that ECR-002
    # flagged. GHA-011 scans every string in the workflow for ECR
    # URI shapes; ECR-002 emits its canonical URI from
    # describe_repositories. Same identity ⇒ the cache-poisonable
    # build pushes to the mutable repo from one workflow.
    by_repo = group_by_anchor(findings, ["GHA-011", "ECR-002"], "ecr_repo")
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for repo_uri, ck_map in by_repo.items():
        gha011 = ck_map["GHA-011"]
        ecr002 = ck_map["ECR-002"]
        triggers = [gha011, ecr002]
        matched_findings.add(id(gha011))
        matched_findings.add(id(ecr002))
        narrative = (
            f"For ECR repo `{repo_uri}`:\n"
            + _base_narrative()
            + f"  3. Reachability confirmed: the cache-poisonable "
            f"workflow (`{gha011.resource}`) references "
            f"`{repo_uri}` in its push pipeline, and `{repo_uri}` "
            f"is the same repo ECR-002 flagged for mutable tags. "
            f"A fork PR's poisoned cache restored into a "
            f"default-branch build pushes substituted image content "
            f"into a tag that downstream consumers pull by name, "
            f"with no digest to detect the swap."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=Confidence.HIGH,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-011", "ECR-002"],
            triggering_findings=triggers,
            resources=[repo_uri],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=True,
            via_structural=True,
            reachability_note=(
                f"GHA-011 workflow references ECR-002 repo `{repo_uri}`"
            ),
        ))

    # Co-occurrence fallback: both legs fire but no shared ECR repo
    # URI matched (templated tag, indirect push through an
    # intermediate registry, GHA-011 fired on a workflow that doesn't
    # touch ECR at all, or the workflow pushes to a different
    # account's repo). Preserves the legacy "cache poisoning +
    # mutable tag somewhere" prompt.
    if has_failing(findings, "GHA-011") and has_failing(findings, "ECR-002"):
        unmatched = [
            f for f in findings
            if (not f.passed)
            and f.check_id in {"GHA-011", "ECR-002"}
            and id(f) not in matched_findings
        ]
        unmatched_legs = {f.check_id for f in unmatched}
        if "GHA-011" in unmatched_legs and "ECR-002" in unmatched_legs:
            triggers = unmatched
            resources = sorted({f.resource for f in triggers})
            narrative = (
                "In this scan:\n"
                + _base_narrative()
                + "  3. Reachability unconfirmed: no GHA-011 "
                "workflow text references the specific ECR repo URI "
                "ECR-002 flagged (templated tag, indirect push, or "
                "the cache-poisonable workflow doesn't touch ECR at "
                "all). Treat as a co-occurrence signal — the "
                "mutable-tag repo is still a substitution surface "
                "for any privileged push, and the cache-poisoning "
                "leg remains an independent supply-chain risk."
            )
            out.append(Chain(
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
                confirmed_reachable=False,
                reachability_note="",
            ))
    return out
