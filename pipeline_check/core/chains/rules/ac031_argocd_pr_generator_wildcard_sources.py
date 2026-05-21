"""AC-031. Argo CD untrusted PR generator meets wildcard source repos.

The two halves of a fork-PR-to-deploy primitive on Argo CD:

  * ``ARGOCD-006`` — at least one ApplicationSet uses a
    ``pullRequest`` or ``scmProvider`` generator AND the template's
    ``spec.project`` is the literal ``default`` (or a generator-
    interpolated placeholder), with no ``filters:`` /
    ``labels`` / ``branchMatch`` narrowing the generator's input set.
    Any PR in the matched org materializes a fresh ``Application``.
  * ``ARGOCD-001`` — at least one AppProject has
    ``sourceRepos: ['*']``. Applications under that project can
    render manifests from any repository URL.

Independently each leg is a governance smell. Together they are
the fork-PR-to-deploy primitive: an attacker opens a PR in any
repo the generator watches, the ApplicationSet materializes an
``Application`` under a project whose source-repo allowlist is
unbounded, and the Argo CD controller renders the attacker's
manifests into the cluster on the next sync. The classic shape
is an ApplicationSet whose template falls through to the
``default`` project (which ships with ``sourceRepos: ['*']`` out
of the box).

This chain doesn't migrate to the ``job_anchors`` intersection
model. ARGOCD-006 fires on ApplicationSet manifests and
ARGOCD-001 fires on AppProject manifests, but both rules emit
``resource="argocd"`` because the threat is at the instance
level, the AppProject that gets resolved at render time may be
the one ARGOCD-001 flagged, the chain doesn't claim a 1:1
project binding without that anchor. Per-instance co-occurrence
is the reachability claim; tightening to a per-project anchor is
a future refinement (track the ApplicationSet template's
project ↔ AppProject name pair).
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-031",
    title="Argo CD untrusted PR generator meets wildcard source repos",
    severity=Severity.CRITICAL,
    summary=(
        "An ApplicationSet uses a ``pullRequest`` / ``scmProvider`` "
        "generator without a project allowlist (ARGOCD-006) AND at "
        "least one AppProject has ``sourceRepos: ['*']`` "
        "(ARGOCD-001). Any PR in the matched organization "
        "materializes a fresh ``Application`` that inherits the "
        "wildcard source-repo allowlist; the attacker's manifests "
        "render into the cluster on the next sync. The default "
        "out-of-the-box AppProject ships with "
        "``sourceRepos: ['*']``, so the chain fires on most "
        "unconfigured Argo CD installs where a PR generator is "
        "introduced without a tightened project."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1199",      # Trusted Relationship
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase=(
        "initial-access (fork / contributor PR) -> execution "
        "(manifest render) -> impact"
    ),
    references=(
        "https://argo-cd.readthedocs.io/en/stable/operator-manual/"
        "applicationset/Generators-Pull-Request/",
        "https://argo-cd.readthedocs.io/en/stable/user-guide/projects/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
    ),
    recommendation=(
        "Break either leg, both is best:\n"
        "  1. Tighten the AppProject's ``sourceRepos`` (ARGOCD-001). "
        "Replace ``['*']`` with the explicit list of repository "
        "URLs the project is allowed to render. Set "
        "``spec.sourceRepos: ['https://github.com/org/payments-*']`` "
        "and keep ``sourceNamespaces`` / ``destinations`` similarly "
        "scoped.\n"
        "  2. Scope the ApplicationSet generator (ARGOCD-006). Pin "
        "``template.spec.project`` to a single static project name "
        "(not ``default``, not a ``{{...}}`` placeholder) and "
        "constrain the generator with ``filters:`` / "
        "``labels: ['preview']`` / ``branchMatch:`` so PRs from "
        "untrusted authors do not synthesize Applications.\n"
        "If PR-driven preview environments are a deliberate "
        "design, the AppProject the PR-driven Applications resolve "
        "to MUST carry an explicit ``sourceRepos`` allowlist and a "
        "narrow destination, the chain's premise is unbounded "
        "authority, not the PR-preview pattern itself."
    ),
    providers=("argocd",),
    triggering_check_ids=("ARGOCD-006", "ARGOCD-001"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when both legs fail against the same Argo CD instance.

    Both ``ARGOCD-006`` and ``ARGOCD-001`` emit ``resource="argocd"``,
    so ``group_by_resource`` yields one ``{ck_map}`` per Argo CD
    instance that satisfies both legs. A multi-instance scan
    produces one chain per instance.
    """
    grouped = group_by_resource(findings, ["ARGOCD-006", "ARGOCD-001"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        appset = ck_map["ARGOCD-006"]
        project = ck_map["ARGOCD-001"]
        triggers = [appset, project]
        narrative = (
            f"On Argo CD instance `{resource}`:\n"
            f"  1. An ApplicationSet uses a ``pullRequest`` / "
            f"``scmProvider`` generator without a static project "
            f"allowlist or filter (ARGOCD-006). Any PR in the "
            f"matched organization is enough to materialize a "
            f"fresh ``Application``, the template either pins "
            f"``project: default`` or carries a generator-"
            f"interpolated placeholder that resolves at render "
            f"time.\n"
            f"  2. At least one AppProject carries "
            f"``sourceRepos: ['*']`` (ARGOCD-001). Applications "
            f"under that project can render manifests from any "
            f"repository URL, the Argo CD controller will fetch "
            f"and apply whatever the placeholder resolves to.\n"
            f"  3. Composite: a contributor opens a PR (or, with "
            f"a public org filter, a fork PR), the ApplicationSet "
            f"materializes an Application under the wildcard-"
            f"sourceRepos project, and the controller renders the "
            f"attacker-supplied manifests into the cluster on the "
            f"next sync. The default out-of-the-box AppProject "
            f"ships with ``sourceRepos: ['*']``, so this chain "
            f"fires on most Argo CD installs where a PR generator "
            f"is introduced without a tightened project. Break "
            f"either leg to close the chain."
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
            triggering_check_ids=["ARGOCD-006", "ARGOCD-001"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
