"""ARGOCD-012. AppProject defines no sync windows for production."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_appprojects

#: ``prod`` / ``production`` as a delimited token, so ``products`` /
#: ``product-catalog`` / ``reproducer`` (which merely embed the
#: substring) aren't treated as production. ``prod-eu`` / ``prod_us`` /
#: ``prod1`` / ``us-prod`` do match (not-a-letter boundaries).
_PROD_TOKEN_RE = re.compile(
    r"(?<![a-z])(?:production|prod)(?![a-z])", re.IGNORECASE
)

RULE = Rule(
    id="ARGOCD-012",
    title="Argo CD AppProject defines no sync windows",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-C-APPROVAL", "ESF-C-DEPLOY-MON"),
    cwe=("CWE-285",),
    recommendation=(
        "Define explicit ``spec.syncWindows`` entries on every "
        "AppProject that gates production deploys. A sync window is "
        "a calendar-style rule that allows or denies "
        "automated / manual sync during specific schedules. Without "
        "windows, every git commit can be reconciled to production "
        "instantly — fine for staging, dangerous for prod where "
        "off-hours change-freezes (weekend / on-call rotations / "
        "active-incident windows) are normal posture.\n\n"
        "Example: deny automated sync outside business hours but "
        "still allow manual sync (for break-glass deploys):\n\n"
        "    spec:\n"
        "      syncWindows:\n"
        "        - kind: deny\n"
        "          schedule: \"0 18 * * *\"\n"
        "          duration: 14h\n"
        "          applications: ['*']\n"
        "          manualSync: true   # operators can still sync manually\n\n"
        "Pair with ``manualSync: false`` on incident-window "
        "blackouts to fully freeze, and with a separate "
        "``kind: allow`` window for the release-rehearsal cadence."
    ),
    docs_note=(
        "Reads ``spec.syncWindows`` from each AppProject and fires "
        "when the field is missing or empty AND the project's "
        "``destinations`` include a production-shaped namespace "
        "(literal ``prod``, ``production``, or any namespace name "
        "containing ``prod``). The production-shape heuristic keeps "
        "the rule from firing on dev / staging projects where "
        "instant reconciliation is the deliberate posture.\n\n"
        "Sync windows complement ARGOCD-003 (automated sync without "
        "selfHeal) at the schedule layer: ARGOCD-003 catches the "
        "drift-revert hazard, this catches the change-freeze hazard."
    ),
    known_fp=(
        "Hosting / SaaS environments that intentionally deploy "
        "continuously across all hours (24/7 always-on update "
        "cadence) trip this rule. Suppress per project with a "
        "one-line rationale naming the continuous-deploy policy. "
        "Most production environments benefit from at least a "
        "weekend / overnight freeze.",
    ),
    incident_refs=(
        "Common change-control gap: a Friday-evening force-push "
        "to the manifests repo lands in production within minutes "
        "via Argo CD's automated sync. The on-call team is paged "
        "for the resulting outage hours later, by which point the "
        "responsible contributor is offline. Sync windows would "
        "have blocked the deploy until Monday's business hours, "
        "buying time for a manual review.",
    ),
    exploit_example=(
        "# Vulnerable: production project, no sync windows.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: AppProject\n"
        "metadata: { name: prod-workloads, namespace: argocd }\n"
        "spec:\n"
        "  sourceRepos: [https://github.com/example/manifests]\n"
        "  destinations:\n"
        "    - server: https://kubernetes.default.svc\n"
        "      namespace: prod\n"
        "  # No syncWindows: every commit reconciles instantly.\n"
        "\n"
        "# Risk: a Friday 23:30 push to the manifests repo lands\n"
        "# in production at 23:33; the on-call team is paged at\n"
        "# 00:15 for an unexpected error budget burn. The change\n"
        "# author is offline; rollback requires diagnosing what\n"
        "# changed without their context.\n"
        "\n"
        "# Safe: deny window for off-hours, allow manual.\n"
        "spec:\n"
        "  syncWindows:\n"
        "    - kind: deny\n"
        "      schedule: \"0 18 * * 1-5\"\n"
        "      duration: 14h\n"
        "      applications: ['*']\n"
        "      manualSync: true\n"
        "    - kind: deny\n"
        "      schedule: \"0 0 * * 6\"\n"
        "      duration: 48h\n"
        "      applications: ['*']\n"
        "      manualSync: true"
    ),
)


def _looks_like_production(spec: dict[str, Any]) -> bool:
    destinations = spec.get("destinations")
    if not isinstance(destinations, list):
        return False
    for dest in destinations:
        if not isinstance(dest, dict):
            continue
        ns = dest.get("namespace")
        if not isinstance(ns, str):
            continue
        if _PROD_TOKEN_RE.search(ns):
            return True
    return False


def check(ctx: ArgoCDContext) -> Finding:
    projects = list(iter_appprojects(ctx))
    if not projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no AppProjects)",
            description=(
                "No AppProject documents in scope; nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for proj in projects:
        spec = proj.data.get("spec")
        if not isinstance(spec, dict):
            continue
        if not _looks_like_production(spec):
            continue
        windows = spec.get("syncWindows")
        if isinstance(windows, list) and windows:
            continue
        offenders.append(
            f"{proj.display}: production-shaped destinations + no "
            f"syncWindows"
        )
    passed = not offenders
    desc = (
        "Every production-shaped AppProject defines syncWindows."
        if passed else
        f"{len(offenders)} production-shaped AppProject(s) lack "
        f"syncWindows: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Every commit "
        f"reconciles instantly, including off-hours / on-call / "
        f"incident windows."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=projects[0].display,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
