"""ARGOCD-013. Application has no revisionHistoryLimit cap.

Without a cap, ``spec.revisionHistoryLimit`` defaults to 10 in some
Argo CD versions but can also default to unbounded depending on the
controller's deploy parameters. Unbounded history keeps every prior
manifest revision (including ones with stale secrets / disclosed
credentials) accessible via ``argocd app history`` and the API, and
bloats the controller's storage footprint. Rule fires on the
unset case so the operator picks an explicit cap rather than
relying on whatever the cluster's controller defaults to.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applications

RULE = Rule(
    id="ARGOCD-013",
    title="Argo CD Application sets no explicit revisionHistoryLimit",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-C-AUDIT",),
    cwe=("CWE-770",),
    recommendation=(
        "Set ``spec.revisionHistoryLimit`` to an explicit small "
        "integer (5-20 is the typical range) on every Application. "
        "The field caps how many prior synced revisions Argo CD "
        "retains for rollback. Unbounded retention keeps stale "
        "manifests (and any secrets they referenced) accessible "
        "via the Argo CD API indefinitely and grows the "
        "controller's storage footprint without bound.\n\n"
        "Example:\n\n"
        "    spec:\n"
        "      revisionHistoryLimit: 10  # keep last 10 syncs for rollback\n\n"
        "Pick the cap based on the application's rollback need: a "
        "stateless web service rarely benefits from more than 5 "
        "history entries; an infrastructure controller managing "
        "external state may want 20 for forensic comparison "
        "across longer windows."
    ),
    docs_note=(
        "Reads ``spec.revisionHistoryLimit`` and fires when the "
        "field is missing or set to ``null``. Explicit 0 also "
        "fires (history disabled entirely is rarely the "
        "intended posture — operators usually want at least a "
        "1-2 entry rollback window). The rule is informational-"
        "leaning LOW: storage bloat and prolonged-secret-"
        "exposure are real but slow-moving risks, not "
        "exploitable surfaces an attacker can compromise in "
        "isolation."
    ),
    known_fp=(
        "Sandbox / experimental Applications where rollback is "
        "irrelevant trip this rule by design. Suppress per "
        "Application with a one-line rationale.",
    ),
    incident_refs=(
        "Stale-secret pattern in older Argo CD versions: an "
        "Application that referenced a secret directly in a "
        "manifest (later moved to a sealed-secret / external "
        "secret reference) retains the original plaintext "
        "manifest in revision history. ``argocd app history`` "
        "and the controller API surface the old manifest "
        "verbatim, including the plaintext value, until the "
        "revision history limit is reached.",
    ),
    exploit_example=(
        "# Vulnerable: no history cap.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "metadata: { name: payments, namespace: argocd }\n"
        "spec:\n"
        "  project: workloads\n"
        "  source:\n"
        "    repoURL: https://github.com/example/manifests\n"
        "    targetRevision: 7b83187...\n"
        "    path: overlays/prod\n"
        "  destination: { server: https://kubernetes.default.svc, namespace: prod }\n"
        "  syncPolicy: { automated: { prune: true, selfHeal: true } }\n"
        "  # No revisionHistoryLimit: unbounded.\n"
        "\n"
        "# Safe: explicit cap.\n"
        "spec:\n"
        "  revisionHistoryLimit: 10"
    ),
)


def check(ctx: ArgoCDContext) -> Finding:
    apps = list(iter_applications(ctx))
    if not apps:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no Applications)",
            description=(
                "No Argo CD Application documents in scope; "
                "nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for app in apps:
        spec = app.data.get("spec")
        if not isinstance(spec, dict):
            continue
        limit = spec.get("revisionHistoryLimit")
        if limit is None or not isinstance(limit, int):
            offenders.append(
                f"{app.display}: revisionHistoryLimit missing or null"
            )
    passed = not offenders
    desc = (
        "Every Application sets an explicit revisionHistoryLimit."
        if passed else
        f"{len(offenders)} Application(s) lack revisionHistoryLimit: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Argo CD retains "
        f"all prior revisions; stale secrets and bloated controller "
        f"storage accumulate without bound."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=apps[0].display,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
