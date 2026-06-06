"""ARGO-013, automountServiceAccountToken not explicitly false."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ArgoContext, doc_location, iter_templates, template_name, workflow_spec

RULE = Rule(
    id="ARGO-013",
    title="Argo workflow does not opt out of SA token automount",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2", "CICD-SEC-7"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Set ``spec.automountServiceAccountToken: false`` on the "
        "Workflow / WorkflowTemplate, or per-template "
        "(``templates[].automountServiceAccountToken: false``) on any "
        "template that doesn't need to talk to the Kubernetes API. "
        "An explicit ``false`` keeps a compromised step from using "
        "the workflow's SA token to escalate inside the cluster, "
        "even when the SA itself is hardened (ARGO-003), a token "
        "automounted into every pod widens the leak surface."
    ),
    docs_note=(
        "Companion to ARGO-003 (default ServiceAccount). The default "
        "SA only matters when its token is mounted; an explicit "
        "``automountServiceAccountToken: false`` removes the token "
        "from the pod regardless of which SA the pod is bound to. "
        "Detection: workflow passes when the spec sets it to "
        "``false`` AND every template either inherits that or sets "
        "its own ``automountServiceAccountToken: false``. A template "
        "with it explicitly ``true`` (or unset against an unset "
        "spec-level value) is the failing shape."
    ),
    known_fp=(
        "Templates that genuinely need to call the Kubernetes API "
        "(GitOps pull, ``kubectl apply`` from inside the workflow). "
        "Set ``automountServiceAccountToken: true`` on that template "
        "specifically and bind it to a least-privilege SA, the "
        "rule then fires only on the broad spec-level absence, "
        "which is the actual gap.",
    ),
    exploit_example=(
        "# Vulnerable: a Workflow that never opts out of SA-token\n"
        "# automount, so every step's pod gets the token mounted.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: { name: ci }\n"
        "spec:\n"
        "  entrypoint: build\n"
        "  serviceAccountName: ci-workflow-sa\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: ci-tools@sha256:abc123...\n"
        "        command: [./build.sh]\n"
        "\n"
        "# Attack: automountServiceAccountToken defaults to true, so\n"
        "# the SA token is mounted at\n"
        "# /var/run/secrets/kubernetes.io/serviceaccount/ in the build\n"
        "# pod even though build.sh never calls the Kubernetes API. An\n"
        "# attacker who lands a shell in the step (a poisoned\n"
        "# dependency, an injected command) reads the token and acts as\n"
        "# ci-workflow-sa against the API, widening a build-step RCE\n"
        "# into cluster access.\n"
        "\n"
        "# Safe: drop the token from pods that don't call the API.\n"
        "spec:\n"
        "  entrypoint: build\n"
        "  serviceAccountName: ci-workflow-sa\n"
        "  automountServiceAccountToken: false\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: ci-tools@sha256:abc123...\n"
        "        command: [./build.sh]"
    ),
)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        spec = workflow_spec(doc)
        spec_value = spec.get("automountServiceAccountToken")
        for idx, tmpl in enumerate(iter_templates(doc)):
            tmpl_value = tmpl.get("automountServiceAccountToken")
            # If the template explicitly opts out, it's safe.
            if tmpl_value is False:
                continue
            # If the template explicitly opts in, that's the legitimate
            # K8s-API-using case, surface as info, but don't fail on
            # it. The user took an explicit decision.
            if tmpl_value is True:
                continue
            # Template is silent, inherits from the workflow spec.
            if spec_value is False:
                continue
            offenders.append(
                f"{doc.kind}/{doc.name} {template_name(tmpl, idx)}"
            )
            locations.append(doc_location(doc, tmpl))
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every template either opts out of SA-token automount or "
        "inherits an explicit ``automountServiceAccountToken: "
        "false`` from the workflow spec."
        if passed else
        f"{len(offenders)} template(s) silently inherit the "
        f"cluster-default automount behavior, leaving the SA token "
        f"mounted in every step's pod: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
