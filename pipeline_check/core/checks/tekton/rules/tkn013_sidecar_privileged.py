"""TKN-013. Tekton sidecars must not run privileged or as UID 0."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, TektonDoc, doc_location

RULE = Rule(
    id="TKN-013",
    title="Tekton sidecar runs privileged or as root",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Set ``securityContext.privileged: false``, "
        "``runAsNonRoot: true``, and ``allowPrivilegeEscalation: "
        "false`` on every sidecar in ``spec.sidecars``. A privileged "
        "sidecar is the same escape vector as a privileged step, "
        "it shares the pod's network and kernel namespaces, and a "
        "compromised sidecar image owns the entire TaskRun's "
        "execution surface."
    ),
    docs_note=(
        "TKN-002 hardens the ``spec.steps`` list. Tekton's "
        "``spec.sidecars`` list runs alongside the steps in the "
        "same pod, but a sidecar's container image and command "
        "come from a separate place in the manifest, so a Task "
        "with hardened steps and a privileged sidecar (a common "
        "pattern when wrapping ``docker:dind``) leaves the same "
        "kernel-namespace gap TKN-002 was meant to close. The "
        "detection mirrors TKN-002: fires on a sidecar with "
        "``securityContext.privileged: true``, ``runAsUser: 0``, "
        "``runAsNonRoot: false``, ``allowPrivilegeEscalation: "
        "true``, or no ``securityContext`` block at all."
    ),
    known_fp=(
        "Tasks that genuinely need ``docker:dind`` as a sidecar, "
        "e.g. building images inside the cluster without giving the "
        "step itself host-Docker access. The replacement pattern is "
        "Kaniko or BuildKit running as the step itself, with no "
        "privileged sidecar; if neither is viable, ignore TKN-013 "
        "in ``.pipeline-check-ignore.yml`` for the affected Task.",
    ),
    exploit_example=(
        "# Vulnerable: a sidecar runs alongside every step in the\n"
        "# Task and shares the pod's volumes / network. A\n"
        "# privileged sidecar can escape to the node the same way\n"
        "# a privileged step does, with the added attack surface\n"
        "# of being long-lived for the Task's whole duration.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  sidecars:\n"
        "    - name: docker-daemon\n"
        "      image: docker:24-dind\n"
        "      securityContext:\n"
        "        privileged: true\n"
        "  steps:\n"
        "    - name: build\n"
        "      image: docker:24\n"
        "      script: docker build -t app .\n"
        "\n"
        "# Safe: drop the privileged sidecar and use a rootless\n"
        "# builder in the step. Kaniko / BuildKit rootless\n"
        "# eliminates the need for the dind sidecar entirely.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  steps:\n"
        "    - name: build\n"
        "      image: gcr.io/kaniko-project/executor@sha256:abc123...\n"
        "      args: [--context=., --destination=registry/app:tag]"
    ),
)


def task_sidecars(doc: TektonDoc) -> list[dict[str, Any]]:
    """Return the ``spec.sidecars`` list of a Task / ClusterTask, or [].

    Sidecars share the pod with steps and need the same securityContext
    hardening, a privileged sidecar cancels the protection of every
    hardened step in the same Task.
    """
    if doc.kind not in ("Task", "ClusterTask"):
        return []
    spec = doc.data.get("spec") or {}
    if not isinstance(spec, dict):
        return []
    sidecars = spec.get("sidecars") or []
    if not isinstance(sidecars, list):
        return []
    return [s for s in sidecars if isinstance(s, dict)]


def _sidecar_offends(sc: Any) -> list[str]:
    if not isinstance(sc, dict):
        return ["no securityContext"]
    issues: list[str] = []
    if sc.get("privileged") is True:
        issues.append("privileged: true")
    if sc.get("allowPrivilegeEscalation") is True:
        issues.append("allowPrivilegeEscalation: true")
    if sc.get("runAsUser") == 0:
        issues.append("runAsUser: 0")
    if sc.get("runAsNonRoot") is False:
        issues.append("runAsNonRoot: false")
    if sc.get("runAsNonRoot") is None and not issues:
        issues.append("runAsNonRoot not set")
    return issues


def _sidecar_name(sidecar: dict[str, Any], idx: int) -> str:
    n = sidecar.get("name")
    if isinstance(n, str) and n.strip():
        return n.strip()
    return f"sidecars[{idx}]"


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        sidecars = task_sidecars(doc)
        if not sidecars:
            continue
        examined += 1
        for idx, sc in enumerate(sidecars):
            issues = _sidecar_offends(sc.get("securityContext"))
            if issues:
                offenders.append(
                    f"{doc.kind}/{doc.name} {_sidecar_name(sc, idx)}: "
                    f"{', '.join(issues)}"
                )
                locations.append(doc_location(doc, sc))
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask declares sidecars.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every sidecar has a hardened securityContext."
        if passed else
        f"{len(offenders)} sidecar(s) run privileged / as root: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
