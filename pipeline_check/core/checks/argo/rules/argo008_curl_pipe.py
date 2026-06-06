"""ARGO-008, ``curl ... | sh`` and TLS bypass in script sources."""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec, tls_bypass
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ArgoContext, doc_location, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-008",
    title="Argo script source pipes remote install or disables TLS",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-D-COMMS-INTEGRITY"),
    cwe=("CWE-494", "CWE-829", "CWE-295"),
    recommendation=(
        "Replace ``curl ... | sh`` with a download-then-verify-then-"
        "execute pattern. Drop TLS-bypass flags (``curl -k``, ``git "
        "config http.sslverify false``); install the missing CA into "
        "the template image instead. Both forms let an attacker "
        "controlling DNS / a transparent proxy substitute the script "
        "the workflow runs."
    ),
    docs_note=(
        "Walks ``script.source`` and joined ``container.args`` text "
        "with the cross-provider ``_primitives.remote_script_exec`` "
        "and ``_primitives.tls_bypass`` detectors. Coverage stays "
        "aligned with GHA-016 / GHA-027 / BK-004 / BK-008 / TKN-008 "
        "/ GCB-010 / GCB-011 / DF-004."
    ),
    exploit_example=(
        "# Vulnerable: ``curl | bash`` trusts both the network path\n"
        "# (any MITM substitutes the script) and the host (an\n"
        "# attacker-compromised installer endpoint silently serves\n"
        "# attacker code). The script runs as the workflow's pod,\n"
        "# inheriting every secret mounted into the container.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "spec:\n"
        "  templates:\n"
        "    - name: install-cli\n"
        "      script:\n"
        "        image: alpine@sha256:abc123...\n"
        "        command: [sh]\n"
        "        source: |\n"
        "          curl -fsSL https://installer.example.com/cli.sh | bash\n"
        "\n"
        "# Safe: download to a file, verify a sha256 digest from a\n"
        "# trusted source, then execute. If the upstream content\n"
        "# changes the digest stops matching and the build fails\n"
        "# before the malicious code runs.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "spec:\n"
        "  templates:\n"
        "    - name: install-cli\n"
        "      script:\n"
        "        image: alpine@sha256:abc123...\n"
        "        command: [sh]\n"
        "        source: |\n"
        "          set -e\n"
        "          curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh\n"
        "          echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -\n"
        "          bash /tmp/cli.sh"
    ),
)


def _container_text(container: dict[str, Any]) -> str:
    parts: list[str] = []
    src = container.get("source")
    if isinstance(src, str):
        parts.append(src)
    for key in ("command", "args"):
        v = container.get(key)
        if isinstance(v, list):
            parts.extend(s for s in v if isinstance(s, str))
        elif isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                blob = _container_text(container)
                if not blob:
                    continue
                if remote_script_exec.scan(blob):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: curl-pipe-shell"
                    )
                    locations.append(doc_location(doc, container))
                    continue
                if tls_bypass.scan(blob):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: TLS bypass"
                    )
                    locations.append(doc_location(doc, container))
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No curl-pipe-shell or TLS bypass in template scripts."
        if passed else
        f"{len(offenders)} unsafe install / TLS pattern(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
