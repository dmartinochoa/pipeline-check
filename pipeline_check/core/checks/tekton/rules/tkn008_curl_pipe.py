"""TKN-008, ``curl ... | sh`` and TLS bypass in step scripts."""
from __future__ import annotations

from ..._primitives import remote_script_exec, tls_bypass
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, doc_location, iter_step_scripts

RULE = Rule(
    id="TKN-008",
    title="Tekton step script pipes remote install or disables TLS",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-D-COMMS-INTEGRITY"),
    cwe=("CWE-494", "CWE-829", "CWE-295"),
    recommendation=(
        "Replace ``curl ... | sh`` with a download-then-verify-then-"
        "execute pattern. Drop TLS-bypass flags (``curl -k``, ``git "
        "config http.sslverify false``); install the missing CA into "
        "the step image instead. Both forms let an attacker "
        "controlling DNS / a transparent proxy substitute the script "
        "the step runs."
    ),
    docs_note=(
        "Uses the cross-provider ``_primitives.remote_script_exec`` "
        "and ``_primitives.tls_bypass`` detectors so detection is "
        "consistent with the GHA / GitLab / CircleCI / Cloud Build "
        "providers (covering helm / kubectl / ssh / docker / maven / "
        "gradle / aws bypasses in addition to the curl / wget / git / "
        "npm / pip baseline)."
    ),
    known_fp=(
        "Tasks running entirely against an internal mirror "
        "(``curl https://internal-mirror/install.sh | sh`` where "
        "the mirror is the same supply chain as the task image "
        "itself) carry less marginal risk than a public-internet "
        "fetch, but the rule still fires because the curl-pipe "
        "primitive is the structural signal. ``curl -k`` to a "
        "TLS endpoint with a known self-signed CA likewise "
        "triggers; the canonical fix is to install the CA into "
        "the step image and drop ``-k``, but per-task "
        "suppression via ``--ignore-file`` is the escape hatch.",
    ),
    exploit_example=(
        "# Vulnerable: ``curl | bash`` trusts the network path AND\n"
        "# the installer host. A MITM (compromised proxy, malicious\n"
        "# DNS) or a publisher compromise ships malicious code into\n"
        "# the step's shell with the step's full credential set\n"
        "# in scope (TaskRun ServiceAccount, mounted Secrets).\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  steps:\n"
        "    - name: install-cli\n"
        "      image: alpine@sha256:abc123...\n"
        "      script: |\n"
        "        curl -fsSL https://installer.example.com/cli.sh | bash\n"
        "\n"
        "# Safe: download, verify against a known-good sha256, then\n"
        "# execute. If the upstream content changes, the digest\n"
        "# stops matching and the step fails loud.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  steps:\n"
        "    - name: install-cli\n"
        "      image: alpine@sha256:abc123...\n"
        "      script: |\n"
        "        set -e\n"
        "        curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh\n"
        "        echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -\n"
        "        bash /tmp/cli.sh"
    ),
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            if remote_script_exec.scan(script):
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: curl-pipe-shell"
                )
                locations.append(doc_location(doc))
                continue
            if tls_bypass.scan(script):
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: TLS bypass"
                )
                locations.append(doc_location(doc))
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No curl-pipe-shell or TLS bypass in step scripts."
        if passed else
        f"{len(offenders)} unsafe install / TLS pattern(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
