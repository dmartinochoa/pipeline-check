"""JF-035, ``httpRequest`` step disables SSL / certificate verification."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-035",
    title="httpRequest step disables SSL verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-295",),
    recommendation=(
        "Drop ``ignoreSslErrors: true`` from the ``httpRequest`` "
        "step. Fix certificate trust at the source: install the "
        "internal CA into the controller's truststore, or use a "
        "properly-issued certificate on the upstream service. "
        "Disabling verification on a CI runner lets any actor on the "
        "network path between Jenkins and the target inject responses, "
        "including payloads that flow into downstream stages."
    ),
    docs_note=(
        "The HTTP Request plugin's ``ignoreSslErrors: true`` flag "
        "tells the step to accept any TLS certificate (including "
        "self-signed, expired, hostname-mismatched, and "
        "attacker-presented) when calling the configured URL. "
        "Pipelines that hit internal services with broken trust "
        "chains frequently reach for it as a shortcut; the runtime "
        "consequence is that whatever the response body feeds into "
        "(``readJSON``, ``writeFile``, an arg to a subsequent "
        "deploy step) is now attacker-controllable for anyone who "
        "can MITM the controller-to-service connection. Complements "
        "JF-023 (which catches the broader catalog of curl/wget/git "
        "TLS bypasses) — JF-035 is specific to the ``httpRequest`` "
        "plugin step Jenkins pipelines commonly use for API calls."
    ),
    exploit_example=(
        "// Vulnerable: ``httpRequest`` with\n"
        "// ``ignoreSslErrors: true`` disables certificate\n"
        "// verification on the request. A MITM proxy or DNS\n"
        "// hijack between Jenkins and the API endpoint\n"
        "// substitutes the response, and the build trusts\n"
        "// whatever bytes arrive.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('fetch') {\n"
        "      steps {\n"
        "        httpRequest url: 'https://api.example.com/manifest.json',\n"
        "                    ignoreSslErrors: true\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: keep TLS verification on. For internal APIs on\n"
        "// a private CA, install the CA into the Jenkins JVM\n"
        "// trust store via the Java keystore (cacerts).\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('fetch') {\n"
        "      steps {\n"
        "        httpRequest url: 'https://api.example.com/manifest.json'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


_HTTP_REQUEST_RE = re.compile(
    r"\bhttpRequest\b.{0,400}?\bignoreSslErrors\s*:\s*true\b",
    re.IGNORECASE | re.DOTALL,
)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments or jf.text
    offenders: list[str] = []
    locations: list[Location] = []
    for m in _HTTP_REQUEST_RE.finditer(text):
        line_no = text[: m.start()].count("\n") + 1
        offenders.append(f"L{line_no}")
        locations.append(Location(
            path=jf.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No httpRequest step disables SSL verification."
        if passed else
        f"{len(offenders)} httpRequest step(s) set "
        f"ignoreSslErrors: true: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any MITM on the "
        f"controller-to-service path can inject response payloads "
        f"that flow into downstream stages."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
