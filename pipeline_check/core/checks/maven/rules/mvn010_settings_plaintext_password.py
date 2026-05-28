"""MVN-010. settings.xml <server> carries a plaintext password."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-010",
    title="settings.xml <server> carries a plaintext password",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Replace every plaintext ``<password>`` inside "
        "``<settings><servers><server>`` with a Maven-encrypted "
        "value. The remediation flow is:\n\n"
        "1. Generate a master password: ``mvn --encrypt-master-"
        "password <master>``. Store the result in "
        "``~/.m2/settings-security.xml`` under ``<settingsSecurity>"
        "<master>``.\n"
        "2. Encrypt the per-server password: ``mvn --encrypt-"
        "password <real-password>``. The output is a "
        "``{...}``-wrapped opaque token.\n"
        "3. Paste the token into the ``<password>`` element of the "
        "``<server>`` block. Maven decrypts it at build time using "
        "the master from ``settings-security.xml``.\n\n"
        "For CI environments, prefer injecting the password via "
        "environment variable or CI secret manager: Maven 3.6+ "
        "expands ``${env.MY_DEPLOY_TOKEN}`` inside settings.xml at "
        "read time, so the value never lives on disk. The plaintext "
        "form in settings.xml leaves the credential committed to "
        "any repository the file is checked into and persists in "
        "git history indefinitely."
    ),
    docs_note=(
        "Reads ``<settings><servers><server>`` entries and fires "
        "when ``<password>`` carries a plaintext value (anything "
        "that's not the Maven-encrypted ``{...}`` form, an empty "
        "string, or an ``${...}`` property expansion). The Maven-"
        "encrypted form is a base64-encoded opaque token wrapped "
        "in literal curly braces; the password decrypts at build "
        "time using the master in ``settings-security.xml``.\n\n"
        "Property-expansion forms (``${env.MY_TOKEN}``, "
        "``${deploy.token}``) pass the rule because the actual "
        "value lives outside the file. CI-injected forms via "
        "environment variables are the safest pattern."
    ),
    known_fp=(
        "Sandbox / playground settings.xml files used only for "
        "local testing against a public mirror may legitimately "
        "carry placeholder values that look like plaintext "
        "passwords. Suppress per file with a rationale; "
        "production settings.xml should never carry plaintext.",
    ),
    incident_refs=(
        "Long-running pattern of internal Nexus / Artifactory "
        "credentials leaking through settings.xml files committed "
        "to public mirrors. Maven's own documentation has "
        "highlighted password encryption since Maven 2.1 (2008); "
        "the plaintext shape is a posture / migration gap that "
        "tooling like this one's value is to surface at audit "
        "time.",
    ),
    exploit_example=(
        "<!-- Vulnerable: plaintext password committed to git. -->\n"
        "<settings>\n"
        "  <servers>\n"
        "    <server>\n"
        "      <id>corp-nexus</id>\n"
        "      <username>deploy-bot</username>\n"
        "      <password>s3cret-rotate-me</password>\n"
        "    </server>\n"
        "  </servers>\n"
        "</settings>\n"
        "\n"
        "<!-- Attack: `git push` lands the file in repo history.\n"
        "     Any clone (CI cache, contractor laptop, archived\n"
        "     backup) carries the deploy-bot password\n"
        "     indefinitely. A leak of the repo turns into\n"
        "     write-access to the internal Nexus, including any\n"
        "     private artifacts that weren't meant to be visible. -->\n"
        "\n"
        "<!-- Safe: Maven-encrypted password. -->\n"
        "<settings>\n"
        "  <servers>\n"
        "    <server>\n"
        "      <id>corp-nexus</id>\n"
        "      <username>deploy-bot</username>\n"
        "      <password>{COQLCE6DU6GtcS5P=}</password>\n"
        "    </server>\n"
        "  </servers>\n"
        "</settings>\n"
        "\n"
        "<!-- Or, CI-friendly env-var expansion (no on-disk value). -->\n"
        "<password>${env.NEXUS_DEPLOY_TOKEN}</password>"
    ),
)


_MAVEN_NS_RE = re.compile(r"^\{[^}]+\}")
_ENCRYPTED_RE = re.compile(r"^\{[^}]+\}$")
_PLACEHOLDER_RE = re.compile(r"^\$\{[^}]+\}$")


def _strip_ns(tag: str) -> str:
    return _MAVEN_NS_RE.sub("", tag)


def _findtext_local(elem: ET.Element, name: str) -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return ""


def check(pom: PomFile) -> Finding:
    if not pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Not a settings.xml; <server><password> audit does "
                "not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        root = ET.fromstring(pom.text)
    except ET.ParseError:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml parse error; can't audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    servers_node = None
    for child in root:
        if _strip_ns(child.tag) == "servers":
            servers_node = child
            break
    if servers_node is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml declares no <servers>.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for server in servers_node:
        if _strip_ns(server.tag) != "server":
            continue
        server_id = _findtext_local(server, "id") or "(no id)"
        password = _findtext_local(server, "password")
        if not password:
            continue
        if _ENCRYPTED_RE.match(password):
            continue  # Maven-encrypted form
        if _PLACEHOLDER_RE.match(password):
            continue  # property / env-var expansion
        offenders.append(server_id)
        line_no = 1
        marker = f"<id>{server_id}</id>"
        if marker in pom.text:
            line_no = pom.text[:pom.text.index(marker)].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every <server><password> uses Maven encryption or "
        "property expansion."
        if passed else
        f"{len(offenders)} <server> entry / entries carry plaintext "
        f"passwords: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each value persists "
        f"in git history; rotation requires consumer-side updates "
        f"plus history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
