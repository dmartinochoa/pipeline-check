"""MVN-017. settings.xml <server> ships a private key with an inline passphrase."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-017",
    title="settings.xml <server> ships a private key with an inline passphrase",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Encrypt the ``<passphrase>`` or inject it at build time; "
        "never commit a private-key passphrase in plaintext "
        "alongside the key. The remediation mirrors MVN-010's "
        "password flow: run ``mvn --encrypt-password <passphrase>`` "
        "and paste the ``{...}`` token into ``<passphrase>``, with "
        "the master in ``~/.m2/settings-security.xml``; or use a "
        "property expansion (``${env.DEPLOY_KEY_PASSPHRASE}``) so "
        "the value lives in a CI secret, not on disk. A plaintext "
        "passphrase next to a ``<privateKey>`` path defeats the key "
        "passphrase entirely: anyone who reads the file (a repo "
        "clone, a CI cache, an archived backup) has both halves and "
        "can use the key to deploy. Prefer rotating to a CI-managed "
        "deploy credential over storing a long-lived key + "
        "passphrase in settings.xml at all."
    ),
    docs_note=(
        "Reads ``<settings><servers><server>`` entries and fires "
        "when a ``<server>`` declares a ``<privateKey>`` AND a "
        "``<passphrase>`` that carries a plaintext value, anything "
        "that is not the Maven-encrypted ``{...}`` form, an "
        "``${...}`` property / env expansion, or empty.\n\n"
        "The SSH / GPG-credential sibling of MVN-010 (a plaintext "
        "``<password>``); it reuses the same "
        "encrypted-vs-``${}``-vs-plaintext discriminator. Lower "
        "frequency than ``<password>`` but higher blast radius: a "
        "leaked key + passphrase is a reusable deploy credential."
    ),
    known_fp=(
        "Local / sandbox settings.xml files used only against a "
        "throwaway key may carry a placeholder passphrase that "
        "looks like plaintext. Suppress per file with a rationale; "
        "a production settings.xml should never pair a real "
        "``<privateKey>`` with a plaintext ``<passphrase>``.",
    ),
    incident_refs=(
        "Same leak class as MVN-010: deploy credentials committed "
        "through settings.xml. A private key whose passphrase is "
        "stored next to it offers no protection once the file "
        "leaks, the passphrase is the only thing standing between "
        "a stolen key file and a working deploy credential.",
    ),
    exploit_example=(
        "<!-- Vulnerable: private key + plaintext passphrase. -->\n"
        "<settings>\n"
        "  <servers>\n"
        "    <server>\n"
        "      <id>release-host</id>\n"
        "      <privateKey>${user.home}/.ssh/deploy_id_rsa</privateKey>\n"
        "      <passphrase>hunter2-rotate-me</passphrase>\n"
        "    </server>\n"
        "  </servers>\n"
        "</settings>\n"
        "\n"
        "<!-- Attack: the file lands in git history. Whoever reads\n"
        "     it (clone, CI cache, backup) has the passphrase; paired\n"
        "     with the key it's a working deploy credential to the\n"
        "     release host, indefinitely. -->\n"
        "\n"
        "<!-- Safe: Maven-encrypted passphrase, or env expansion. -->\n"
        "<passphrase>{COQLCE6DU6GtcS5P=}</passphrase>\n"
        "<!-- or -->\n"
        "<passphrase>${env.DEPLOY_KEY_PASSPHRASE}</passphrase>"
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
                "Not a settings.xml; <server> passphrase audit does "
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
        private_key = _findtext_local(server, "privateKey")
        passphrase = _findtext_local(server, "passphrase")
        if not private_key or not passphrase:
            continue
        if _ENCRYPTED_RE.match(passphrase):
            continue  # Maven-encrypted form
        if _PLACEHOLDER_RE.match(passphrase):
            continue  # property / env-var expansion
        server_id = _findtext_local(server, "id") or "(no id)"
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
        "No <server> pairs a private key with a plaintext passphrase."
        if passed else
        f"{len(offenders)} <server> entry / entries ship a private "
        f"key with a plaintext passphrase: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The passphrase "
        f"persists in git history; paired with the key it is a "
        f"reusable deploy credential."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
