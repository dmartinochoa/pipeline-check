"""MVN-011. Maven repository URL embeds plaintext credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-011",
    title="Maven repository URL embeds plaintext credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Strip the credential out of every repository / mirror URL "
        "and move it into a ``<server>`` entry in "
        "``~/.m2/settings.xml``. Maven matches the server entry to "
        "the repository by ``<id>``:\n\n"
        "    <!-- pom.xml -->\n"
        "    <repositories>\n"
        "      <repository>\n"
        "        <id>corp-nexus</id>\n"
        "        <url>https://nexus.corp.example/repo/</url>\n"
        "      </repository>\n"
        "    </repositories>\n\n"
        "    <!-- ~/.m2/settings.xml -->\n"
        "    <servers>\n"
        "      <server>\n"
        "        <id>corp-nexus</id>\n"
        "        <username>deploy-bot</username>\n"
        "        <password>{encrypted-form}</password>\n"
        "      </server>\n"
        "    </servers>\n\n"
        "The settings.xml entry lives outside the project repo and "
        "uses the Maven-encrypted password form (see MVN-010). "
        "URL-embedded credentials in pom.xml or settings.xml "
        "mirror entries land directly in git history; rotation "
        "requires a history scrub before the leaked value stops "
        "being useful."
    ),
    docs_note=(
        "Walks every ``<repository><url>``, "
        "``<pluginRepository><url>``, "
        "``<distributionManagement><repository><url>``, and "
        "settings.xml ``<mirror><url>`` for an embedded "
        "``user:pass@`` authority. Empty-password forms "
        "(``https://user:@host``) and ``${var}`` placeholders "
        "are skipped, the former is an operator-flagged "
        "'no credential intended' marker and the latter resolves "
        "at build time from the environment.\n\n"
        "Distinct from MVN-003 (HTTP scheme — transport risk) and "
        "MVN-010 (settings.xml ``<server><password>`` — different "
        "credential location). All three failure modes can "
        "coexist."
    ),
    known_fp=(
        "Some internal templating tools emit a placeholder "
        "credential form (``https://__TOKEN__:@host``) and "
        "substitute the real value at build time. The rule's "
        "placeholder skip-list only recognizes ``${...}``; "
        "suppress per file when the template marker is stable.",
    ),
    incident_refs=(
        "Common pattern across enterprise Maven projects: a "
        "contributor pastes a deploy-bot URL with embedded "
        "credentials into pom.xml during a quick test, intends to "
        "replace it before commit, the replacement never happens. "
        "The repo's git history retains the credential after the "
        "fact even if the next commit cleans the file.",
    ),
    exploit_example=(
        "<!-- Vulnerable: credentials pasted into the URL. -->\n"
        "<repositories>\n"
        "  <repository>\n"
        "    <id>corp-nexus</id>\n"
        "    <url>https://deploy-bot:s3cret@nexus.corp.example/repo/</url>\n"
        "  </repository>\n"
        "</repositories>\n"
        "\n"
        "<!-- Attack: `git push` lands the file in repo history.\n"
        "     The deploy-bot credential is now in every clone and\n"
        "     CI cache indefinitely. -->\n"
        "\n"
        "<!-- Safe: credential-free URL + settings.xml server. -->\n"
        "<repositories>\n"
        "  <repository>\n"
        "    <id>corp-nexus</id>\n"
        "    <url>https://nexus.corp.example/repo/</url>\n"
        "  </repository>\n"
        "</repositories>"
    ),
)


_AUTH_RE = re.compile(
    r"://(?P<user>[^/@:\s\${]+):(?P<pass>[^/@\s\${][^/@\s]*)@",
)


def check(pom: PomFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        if not repo.url:
            continue
        m = _AUTH_RE.search(repo.url)
        if not m:
            continue
        user = m.group("user")
        host = repo.url.split("@", 1)[1].split("/", 1)[0]
        offenders.append(
            f"{repo.section}[{repo.id or 'unnamed'}]: {user}@{host}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=repo.line_no, end_line=repo.line_no,
        ))
    for mirror in pom.mirrors:
        if not mirror.url:
            continue
        m = _AUTH_RE.search(mirror.url)
        if not m:
            continue
        user = m.group("user")
        host = mirror.url.split("@", 1)[1].split("/", 1)[0]
        offenders.append(
            f"mirror[{mirror.id or 'unnamed'}]: {user}@{host}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=mirror.line_no, end_line=mirror.line_no,
        ))
    passed = not offenders
    desc = (
        "No Maven repository / mirror URLs carry embedded "
        "credentials."
        if passed else
        f"{len(offenders)} URL(s) carry embedded credentials: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each value lands "
        f"in git history; rotation requires consumer-side updates "
        f"plus history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
