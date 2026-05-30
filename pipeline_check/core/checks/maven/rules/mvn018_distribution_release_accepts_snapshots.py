"""MVN-018. distributionManagement release repository accepts SNAPSHOTs."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-018",
    title="distributionManagement release repository accepts SNAPSHOTs",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Keep the ``<distributionManagement><repository>`` "
        "(the release deployment target) snapshot-free, and route "
        "mutable ``-SNAPSHOT`` builds to a separate "
        "``<snapshotRepository>``. When the release repository "
        "enables snapshots (``<snapshots><enabled>true``), mutable "
        "``-SNAPSHOT`` artifacts land in the same place consumers "
        "treat as immutable releases, so a coordinate that looks "
        "like a pinned release can be silently re-published with "
        "different bytes. Set ``<releases><enabled>true`` + "
        "``<snapshots><enabled>false`` on the release repository, "
        "and declare a distinct ``<snapshotRepository>`` for "
        "in-development builds."
    ),
    docs_note=(
        "Re-parses ``pom.xml`` and inspects the "
        "``<distributionManagement><repository>`` element (the "
        "release deploy target, not the ``<snapshotRepository>``). "
        "Fires when that repository sets "
        "``<snapshots><enabled>true``, which lets ``mvn deploy`` "
        "publish mutable ``-SNAPSHOT`` artifacts into the release "
        "repo.\n\n"
        "Scoped tightly to the snapshot-acceptance angle: the "
        "``http://`` deploy-URL half of distributionManagement "
        "hygiene is already MVN-003's surface. This rule is about a "
        "release target that doesn't hold its release-only "
        "guarantee."
    ),
    known_fp=(
        "Internal repositories that intentionally serve both "
        "releases and snapshots from one URL (a single Nexus / "
        "Artifactory hosted repo) may enable snapshots on the "
        "release target by design. Suppress per pom with a "
        "rationale; the cleaner posture is a dedicated "
        "``<snapshotRepository>``.",
    ),
    exploit_example=(
        "<!-- Vulnerable: the release target accepts snapshots. -->\n"
        "<distributionManagement>\n"
        "  <repository>\n"
        "    <id>corp-releases</id>\n"
        "    <url>https://nexus.corp/releases</url>\n"
        "    <snapshots><enabled>true</enabled></snapshots>\n"
        "  </repository>\n"
        "</distributionManagement>\n"
        "\n"
        "<!-- Risk: a `1.2.0-SNAPSHOT` (or even a re-deployed\n"
        "     `1.2.0`) lands in the repo consumers treat as\n"
        "     immutable releases, so a pinned-looking coordinate can\n"
        "     be re-published with different bytes. -->\n"
        "\n"
        "<!-- Safe: release-only target + separate snapshot repo. -->\n"
        "<distributionManagement>\n"
        "  <repository>\n"
        "    <id>corp-releases</id>\n"
        "    <url>https://nexus.corp/releases</url>\n"
        "    <snapshots><enabled>false</enabled></snapshots>\n"
        "  </repository>\n"
        "  <snapshotRepository>\n"
        "    <id>corp-snapshots</id>\n"
        "    <url>https://nexus.corp/snapshots</url>\n"
        "  </snapshotRepository>\n"
        "</distributionManagement>"
    ),
)


_MAVEN_NS_RE = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _MAVEN_NS_RE.sub("", tag)


def _findtext_local(elem: ET.Element, name: str) -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_child_local(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def check(pom: PomFile) -> Finding:
    if pom.is_settings or not pom.path.endswith(".xml"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="No distributionManagement to audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        root = ET.fromstring(pom.text)
    except ET.ParseError:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="pom.xml parse error; can't audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    dist = _find_child_local(root, "distributionManagement")
    repo = _find_child_local(dist, "repository") if dist is not None else None
    if repo is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="No distributionManagement release repository.",
            recommendation=RULE.recommendation, passed=True,
        )
    snapshots = _find_child_local(repo, "snapshots")
    enabled = (
        _findtext_local(snapshots, "enabled").lower() == "true"
        if snapshots is not None else False
    )
    if not enabled:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "distributionManagement release repository does not "
                "accept SNAPSHOTs."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    repo_id = _findtext_local(repo, "id") or "(no id)"
    line_no = 1
    # Tolerate a namespace prefix / attributes on the opening tag
    # (``<foo:distributionManagement ...>``) so the location stays
    # accurate instead of falling back to line 1.
    m = re.search(r"<(?:\w+:)?distributionManagement(?:\s|>)", pom.text)
    if m is not None:
        line_no = pom.text[:m.start()].count("\n") + 1
    desc = (
        f"distributionManagement release repository '{repo_id}' "
        f"enables snapshots, so mutable -SNAPSHOT artifacts deploy "
        f"into the release target consumers treat as immutable. "
        f"Route snapshots to a separate <snapshotRepository>."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=[Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        )],
    )
