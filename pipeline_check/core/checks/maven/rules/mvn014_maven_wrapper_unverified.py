"""MVN-014. Maven Wrapper distributionUrl lacks distributionSha256Sum."""
from __future__ import annotations

from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-014",
    title="Maven Wrapper distributionUrl lacks distributionSha256Sum",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-345"),
    recommendation=(
        "Add a ``distributionSha256Sum`` entry to ``.mvn/wrapper/"
        "maven-wrapper.properties`` matching the SHA-256 of the "
        "Maven distribution at ``distributionUrl``:\n\n"
        "    distributionUrl=https://repo.maven.apache.org/maven2/"
        "org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip\n"
        "    distributionSha256Sum=<64-char-sha256>\n\n"
        "The hash is published at the distribution URL plus "
        "``.sha256`` (or available from Apache's release manifest). "
        "The wrapper verifies the downloaded archive's hash before "
        "extracting; without the entry, the wrapper trusts whatever "
        "bytes the URL serves at download time — fine when the URL "
        "is the canonical Apache repo and the connection is HTTPS, "
        "but unrecoverable when an internal mirror is "
        "compromised or a network MITM intercepts the download.\n\n"
        "Modern ``mvn wrapper:wrapper`` invocations support a "
        "``-Dtype=script`` mode that adds the hash automatically."
    ),
    docs_note=(
        "Reads ``.mvn/wrapper/maven-wrapper.properties`` (Java "
        "properties format: ``key=value`` lines) in the same "
        "directory as each ``pom.xml`` and fires when "
        "``distributionUrl`` is set but ``distributionSha256Sum`` "
        "is missing. Projects that don't ship the Maven Wrapper "
        "(no properties file) pass silently — the wrapper is "
        "optional and absent files aren't a posture risk.\n\n"
        "The Maven Wrapper, like Gradle's, downloads its own "
        "build tool on first invocation. Hash verification at "
        "the wrapper layer closes the supply-chain gap that "
        "would otherwise require trusting the URL + TLS chain "
        "alone."
    ),
    known_fp=(
        "Wrapper configurations that use a non-HTTPS internal "
        "mirror sometimes deliberately omit the hash because "
        "the mirror's content can change. The right fix is to "
        "freeze the mirror's distribution to a specific Maven "
        "release and pin its hash, but suppression with a "
        "rationale is acceptable in the interim.",
    ),
    incident_refs=(
        "Maven Wrapper compromise pattern: an internal mirror "
        "serves a tampered Maven distribution; consumers who "
        "use the wrapper without ``distributionSha256Sum`` "
        "accept the tampered bytes and run them as their build "
        "tool. The hash entry catches this at download time "
        "before the malicious Maven ever extracts.",
    ),
    exploit_example=(
        "# Vulnerable: .mvn/wrapper/maven-wrapper.properties\n"
        "distributionUrl=https://internal.example.com/maven/apache-maven-3.9.6-bin.zip\n"
        "# (no distributionSha256Sum)\n"
        "\n"
        "# Attack: the internal mirror is compromised; serving\n"
        "# a tampered apache-maven-3.9.6-bin.zip. Every consumer\n"
        "# running ``./mvnw`` downloads the tampered archive\n"
        "# without hash verification, extracts it, and runs the\n"
        "# malicious Maven as their build tool.\n"
        "\n"
        "# Safe:\n"
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip\n"
        "distributionSha256Sum=a3f2c5e3b8e0d4a5c1234567890abcdef1234567890abcdef1234567890abcd\n"
        "\n"
        "# The wrapper rejects the download when the hash drifts.\n"
    ),
)


def _parse_properties(text: str) -> dict[str, str]:
    """Minimal Java-properties parser sufficient for the wrapper
    properties file (no escapes, no continuations)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip()
    return out


def _find_wrapper_properties(pom_path: str) -> Path | None:
    """Return the maven-wrapper.properties sibling to *pom_path*,
    or ``None`` when absent. The wrapper conventionally lives at
    ``<project-root>/.mvn/wrapper/maven-wrapper.properties``."""
    pom = Path(pom_path)
    candidate = pom.parent / ".mvn" / "wrapper" / "maven-wrapper.properties"
    if candidate.is_file():
        return candidate
    return None


def check(pom: PomFile) -> Finding:
    if pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "settings.xml does not anchor a project wrapper."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    wrapper = _find_wrapper_properties(pom.path)
    if wrapper is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Project does not ship a Maven Wrapper; nothing to "
                "audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        text = wrapper.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(wrapper),
            description=(
                "Wrapper properties file unreadable; can't audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    props = _parse_properties(text)
    if "distributionUrl" not in props:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(wrapper),
            description=(
                "Wrapper properties has no distributionUrl; "
                "wrapper is non-functional."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    has_hash = bool(props.get("distributionSha256Sum"))
    if has_hash:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(wrapper),
            description=(
                "Wrapper distribution is pinned with a SHA-256 hash."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=str(wrapper),
        description=(
            f"Wrapper distributionUrl=`{props['distributionUrl']}` "
            f"has no distributionSha256Sum. The wrapper accepts "
            f"whatever bytes the URL serves; a compromised mirror "
            f"or MITM substitutes a tampered Maven."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
