"""JF-009, docker agent images must be pinned by sha256 digest."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import DIGEST_RE, DOCKER_IMAGE_RE, VERSION_TAG_RE

RULE = Rule(
    id="JF-009",
    title="Agent docker image not pinned to sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve each image to its current digest (`docker buildx "
        "imagetools inspect <ref>` prints it) and reference it via "
        "`image '<repo>@sha256:<digest>'`. Automate refreshes with "
        "Renovate."
    ),
    docs_note=(
        "`agent { docker { image 'name:tag' } }` is not digest-"
        "pinned, so a repointed registry tag silently swaps the "
        "executor under every subsequent build. Unlike the YAML "
        "providers, Jenkins has no separate tag-pinning check, so "
        "this one fires at HIGH regardless of whether the tag is "
        "floating or immutable."
    ),
    exploit_example=(
        "// Vulnerable: ``image 'maven:3.9'`` is a mutable tag.\n"
        "// Docker Hub's maven team rebuilds it on every Maven\n"
        "// point release; a publisher takeover ships code into\n"
        "// every Jenkins build using the tag.\n"
        "pipeline {\n"
        "  agent {\n"
        "    docker { image 'maven:3.9' }\n"
        "  }\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps { sh 'mvn -B verify' }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: pin to the content-addressable digest.\n"
        "pipeline {\n"
        "  agent {\n"
        "    docker { image 'maven@sha256:abc123...' }  // maven:3.9.5-eclipse-temurin-21\n"
        "  }\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps { sh 'mvn -B verify' }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    # Re-scan the source text via ``finditer`` to recover line offsets
    # for each match. ``DOCKER_IMAGE_RE.findall`` only returns the
    # captured ref strings; positional info needs the match objects.
    for m in DOCKER_IMAGE_RE.finditer(jf.text):
        ref = m.group(1) if m.groups() else m.group(0)
        is_offender = False
        if DIGEST_RE.search(ref):
            continue
        if ":" not in ref.rsplit("/", 1)[-1]:
            unpinned.append(f"{ref} (no tag)")
            is_offender = True
        else:
            tag = ref.rsplit(":", 1)[1]
            if tag == "latest" or not VERSION_TAG_RE.search(ref):
                unpinned.append(f"{ref} (floating tag)")
            else:
                unpinned.append(f"{ref} (tag, not digest)")
            is_offender = True
        if is_offender:
            # 1-based line of the match, same pattern JF-001 uses
            # to recover line offsets from a text-based file.
            line_no = jf.text.count("\n", 0, m.start()) + 1
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not unpinned
    desc = (
        "Every docker agent image is pinned by sha256 digest."
        if passed else
        f"{len(unpinned)} docker agent image(s) are not digest-"
        f"pinned: {', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
