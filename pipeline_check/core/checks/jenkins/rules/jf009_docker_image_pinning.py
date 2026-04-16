"""JF-009 — docker agent images must be pinned by sha256 digest."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import DIGEST_RE, DOCKER_IMAGE_RE, VERSION_TAG_RE


RULE = Rule(
    id="JF-009",
    title="Agent docker image not pinned to sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
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
        "providers, Jenkins has no separate tag-pinning check — so "
        "this one fires at HIGH regardless of whether the tag is "
        "floating or immutable."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    unpinned: list[str] = []
    for ref in DOCKER_IMAGE_RE.findall(jf.text):
        if DIGEST_RE.search(ref):
            continue
        if ":" not in ref.rsplit("/", 1)[-1]:
            unpinned.append(f"{ref} (no tag)")
            continue
        tag = ref.rsplit(":", 1)[1]
        if tag == "latest" or not VERSION_TAG_RE.search(ref):
            unpinned.append(f"{ref} (floating tag)")
            continue
        unpinned.append(f"{ref} (tag, not digest)")
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
    )
