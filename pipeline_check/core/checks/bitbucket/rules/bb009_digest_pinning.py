"""BB-009, `pipe:` should pin by sha256 digest (strictest tier)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps
from ._helpers import extract_pipe_ref

RULE = Rule(
    id="BB-009",
    title="pipe: pinned by version rather than sha256 digest",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve each pipe to its digest (`docker buildx imagetools "
        "inspect bitbucketpipelines/<name>:<ver>`) and reference it "
        "via `@sha256:<digest>`."
    ),
    docs_note=(
        "BB-001 fails floating tags at HIGH; BB-009 is the stricter "
        "tier. Even immutable-looking semver tags can be repointed "
        "by the registry; sha256 digests are tamper-evident."
    ),
    exploit_example=(
        "# Vulnerable: a third-party pipe pinned by version tag.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - pipe: acme/deploy-pipe:1.2.0\n"
        "\n"
        "# Attack: the tag `1.2.0` is mutable. The pipe's publisher (or\n"
        "# whoever compromises their registry account) repoints `1.2.0`\n"
        "# to a new image carrying credential-exfil code. Your next\n"
        "# pipeline run pulls it and runs it with your repository\n"
        "# variables and tokens.\n"
        "\n"
        "# Safe: pin to the immutable sha256 digest.\n"
        "          - pipe: acme/deploy-pipe@sha256:<digest>"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    tagged: list[str] = []
    for loc, step in iter_steps(doc):
        script = step.get("script")
        if not isinstance(script, list):
            continue
        for entry in script:
            ref = extract_pipe_ref(entry)
            if not ref or "@sha256:" in ref:
                continue
            tagged.append(f"{loc}: {ref}")
    passed = not tagged
    desc = (
        "Every `pipe:` reference is pinned by sha256 digest."
        if passed else
        f"{len(tagged)} `pipe:` reference(s) are pinned by version "
        f"rather than digest: {', '.join(tagged[:5])}"
        f"{'…' if len(tagged) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
