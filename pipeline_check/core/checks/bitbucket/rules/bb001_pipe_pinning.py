"""BB-001, `pipe:` references must be pinned to a full semver or SHA."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps
from ._helpers import VER_OK_RE, extract_pipe_ref

RULE = Rule(
    id="BB-001",
    title="pipe: action not pinned to exact version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every `pipe:` to a full semver tag (e.g. "
        "`atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. "
        "Floating majors like `:1` can roll to new code silently."
    ),
    docs_note=(
        "Bitbucket pipes are docker-image references. Major-only "
        "(`:1`) or missing tags let Atlassian/the publisher swap the "
        "image contents. Full semver or sha256 digest is required."
    ),
    exploit_example=(
        "# Vulnerable: ``atlassian/aws-s3-deploy:1`` resolves to\n"
        "# whatever the publisher's latest 1.x image is at job\n"
        "# start. A publisher takeover (compromised Atlassian\n"
        "# Marketplace account, leaked token) repoints the tag\n"
        "# silently; every consumer's pipeline executes the new\n"
        "# image on the next run.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - pipe: atlassian/aws-s3-deploy:1\n"
        "            variables: { ... }\n"
        "\n"
        "# Safe: pin to an exact version (``X.Y.Z``). Renovate /\n"
        "# Dependabot's bitbucket-pipe ecosystem bumps these in\n"
        "# reviewable PRs.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - pipe: atlassian/aws-s3-deploy:1.7.0\n"
        "            variables: { ... }"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    for loc, step in iter_steps(doc):
        script = step.get("script")
        if not isinstance(script, list):
            continue
        for entry in script:
            ref = extract_pipe_ref(entry)
            if ref is None or "@sha256:" in ref:
                continue
            if ":" not in ref or not VER_OK_RE.search(ref):
                unpinned.append(f"{loc}: {ref}")
                # Anchor on the script entry when it's a dict (loader
                # tracks lines on dicts/lists, not on bare strings).
                anchor = entry if isinstance(entry, dict) else step
                line = _line_of(anchor)
                locations.append(
                    Location(path=path, start_line=line, end_line=line)
                )
    passed = not unpinned
    desc = (
        "All `pipe:` references are pinned to a specific version."
        if passed else
        f"{len(unpinned)} `pipe:` reference(s) use a floating / "
        f"major-only tag: {', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
