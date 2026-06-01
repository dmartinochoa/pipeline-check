"""BB-010, deploy steps must verify ingested PR artifacts."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-010",
    title="Deploy step ingests pull-request artifact unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step before the deploy step consumes "
        "the artifact: `sha256sum -c artifact.sha256` against a "
        "manifest the producer signed, or `cosign verify` over the "
        "artifact directly. Alternatively, restrict the artifact-"
        "producing step to non-PR pipelines via ``branches:`` or "
        "``custom:`` triggers."
    ),
    docs_note=(
        "Bitbucket steps declare artifacts on the producer and "
        "downstream steps implicitly receive them. When an "
        "unprivileged step produces an artifact and a later "
        "`deployment:` step consumes it without verification, "
        "attacker-controlled output flows into the privileged stage."
    ),
    exploit_example=(
        "# Vulnerable: a deploy step consumes ``build`` artifacts\n"
        "# produced by a PR-triggered build step. A fork PR's\n"
        "# build step uploads anything as ``build``; the deploy\n"
        "# step (which runs with the production credential set)\n"
        "# executes the attacker's binary.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    \"**\":\n"
        "      - step:\n"
        "          name: build\n"
        "          script: [\"./build.sh\"]\n"
        "          artifacts: [\"dist/**\"]\n"
        "      - step:\n"
        "          name: deploy   # consumes the PR build's artifact\n"
        "          deployment: staging\n"
        "          script: [\"./deploy ./dist/release\"]\n"
        "\n"
        "# Safe: don't hand off PR artifacts to a deploy step.\n"
        "# Deploy only on ``branches: { main: ... }`` triggers,\n"
        "# where the artifact's producer was the trusted-context\n"
        "# build of ``main`` itself.\n"
        "pipelines:\n"
        "  pull-requests:\n"
        "    \"**\":\n"
        "      - step:\n"
        "          name: build\n"
        "          script: [\"./build.sh\"]\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          name: build\n"
        "          script: [\"./build.sh\"]\n"
        "          artifacts: [\"dist/**\"]\n"
        "      - step:\n"
        "          name: deploy\n"
        "          deployment: production\n"
        "          script: [\"./deploy ./dist/release\"]"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    produces = False
    deploys = False
    verified = False
    for loc, step in iter_steps(doc):
        # Only a ``pull-requests:`` pipeline runs on untrusted (fork) input.
        # A ``branches:`` / ``default`` build->deploy is the trusted release
        # path, so pairing produce+deploy there is not this finding.
        if not loc.startswith("pull-requests"):
            continue
        arts = step.get("artifacts")
        if (isinstance(arts, list) and arts) or (isinstance(arts, dict) and arts):
            produces = True
        if step.get("deployment"):
            deploys = True
        for line in step.get("script", []) or []:
            if not isinstance(line, str):
                continue
            low = line.lower()
            if (
                "cosign verify" in low
                or "sha256sum --check" in low
                or "sha256sum -c" in low
                or "gpg --verify" in low
            ):
                verified = True
    if not (produces and deploys):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Pipeline does not pair an artifact-producing step "
                "with a deploy step."
            ),
            recommendation="No action required.", passed=True,
        )
    passed = verified
    desc = (
        "Deploy step is paired with an artifact verification step."
        if passed else
        "Pipeline produces an artifact in one step and consumes it "
        "in a `deployment:` step without any verification (cosign, "
        "sha256sum -c, gpg --verify)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
