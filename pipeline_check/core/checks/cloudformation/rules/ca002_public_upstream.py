"""CA-002 (CloudFormation). CodeArtifact repo has public upstream."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-002",
    title="CodeArtifact repository has a public external connection",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Route every ``ExternalConnections`` entry through a private "
        "mirror that caches and vets public packages, or scope with "
        "upstream allow-lists. Direct ``public:npmjs`` / "
        "``public:pypi`` is dependency-confusion fuel."
    ),
    docs_note=(
        "Reads ``AWS::CodeArtifact::Repository.Properties."
        "ExternalConnections``. Any value beginning with ``public:`` "
        "(e.g. ``public:npmjs``) fetches packages directly from the "
        "public ecosystem with no intermediate scrub."
    ),
    exploit_example=(
        "# Vulnerable: a CodeArtifact repository wired to a public\n"
        "# external connection. Internal package names that show\n"
        "# up in your repo manifests can be claimed on the public\n"
        "# upstream with a higher version; consumers resolve via\n"
        "# the connection and pull attacker code.\n"
        "Resources:\n"
        "  SharedRepo:\n"
        "    Type: AWS::CodeArtifact::Repository\n"
        "    Properties:\n"
        "      DomainName: myorg\n"
        "      RepositoryName: shared\n"
        "      ExternalConnections: [public:pypi]   # public upstream\n"
        "\n"
        "# Safe: drop the public external connection. Use a\n"
        "# curated internal upstream (or another internal\n"
        "# CodeArtifact repo) that only mirrors known-good\n"
        "# packages.\n"
        "Resources:\n"
        "  SharedRepo:\n"
        "    Type: AWS::CodeArtifact::Repository\n"
        "    Properties:\n"
        "      DomainName: myorg\n"
        "      RepositoryName: shared\n"
        "      Upstreams: [public-pypi-cache]   # internal-only upstream"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-002"]
