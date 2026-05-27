"""CA-002 (Terraform). CodeArtifact repo has direct public upstream."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-002",
    title="CodeArtifact repository has a public external connection",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Route every ``aws_codeartifact_repository.external_connections`` "
        "through a private mirror that caches and vets public "
        "packages, or scope it with upstream allow-lists. Direct "
        "``public:npmjs``/``public:pypi`` is dependency-confusion fuel."
    ),
    docs_note=(
        "Reads ``aws_codeartifact_repository.external_connections``. "
        "Any value beginning with ``public:`` (e.g. ``public:npmjs``) "
        "fetches packages directly from the public ecosystem with no "
        "intermediate scrub."
    ),
    exploit_example=(
        "# Vulnerable: CodeArtifact repo has a public upstream\n"
        "# (npmjs, PyPI, Maven Central). An attacker publishes a\n"
        "# higher version of an internal package name on the\n"
        "# public upstream; CodeArtifact fetches it automatically.\n"
        'resource "aws_codeartifact_repository" "shared" {\n'
        "  domain     = aws_codeartifact_domain.internal.domain\n"
        '  repository = "shared"\n'
        "  upstream {\n"
        '    repository_name = "npmjs-store"\n'
        "  }\n"
        "}\n"
        "\n"
        "# Safe: remove the public upstream and mirror packages\n"
        "# explicitly, or use package-origin controls to block\n"
        "# upstream publishes of internal package names.\n"
        'resource "aws_codeartifact_repository" "shared" {\n'
        "  domain     = aws_codeartifact_domain.internal.domain\n"
        '  repository = "shared"\n'
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-002"]
