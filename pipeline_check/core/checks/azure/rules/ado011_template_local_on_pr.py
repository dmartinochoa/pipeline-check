"""ADO-011 — PR-validated pipelines must not include local templates."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule


RULE = Rule(
    id="ADO-011",
    title="`template: <local-path>` on PR-validated pipeline",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-PIN-DEPS"),
    recommendation=(
        "Move the template into a separate, branch-protected "
        "repository and reference it via `template: foo.yml@<repo-"
        "resource>` with a pinned `ref:` on the resource. That way "
        "the template content is fixed at PR creation time and "
        "can't be modified from the PR branch."
    ),
    docs_note=(
        "`template: <relative-path>` includes another YAML from the "
        "CURRENT repo. On PR validation builds, the repo content is "
        "the PR branch — letting the PR author swap the template "
        "body. Cross-repo templates (`template: foo.yml@my-repo`) "
        "are version-pinned and not affected."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
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
    local_templates: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            t = node.get("template")
            if isinstance(t, str) and "@" not in t:
                local_templates.append(t)
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(doc)
    passed = not local_templates
    desc = (
        "PR-validated pipeline does not include any local templates."
        if passed else
        f"PR-validated pipeline includes {len(local_templates)} "
        f"local template(s): {', '.join(local_templates[:5])}"
        f"{'…' if len(local_templates) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
