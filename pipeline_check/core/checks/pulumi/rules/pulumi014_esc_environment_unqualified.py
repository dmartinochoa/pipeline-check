"""PULUMI-014. ESC environment imported without a project / org qualifier."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-014",
    title="ESC environment imported without a project / org qualifier",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-6"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Import every Pulumi ESC environment by its fully-qualified "
        "``<project>/<environment>`` (or ``<org>/<project>/<env>``) "
        "name, not a bare environment name. An ESC environment can "
        "carry secrets and the cloud OIDC / credential config a "
        "stack assumes at ``pulumi up``, so resolving it by an "
        "unqualified name lets the import bind to whichever project "
        "context happens to apply, a different environment (with "
        "different credentials) than intended if the default "
        "context drifts or differs between operators / CI. Qualify "
        "the name so the import is unambiguous and pins to one "
        "environment, the same drift concern PULUMI-006 flags for "
        "``StackReference``."
    ),
    docs_note=(
        "Reads the ``environment:`` import list from each "
        "``Pulumi.yaml`` and ``Pulumi.<stack>.yaml`` (both the "
        "bare-list form and the ``{ imports: [...] }`` form) and "
        "fires on any entry that is a bare environment name with no "
        "``/`` qualifier. A qualified name "
        "(``project/env`` or ``org/project/env``) pins the import; "
        "a bare name resolves against the ambient default "
        "project / org context.\n\n"
        "The ESC face of the StackReference-drift primitive "
        "(PULUMI-006): an unqualified cross-resource reference that "
        "can silently resolve to the wrong source."
    ),
    known_fp=(
        "A single-project setup where the default context is "
        "unambiguous and stable may use bare environment names "
        "safely. Suppress per stack with a rationale; qualifying "
        "the name is cheap and removes the ambiguity outright.",
    ),
    incident_refs=(
        "Ambiguous-reference drift class: an unqualified ESC import "
        "binding to a different environment (and its credentials) "
        "than the author intended when the default project / org "
        "context differs between who runs the deployment.",
    ),
    exploit_example=(
        "# Vulnerable Pulumi.prod.yaml: bare environment name.\n"
        "environment:\n"
        "  - prod-secrets\n"
        "config:\n"
        "  aws:region: us-east-1\n"
        "\n"
        "# Risk: `prod-secrets` resolves against whatever project /\n"
        "# org context applies when `pulumi up` runs. In a different\n"
        "# context (another operator, a CI org) it can bind to a\n"
        "# different `prod-secrets` carrying different cloud\n"
        "# credentials than intended.\n"
        "\n"
        "# Safe: fully-qualified import.\n"
        "environment:\n"
        "  - myproject/prod-secrets\n"
    ),
)


def _environment_entries(data: dict[str, Any]) -> list[str]:
    """Return the string entries of an ``environment:`` import block,
    handling the bare-list and ``{imports: [...]}`` forms."""
    env = data.get("environment")
    items: list[Any]
    if isinstance(env, list):
        items = env
    elif isinstance(env, dict) and isinstance(env.get("imports"), list):
        items = env["imports"]
    else:
        return []
    return [e for e in items if isinstance(e, str) and e.strip()]


def check(ctx: PulumiContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    sources: list[tuple[str, str, dict[str, Any]]] = []
    for p in ctx.projects:
        sources.append((p.path, p.text, p.data))
    for s in ctx.stacks:
        sources.append((s.path, s.text, s.data))

    for path, text, data in sources:
        for entry in _environment_entries(data):
            if "/" in entry:
                continue
            offenders.append(f"{entry} ({path})")
            line_no = 1
            marker = entry
            if marker in text:
                line_no = text[: text.index(marker)].count("\n") + 1
            locations.append(Location(
                path=path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "Every imported ESC environment is qualified, or none are "
        "imported."
        if passed else
        f"{len(offenders)} ESC environment import(s) lack a "
        f"project / org qualifier: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A bare name resolves "
        f"against the ambient default context and can bind to the "
        f"wrong environment / credentials."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations
            else (ctx.projects[0].path if ctx.projects else "Pulumi.yaml")
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
