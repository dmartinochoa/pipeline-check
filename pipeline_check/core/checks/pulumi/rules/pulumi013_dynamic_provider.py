"""PULUMI-013. Dynamic provider runs arbitrary code at deploy time."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-013",
    title="Pulumi dynamic provider runs arbitrary code at deploy time",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-913"),
    recommendation=(
        "Prefer a native Pulumi provider or a reviewed, published "
        "component over a dynamic provider. A dynamic provider's "
        "``create`` / ``update`` / ``delete`` handlers are invoked "
        "by the Pulumi engine during ``pulumi up``, on the deploy "
        "host, with the orchestrator's cloud credentials. The "
        "handler closure is also serialized into stack state, so "
        "anyone who can edit the handler source (or tamper with the "
        "state) gets code execution on the next deploy.\n\n"
        "If a dynamic provider is unavoidable, keep the handler "
        "code minimal, free of external / config-derived input, and "
        "reviewed on every change. Never let a handler shell out or "
        "fetch remote code (see PULUMI-008 and PULUMI-007)."
    ),
    docs_note=(
        "Scans source files for the dynamic-provider API, scoped to "
        "the runtimes where it exists:\n\n"
        "* Python: ``pulumi.dynamic.ResourceProvider`` (the base "
        "class a dynamic provider subclasses)\n"
        "* Node / TypeScript: ``pulumi.dynamic`` namespace usage "
        "(``pulumi.dynamic.ResourceProvider`` / "
        "``pulumi.dynamic.Resource``)\n\n"
        "Go and .NET source files are not scanned because the "
        "dynamic-provider API is a Python / Node feature. The rule "
        "reads the preserved source text; it does not execute the "
        "program."
    ),
    known_fp=(
        "A dynamic provider with a small, constant, reviewed handler "
        "is lower risk than one that reads config or remote input, "
        "but it still fires: the engine executes the handler either "
        "way and the closure still lands in state. Suppress per "
        "file with a one-line rationale when the handler is audited "
        "and input-free.",
    ),
    incident_refs=(
        "Maps to the engine-invoked-code class: deploy-time "
        "automation that runs arbitrary handler logic with broad "
        "credentials. Because Pulumi serializes the dynamic "
        "provider's handler closure into stack state, the rule also "
        "covers the state-tampering variant where an attacker who "
        "can write the backing state injects code that the next "
        "``pulumi up`` deserializes and runs.",
    ),
    exploit_example=(
        "# Vulnerable: a dynamic provider whose create handler is\n"
        "# engine-invoked at deploy time.\n"
        "# __main__.py\n"
        "import pulumi\n"
        "from pulumi.dynamic import ResourceProvider, CreateResult\n"
        "\n"
        "class Provisioner(ResourceProvider):\n"
        "    def create(self, props):\n"
        "        # Runs on the deploy host with cloud creds. An\n"
        "        # attacker who lands a change here (or tampers with\n"
        "        # serialized state) gets code execution on the next\n"
        "        # ``pulumi up``.\n"
        "        import os\n"
        "        os.system(props['cmd'])\n"
        "        return CreateResult('id', props)\n"
        "\n"
        "# Safe: model the resource with a native provider, or a\n"
        "# reviewed component, so no arbitrary handler runs in the\n"
        "# engine. If a one-shot deploy step is genuinely needed,\n"
        "# use ``pulumi.Command`` with an argv array (see\n"
        "# PULUMI-008), not a dynamic provider handler."
    ),
)

# The dynamic-provider API by runtime. Python subclasses
# ``pulumi.dynamic.ResourceProvider``; Node / TS reference the
# ``pulumi.dynamic`` namespace.
_PATTERNS_BY_RUNTIME: dict[str, tuple[re.Pattern[str], ...]] = {
    "python": (re.compile(r"\bpulumi\.dynamic\.ResourceProvider\b"),),
    "nodejs": (re.compile(r"\bpulumi\.dynamic\b"),),
}


def check(ctx: PulumiContext) -> Finding:
    if not ctx.sources:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=(
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            ),
            description=(
                "No source files in the Pulumi project; nothing "
                "to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for source in ctx.sources:
        patterns = _PATTERNS_BY_RUNTIME.get(source.runtime)
        if not patterns:
            continue
        for pattern in patterns:
            m = pattern.search(source.text)
            if m is None:
                continue
            line_no = source.text[:m.start()].count("\n") + 1
            offenders.append(f"{source.path}:{line_no}")
            locations.append(Location(
                path=source.path,
                start_line=line_no, end_line=line_no,
            ))
            break
    passed = not offenders
    desc = (
        f"No dynamic-provider definitions across "
        f"{len(ctx.sources)} source file(s)."
        if passed else
        f"{len(offenders)} dynamic-provider definition(s) detected: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each handler is "
        f"engine-invoked during ``pulumi up`` with the "
        f"orchestrator's identity and serialized into state."
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
