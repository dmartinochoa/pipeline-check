"""PULUMI-006. Pulumi source uses StackReference without a project
or organization guard."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-006",
    title="Pulumi source uses StackReference without project/org guard",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-6"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-1357", "CWE-345"),
    recommendation=(
        "Always pass the fully-qualified ``<org>/<project>/<stack>`` "
        "form to ``new StackReference(...)``. The 3-segment form "
        "binds the reference to a specific organization and "
        "project; a bare stack name (``\"prod\"``) resolves "
        "against whichever org/project the current Pulumi login "
        "is pointing at, which can drift between developers and "
        "across CI runners. The drift turns into a data-leakage "
        "primitive when an attacker who can influence the "
        "login binding swaps the referenced stack for one they "
        "control. The fully-qualified form also serves as the "
        "audit-trail anchor — a reviewer can grep the source "
        "for the explicit org/project pair and verify the cross-"
        "stack flow."
    ),
    docs_note=(
        "Walks every source file for ``new StackReference("
        "<arg>)`` / ``StackReference(<arg>)`` calls and inspects "
        "the literal string arg. Fires when the literal lacks "
        "two ``/`` separators (the fully-qualified form is "
        "``<org>/<project>/<stack>``).\n\n"
        "Pattern variants matched:\n\n"
        "* TypeScript / JS: ``new pulumi.StackReference(\"...\")``\n"
        "* Python: ``pulumi.StackReference(\"...\")``\n"
        "* Go: ``pulumi.NewStackReference(ctx, \"<name>\", ...)``\n"
        "* C#: ``new StackReference(\"...\")``\n\n"
        "Variable / interpolated args (``new StackReference("
        "stackName)``) are skipped — the rule can't statically "
        "decide their form without language-specific evaluation. "
        "Suppress per source file when the indirection is "
        "deliberate (e.g. the stack name is itself a "
        "config-driven value)."
    ),
    known_fp=(
        "Stack-name indirection via config (``new StackReference("
        "cfg.require(\"upstream\"))``) is invisible to this "
        "rule's static scan and won't fire. Conversely, a "
        "deliberately-bare reference for a single-org project "
        "(common in early-stage repos) trips the rule by shape; "
        "suppress per file with a one-line rationale when the "
        "org/project pair is fixed and well-known.",
    ),
    incident_refs=(
        "Pattern of cross-stack data leakage when a Pulumi login "
        "context is shared between development and a customer "
        "deployment. A bare ``new StackReference(\"prod\")`` in "
        "the consumer code resolves against whichever org the "
        "current login points at; an engineer who runs the "
        "consumer's tests under a customer login binding "
        "accidentally reads the customer's prod stack outputs "
        "into the development tree. The fully-qualified form "
        "would have raised a clear 'no such stack' error and "
        "the cross-org access would never have completed.",
    ),
    exploit_example=(
        "// Vulnerable: bare stack name; resolves against the\n"
        "// current login's default org/project.\n"
        "import * as pulumi from \"@pulumi/pulumi\";\n"
        "const upstream = new pulumi.StackReference(\"prod\");\n"
        "const dbUrl = upstream.getOutput(\"databaseUrl\");\n"
        "\n"
        "// Attack scenario: a contractor with a separate Pulumi\n"
        "// login binding runs ``pulumi up`` against this code.\n"
        "// The ``prod`` resolution lands on the contractor's\n"
        "// own org, where they've created a stack named\n"
        "// ``prod`` that exposes a chosen ``databaseUrl``. The\n"
        "// consumer code now reads attacker-controlled data into\n"
        "// downstream resources.\n"
        "\n"
        "// Safe: fully-qualified reference.\n"
        "const upstream = new pulumi.StackReference(\n"
        "    \"myorg/platform-infra/prod\"\n"
        ");\n"
        "const dbUrl = upstream.getOutput(\"databaseUrl\");\n"
        "\n"
        "// The reference is now bound to the explicit\n"
        "// myorg/platform-infra project; any other login binding\n"
        "// produces a clear 'no such stack' error rather than\n"
        "// silently substituting attacker data."
    ),
)


# Capture string literal forms across the four common runtimes.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # TypeScript / JS: new pulumi.StackReference("...")
    re.compile(
        r'new\s+(?:pulumi\.)?StackReference\s*\(\s*["\']([^"\']+)["\']'
    ),
    # Python: pulumi.StackReference("...")
    re.compile(
        r'(?:pulumi\.)?StackReference\s*\(\s*["\']([^"\']+)["\']'
    ),
    # Go: pulumi.NewStackReference(ctx, "name", ...) — second arg is
    # the stack id.
    re.compile(
        r'pulumi\.NewStackReference\s*\(\s*[^,]+,\s*["\']([^"\']+)["\']'
    ),
)


def _is_unguarded(name: str) -> bool:
    """A fully-qualified Pulumi stack name has exactly two ``/``
    separators (``<org>/<project>/<stack>``). Anything with fewer
    is a bare or partially-qualified reference."""
    return name.count("/") < 2


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
    seen: set[tuple[str, int]] = set()
    for source in ctx.sources:
        for pat in _PATTERNS:
            for m in pat.finditer(source.text):
                name = m.group(1)
                if not _is_unguarded(name):
                    continue
                line_no = source.text[:m.start()].count("\n") + 1
                if (source.path, line_no) in seen:
                    continue
                seen.add((source.path, line_no))
                offenders.append(
                    f'"{name}" at {source.path}:{line_no}'
                )
                locations.append(Location(
                    path=source.path,
                    start_line=line_no, end_line=line_no,
                ))
    passed = not offenders
    desc = (
        f"Every StackReference uses the fully-qualified "
        f"<org>/<project>/<stack> form."
        if passed else
        f"{len(offenders)} StackReference call(s) use a bare "
        f"stack name: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each resolves "
        f"against the current Pulumi login's default org / "
        f"project, which is mutable per-runner and per-engineer."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations
            else (
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            )
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
