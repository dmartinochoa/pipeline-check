"""PULUMI-005. Pulumi source declares an IAM policy with both
``Action: "*"`` and ``Resource: "*"``."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-005",
    title="Pulumi source declares an IAM policy with wildcard action + resource",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-2"),
    esf=("ESF-S-LEAST-PRIV",),
    cwe=("CWE-269", "CWE-732"),
    recommendation=(
        "Replace the wildcard policy with an explicit "
        "action + resource list. AWS' IAM Access Analyzer and "
        "Azure's RBAC review feature both surface the minimum "
        "rights a workload exercised over the last N days; the "
        "tightening pass is mechanical: copy the report's "
        "permission set into the policy document and drop the "
        "wildcards. Where the policy genuinely needs broad "
        "rights (a debugger / break-glass role), gate the "
        "policy attachment behind a separate principal that's "
        "assumed only via an explicit ``sts:AssumeRole`` (or "
        "Azure ``Conditional Access`` equivalent) with MFA and "
        "session-recording, rather than handing out the "
        "wildcards to every consumer."
    ),
    docs_note=(
        "Scans every source file in the Pulumi project root for "
        "the IAM policy-document shape that pairs a wildcard "
        "``Action`` with a wildcard ``Resource``:\n\n"
        "* ``\"Action\": \"*\"`` (or ``\"Action\": [\"*\"]``) "
        "AND\n"
        "* ``\"Resource\": \"*\"`` (or ``\"Resource\": [\"*\"]``) "
        "in the same policy statement\n\n"
        "Single-wildcard policies (just ``Action: \"*\"`` or "
        "just ``Resource: \"*\"``) are common in legitimate "
        "service-linked roles where the other axis is "
        "naturally bounded; the rule only fires when both axes "
        "are unbounded.\n\n"
        "The pattern is intentionally syntactic: it matches "
        "embedded JSON string literals (``policy.JSON.stringify"
        "({...})`` / `` policy: pulumi.all([...]).apply(...)``) "
        "rather than parsing the source language's AST. This "
        "covers the common ``new aws.iam.RolePolicy({policy: "
        "JSON.stringify(...)})`` / "
        "``aws.iam.RolePolicy(\"...\", policy=json.dumps(...))`` "
        "shapes across TypeScript, Python, Go, and C#."
    ),
    known_fp=(
        "Sandbox / playground stacks that intentionally use "
        "broad policies for short-lived experiments. The rule "
        "still fires; suppress per file with a one-line "
        "rationale and a TODO to scope the policy before any "
        "production usage. Service-linked roles published by "
        "AWS that legitimately need wildcards are usually "
        "looked up by ARN rather than declared inline, so they "
        "don't trip this matcher.",
    ),
    incident_refs=(
        "Long-running pattern in early-stage Pulumi projects: a "
        "single ``allow-everything`` policy attached during the "
        "initial bootstrap is never tightened, even after the "
        "project ships. Audit reports years later still find "
        "the same wildcard role active in production with all "
        "consumers depending on its breadth.",
    ),
    exploit_example=(
        "// Vulnerable: pulumi-side IAM policy with both axes\n"
        "// wide open.\n"
        "import * as aws from \"@pulumi/aws\";\n"
        "import * as pulumi from \"@pulumi/pulumi\";\n"
        "\n"
        "const role = new aws.iam.Role(\"deploy\", {\n"
        "    assumeRolePolicy: JSON.stringify({...}),\n"
        "});\n"
        "new aws.iam.RolePolicy(\"deploy-policy\", {\n"
        "    role: role.id,\n"
        "    policy: JSON.stringify({\n"
        "        Version: \"2012-10-17\",\n"
        "        Statement: [{\n"
        "            Effect: \"Allow\",\n"
        "            Action: \"*\",\n"
        "            Resource: \"*\",\n"
        "        }],\n"
        "    }),\n"
        "});\n"
        "\n"
        "// Risk: anyone who can assume the role (a compromised\n"
        "// CI runner, a sloppy ``sts:AssumeRole`` trust policy,\n"
        "// an over-broad SSO group binding) now has root in the\n"
        "// account.\n"
        "\n"
        "// Safe: explicit action + resource list, scoped to the\n"
        "// resources the workload actually touches.\n"
        "new aws.iam.RolePolicy(\"deploy-policy\", {\n"
        "    role: role.id,\n"
        "    policy: JSON.stringify({\n"
        "        Version: \"2012-10-17\",\n"
        "        Statement: [{\n"
        "            Effect: \"Allow\",\n"
        "            Action: [\"s3:GetObject\", \"s3:PutObject\"],\n"
        "            Resource: [\"arn:aws:s3:::my-app/*\"],\n"
        "        }],\n"
        "    }),\n"
        "});"
    ),
)


# Match a JSON policy fragment with both wildcards present anywhere in a
# window. The key quote is optional and may be single or double: real
# Pulumi source rarely double-quotes keys — TS/JS pass object literals to
# ``JSON.stringify`` with BARE keys (``Action: "*"``) and Python dict
# literals use SINGLE quotes (``{'Action': '*'}``). ``\bAction\b`` keeps
# ``myAction`` / ``Actions`` from matching the bare form. Values stay
# quoted (they survive ``JSON.stringify``). DOTALL accepts newlines
# between the two keys (the canonical multi-line IAM layout).
_ACTION_WC = r'''["']?\bAction\b["']?\s*:\s*(?:["']\*["']|\[\s*["']\*["']\s*\])'''
_RESOURCE_WC = r'''["']?\bResource\b["']?\s*:\s*(?:["']\*["']|\[\s*["']\*["']\s*\])'''
_WILDCARD_RE = re.compile(_ACTION_WC + r'.*?' + _RESOURCE_WC, re.DOTALL)
_WILDCARD_REVERSE_RE = re.compile(_RESOURCE_WC + r'.*?' + _ACTION_WC, re.DOTALL)


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
        # Limit the search window per match so a giant source file
        # with a wildcard at the top and a Resource at the bottom
        # doesn't accidentally pair them across the whole file. We
        # cap by inspecting matches of either pattern individually,
        # then verifying both shapes are within 2000 chars.
        for pat in (_WILDCARD_RE, _WILDCARD_REVERSE_RE):
            for m in pat.finditer(source.text):
                if m.end() - m.start() > 2000:
                    continue
                line_no = source.text[:m.start()].count("\n") + 1
                offenders.append(f"{source.path}:{line_no}")
                locations.append(Location(
                    path=source.path,
                    start_line=line_no, end_line=line_no,
                ))
    passed = not offenders
    desc = (
        f"No wildcard Action+Resource IAM policies across "
        f"{len(ctx.sources)} source file(s)."
        if passed else
        f"{len(offenders)} wildcard IAM policy declaration(s) "
        f"detected: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Both Action and "
        f"Resource are unbounded; anyone who can assume the "
        f"attached principal has root."
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
