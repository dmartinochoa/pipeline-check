"""PULUMI-008. Pulumi source spawns a shell with non-constant input."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-008",
    title="Pulumi source spawns a shell with non-constant input",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5", "CICD-SEC-3"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-94"),
    recommendation=(
        "Pulumi programs run at deployment-orchestration time, "
        "on a developer's machine or a CI runner with whatever "
        "credentials the orchestrator carries. Spawning a shell "
        "from inside the Pulumi program — especially with input "
        "derived from config, stack outputs, or environment "
        "variables — turns the program itself into a command-"
        "injection primitive: anyone who can influence the "
        "config value (a stack-config push, a promoted stack "
        "output, a CI env var) executes arbitrary shell with "
        "the orchestrator's identity.\n\n"
        "Replace shell-exec primitives with one of:\n\n"
        "* A native Pulumi resource (``aws.s3.Bucket``, "
        "``kubernetes.helm.v3.Release``) instead of "
        "``exec(\"aws s3 mb\")`` / ``exec(\"helm install\")``. "
        "Pulumi's resource model carries the desired-state + "
        "diff semantics that command-line invocation lacks.\n"
        "* For one-shot deploy-time operations that have no "
        "Pulumi resource (running a database migration), use "
        "``pulumi.Command`` (the official command-resource "
        "package) with explicit string arrays rather than "
        "concatenated shell snippets — the args array bypasses "
        "shell-interpolation entirely."
    ),
    docs_note=(
        "Scans every source file for canonical shell-exec "
        "primitives that take a single string argument "
        "(implying shell interpolation rather than argv "
        "array passing):\n\n"
        "* Node: ``child_process.exec(...)``, "
        "``child_process.execSync(...)``\n"
        "* Python: ``os.system(...)``, ``subprocess.run(..., "
        "shell=True)``, ``subprocess.Popen(..., shell=True)``\n"
        "* Go: ``exec.Command(\"sh\", \"-c\", ...)``\n"
        "* C#: ``Process.Start(\"cmd.exe\", \"/c ...\")``\n\n"
        "argv-array forms (``child_process.spawn(cmd, [args])``, "
        "``subprocess.run([cmd, *args])``) are skipped — those "
        "don't go through a shell and aren't injection "
        "primitives in the same way. The rule's focus is on "
        "the *shell* path."
    ),
    known_fp=(
        "Some deploy-time scripts legitimately use shell-exec "
        "for portability across CI runners. The right fix is "
        "to switch to argv-array forms or a Pulumi-native "
        "resource; suppress per file with a one-line "
        "rationale when the alternative is impractical.",
    ),
    incident_refs=(
        "Pattern in Pulumi programs that grew organically out "
        "of shell scripts: deployment automation logic that "
        "used to be a bash script gets ported to Pulumi by "
        "wrapping the original shell-exec calls. The Pulumi "
        "program runs with the orchestrator's identity (often "
        "broader than the original script's), so the "
        "injection-surface inheritance is amplified by the "
        "scope expansion.",
    ),
    exploit_example=(
        "// Vulnerable: shell-exec with config-derived input.\n"
        "import { execSync } from \"child_process\";\n"
        "import * as pulumi from \"@pulumi/pulumi\";\n"
        "const cfg = new pulumi.Config();\n"
        "const env = cfg.require(\"environment\");\n"
        "execSync(`./deploy.sh ${env}`);\n"
        "\n"
        "// Attack: ``pulumi config set environment "
        "\"prod; rm -rf /\"``. Next ``pulumi up`` runs the\n"
        "// concatenated string through the shell, executing the\n"
        "// destructive second command with the orchestrator's\n"
        "// privileges.\n"
        "\n"
        "// Safe: argv-array form, no shell interpolation.\n"
        "import { spawnSync } from \"child_process\";\n"
        "spawnSync(\"./deploy.sh\", [env]);\n"
        "\n"
        "// Better: native Pulumi resource.\n"
        "// (depends on what deploy.sh was doing)"
    ),
)


_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Node child_process.exec / execSync taking a single string.
    re.compile(r'\bchild_process\.exec(?:Sync)?\s*\('),
    re.compile(r'\bexecSync\s*\('),
    # Python subprocess.* with shell=True.
    re.compile(r'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True'),
    # Python os.system always shells out.
    re.compile(r'\bos\.system\s*\('),
    # Go exec.Command("sh", "-c", ...) is the canonical shell form.
    re.compile(r'exec\.Command\s*\(\s*["\'](?:sh|bash|cmd|cmd\.exe)["\']'),
    # C# Process.Start with cmd.exe and /c flag.
    re.compile(
        r'Process\.Start\s*\(\s*["\']cmd(?:\.exe)?["\']\s*,\s*["\']/c'
    ),
)


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
        for pattern in _PATTERNS:
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
        f"No shell-exec primitives across {len(ctx.sources)} "
        f"source file(s)."
        if passed else
        f"{len(offenders)} shell-exec primitive(s) detected: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each one runs "
        f"during ``pulumi up`` with the orchestrator's "
        f"identity; config-derived input becomes a command-"
        f"injection primitive."
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
