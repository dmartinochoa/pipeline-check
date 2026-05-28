"""PULUMI-009. Pulumi.yaml runtime doesn't match any source file."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-009",
    title="Pulumi.yaml runtime does not match any source file",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Align ``Pulumi.yaml``'s ``runtime:`` declaration with "
        "the language of the source files in the project. The "
        "five recognized runtimes:\n\n"
        "* ``python`` -> ``__main__.py`` / ``*.py``\n"
        "* ``nodejs`` -> ``index.ts`` / ``index.js`` / ``*.ts``\n"
        "* ``go`` -> ``main.go`` / ``*.go``\n"
        "* ``dotnet`` -> ``Program.cs`` / ``*.cs`` / ``*.fs``\n"
        "* ``java`` -> ``*.java``\n\n"
        "A mismatch — ``runtime: python`` with TypeScript "
        "sources, or no source files matching the runtime — "
        "means ``pulumi up`` either fails outright or, worse, "
        "succeeds against an unintended entry-point file the "
        "operator didn't review. Adjusting the runtime "
        "declaration to match the actual source language is "
        "usually a one-line fix; investigate the underlying "
        "cause if the mismatch suggests deeper drift."
    ),
    docs_note=(
        "Reads ``Pulumi.yaml`` ``runtime:`` and checks whether "
        "the project root contains at least one source file "
        "matching the runtime's expected extension set. The "
        "language-extension map mirrors the recognition logic "
        "in the loader (``__main__.py``, ``index.ts``, "
        "``main.go``, ``Program.cs``, ``*.java``).\n\n"
        "Projects with multiple language directories under a "
        "single Pulumi.yaml (a rare layout) pass when at least "
        "one source matches; the rule's intent is to catch the "
        "common 'wrong runtime' case, not enforce a single-"
        "language project tree."
    ),
    known_fp=(
        "Multi-language projects where the Pulumi runtime "
        "wraps another language (a custom Pulumi component "
        "shipped in one language but invoked from another) "
        "may legitimately have a runtime declaration that "
        "doesn't match the top-level source. Suppress per "
        "project with a one-line rationale.",
    ),
    incident_refs=(
        "Pattern in repositories that migrated from one Pulumi "
        "runtime to another (e.g. Python to TypeScript) "
        "without updating Pulumi.yaml: ``pulumi up`` either "
        "fails confusingly (loader can't find a matching "
        "entry-point) or — in the worst case — silently runs "
        "against a stale entry-point file the migration left "
        "behind.",
    ),
    exploit_example=(
        "# Vulnerable: Pulumi.yaml runtime doesn't match sources.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: python\n"
        "\n"
        "# Source tree:\n"
        "$ ls\n"
        "Pulumi.yaml  index.ts  package.json  tsconfig.json\n"
        "\n"
        "# Risk: ``pulumi up`` either fails to find a Python\n"
        "# entry-point, or — if a stale __main__.py exists in\n"
        "# the directory from a prior migration — runs that\n"
        "# unreviewed entry-point instead of the intended\n"
        "# index.ts.\n"
        "\n"
        "# Safe: update runtime to match.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: nodejs"
    ),
)


_RUNTIME_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "nodejs": {".ts", ".js"},
    "go":     {".go"},
    "dotnet": {".cs", ".fs"},
    "java":   {".java"},
}


def check(ctx: PulumiContext) -> Finding:
    if not ctx.projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="Pulumi.yaml",
            description="No Pulumi.yaml in the scan path.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for project in ctx.projects:
        runtime = project.runtime.strip().lower()
        if not runtime:
            offenders.append(
                f"{project.path}: runtime declaration missing"
            )
            continue
        expected = _RUNTIME_EXTENSIONS.get(runtime)
        if expected is None:
            offenders.append(
                f"{project.path}: runtime {runtime!r} not in the "
                f"recognized set (python / nodejs / go / dotnet / "
                f"java)"
            )
            continue
        # Look for at least one source file under the project
        # whose extension matches the runtime.
        match = any(
            any(s.path.endswith(ext) for ext in expected)
            for s in ctx.sources
        )
        if not match:
            offenders.append(
                f"{project.path}: runtime is {runtime!r} but no "
                f"matching source files ({', '.join(sorted(expected))}) "
                f"were found in the project."
            )
    passed = not offenders
    desc = (
        "Every Pulumi.yaml runtime matches at least one source "
        "file in the project."
        if passed else
        f"{len(offenders)} project(s) with runtime mismatch: "
        f"{offenders[0]}{' …' if len(offenders) > 1 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=ctx.projects[0].path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
