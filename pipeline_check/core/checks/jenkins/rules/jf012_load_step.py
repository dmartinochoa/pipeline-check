"""JF-012, `load` step must not be used for dynamic Groovy inclusion."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import LOAD_STEP_RE

RULE = Rule(
    id="JF-012",
    title="`load` step pulls Groovy from disk without integrity pin",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Move shared Groovy into a Jenkins shared library "
        "(`@Library('name@<sha>')`). Those are version-pinned and "
        "JF-001 audits them. Reserve `load` for one-off development "
        "experiments."
    ),
    docs_note=(
        "`load 'foo.groovy'` evaluates whatever exists at the path "
        "when the build runs, there's no integrity check, so a "
        "workspace mutation can swap the loaded code between runs."
    ),
    exploit_example=(
        "// Vulnerable: load evaluates whatever Groovy is at the path.\n"
        "stage('Build') {\n"
        "  steps {\n"
        "    script {\n"
        "      def helpers = load 'ci/helpers.groovy'\n"
        "      helpers.deploy()\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Attack: `load` runs the file's contents with no integrity\n"
        "// check. An earlier stage, a malicious PR, or any workspace\n"
        "// write can swap ci/helpers.groovy between checkout and load,\n"
        "// and the substituted Groovy runs on the controller/agent with\n"
        "// the build's full permissions and credentials.\n"
        "\n"
        "// Safe: move shared code into a version-pinned shared library.\n"
        "@Library('ci-helpers@<sha>') _"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    loaded = LOAD_STEP_RE.findall(jf.text)
    passed = not loaded
    desc = (
        "Pipeline does not use the `load` step to pull Groovy from disk."
        if passed else
        f"Pipeline `load`s {len(loaded)} Groovy file(s) at runtime: "
        f"{', '.join(loaded[:5])}{'…' if len(loaded) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
