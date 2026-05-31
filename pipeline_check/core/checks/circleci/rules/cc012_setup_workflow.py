"""CC-012, setup: true enables dynamic config generation (code injection risk)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-012",
    title="Dynamic config via `setup: true` enables code injection",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94",),
    recommendation=(
        "If `setup: true` is required, restrict the setup job to a "
        "trusted branch filter and audit the generated config carefully. "
        "Ensure the continuation orb's `configuration_path` points to a "
        "checked-in file, not a dynamically generated one that could be "
        "influenced by PR content."
    ),
    docs_note=(
        "When `setup: true` is set at the top level, the config becomes "
        "a setup workflow. It generates the real pipeline config "
        "dynamically (typically via the `circleci/continuation` orb). "
        "An attacker who controls the setup job (e.g. via a malicious "
        "PR in a fork) can inject arbitrary config for all subsequent "
        "jobs, including deploy steps with production secrets."
    ),
    exploit_example=(
        "# Vulnerable: a setup workflow that builds the real config\n"
        "# dynamically from repo content.\n"
        "setup: true\n"
        "jobs:\n"
        "  generate:\n"
        "    steps:\n"
        "      - checkout\n"
        "      - run: ./scripts/make-config.sh > generated.yml\n"
        "      - continuation/continue:\n"
        "          configuration_path: generated.yml\n"
        "\n"
        "# Attack: with `setup: true`, the setup job generates the\n"
        "# pipeline that actually runs. A fork PR that edits\n"
        "# make-config.sh (or any file it reads) injects arbitrary jobs\n"
        "# into the continuation config, including deploy steps that run\n"
        "# with production context secrets, all before any human reviews\n"
        "# the PR.\n"
        "\n"
        "# Safe: continue to a checked-in, trusted config and gate the\n"
        "# setup job to a trusted branch; never derive it from PR content.\n"
        "      - continuation/continue:\n"
        "          configuration_path: .circleci/continue_config.yml"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    setup_enabled = doc.get("setup") is True
    passed = not setup_enabled
    desc = (
        "Config does not use `setup: true` (no dynamic config generation)."
        if passed else
        "Config has `setup: true`, enabling dynamic config generation. "
        "An attacker who controls the setup job can inject arbitrary "
        "pipeline config for subsequent jobs, including deploy steps "
        "with production secrets."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
