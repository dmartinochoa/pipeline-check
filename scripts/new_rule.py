#!/usr/bin/env python3
"""Scaffold a new rule module plus its test stub for a rule-pack provider.

Adding a rule by hand means creating two files with the exact import
shape and ``check`` signature the provider expects, picking the next
free ID, and then bumping a handful of deliberate drift gates. This
script does the mechanical first half: it finds the next free ID for
the provider, writes a ready-to-edit rule module under
``pipeline_check/core/checks/<provider>/rules/`` and a matching test
stub under ``tests/<provider>/``, then prints the remaining checklist.

It does NOT bump ``EXPECTED_RULE_COUNTS`` or regenerate the provider
docs. Those are intentionally deliberate steps (the framework wants a
count bump to be a conscious decision), so the scaffold prints them as
a checklist instead of doing them silently.

Usage
-----
    python scripts/new_rule.py github self_hosted_cache_poison
    python scripts/new_rule.py kubernetes hostpath_mount --severity HIGH
    python scripts/new_rule.py github fork_pr_secret --title "Fork PR reads a secret"

By default the files are printed to stdout (a dry run). Pass ``--apply``
to write them to disk.

Supported providers are the per-rule-module "rule-pack" providers. The
class-based providers (aws, terraform, cloudformation) use a different
shape and are not scaffolded here; copy an existing module under
``pipeline_check/core/checks/aws/rules/`` instead.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Providers whose ``check`` takes ``(path: str, doc: dict[str, Any])``.
_PATH_DOC = {
    "github",
    "gitlab",
    "bitbucket",
    "azure",
    "circleci",
    "cloudbuild",
    "buildkite",
}

# Providers whose ``check`` takes a single context / domain object.
# ``provider -> (param_name, type_name)`` where ``type_name`` is
# imported from the provider's ``..base`` module.
_CTX: dict[str, tuple[str, str]] = {
    "kubernetes": ("ctx", "KubernetesContext"),
    "tekton": ("ctx", "TektonContext"),
    "argo": ("ctx", "ArgoContext"),
    "argocd": ("ctx", "ArgoCDContext"),
    "helm": ("ctx", "HelmContext"),
    "jenkins": ("jf", "Jenkinsfile"),
    "drone": ("pipeline", "Pipeline"),
    "dockerfile": ("df", "Dockerfile"),
    "oci": ("manifest", "OCIManifest"),
}

SUPPORTED = _PATH_DOC | set(_CTX)

_SLUG_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Sentinel-token templates. We use ``<<TOKEN>>`` placeholders and a
# plain ``str.replace`` so the literal ``{ }`` of the generated
# f-strings need no escaping.
_MODULE_TEMPLATE = '''\
"""<<RULE_ID>>. <<TITLE>>."""

<<IMPORTS>>

RULE = Rule(
    id="<<RULE_ID>>",
    title="<<TITLE>>",
    severity=Severity.<<SEVERITY>>,
    recommendation="TODO: one-paragraph remediation shown in every finding and the provider doc.",
    docs_note="TODO: longer prose for the provider reference page on when this rule fires.",
)


def check(<<SIG>>) -> Finding:
    # TODO: implement the detection. This stub returns a passing finding
    # so the rule is discoverable and wired into the orchestrator.
    # Collect offenders, flip ``passed``, write a real ``description``.
    # See docs/contributing_first_rule.md.
    offenders: list[str] = []
    passed = not offenders
    # ``RULE.finding`` fills check_id / title / severity / recommendation
    # from RULE; pass any other Finding field as a keyword (locations=,
    # job_anchors=, ...). Use RULE.fail_finding / RULE.pass_finding when
    # ``passed`` is fixed.
    return RULE.finding(
        <<RESOURCE>>,
        "No issue detected." if passed else f"{len(offenders)} offenders: {', '.join(offenders[:5])}",
        passed=passed,
    )
'''

_TEST_TEMPLATE = '''\
"""Tests for <<RULE_ID>>. Scaffolded by scripts/new_rule.py.

Implement the two behavioral cases below and remove the skips before
opening the PR. See docs/contributing_first_rule.md.
"""

import pytest

from <<MODULE_FQN>> import RULE, check


class <<CLASS_NAME>>:
    def test_metadata(self):
        assert RULE.id == "<<RULE_ID>>"
        assert callable(check)

    def test_fails_on_insecure(self):
        # TODO: build input that TRIGGERS <<RULE_ID>> and assert ``not f.passed``.
        # The provider test dir exposes ``run_check`` via .conftest, e.g.:
        #     from .conftest import run_check
        #     f = run_check(INSECURE_SNIPPET, "<<RULE_ID>>")
        #     assert not f.passed
        pytest.skip("scaffolded: implement the failing case")

    def test_passes_on_secure(self):
        # TODO: build input that does NOT trigger <<RULE_ID>> and assert ``f.passed``.
        pytest.skip("scaffolded: implement the passing case")
'''


def _imports_block(provider: str) -> str:
    """The import lines for a rule module in *provider*."""
    if provider in _PATH_DOC:
        # ``Any`` is needed for the ``doc: dict[str, Any]`` annotation.
        return (
            "from __future__ import annotations\n"
            "\n"
            "from typing import Any\n"
            "\n"
            "from ...base import Finding, Severity\n"
            "from ...rule import Rule"
        )
    _param, type_name = _CTX[provider]
    return (
        "from __future__ import annotations\n"
        "\n"
        "from ...base import Finding, Severity\n"
        "from ...rule import Rule\n"
        f"from ..base import {type_name}"
    )


def _signature(provider: str) -> str:
    if provider in _PATH_DOC:
        return "path: str, doc: dict[str, Any]"
    param, type_name = _CTX[provider]
    return f"{param}: {type_name}"


def _resource_expr(provider: str) -> str:
    """A valid ``resource=`` expression for the stub finding.

    Path/doc providers carry the file path; context providers get a
    literal placeholder the contributor is expected to refine.
    """
    if provider in _PATH_DOC:
        return "path"
    return f'"{provider}"'


def _rules_fqn(provider: str) -> str:
    return f"pipeline_check.core.checks.{provider}.rules"


def _ruff_format(paths: list[Path]) -> None:
    """Normalize the written files with ruff (best-effort).

    The templates are already in ruff's canonical form, but running the
    formatter guarantees the freshly-written files pass the
    ``ruff format --check`` gate even if a future template edit drifts.
    Silently skipped if ruff is not installed.
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "ruff", "format", *[str(p) for p in paths]],
            check=False,
            capture_output=True,
        )
    except (OSError, ValueError):
        pass


def _next_id(provider: str, prefix_override: str | None) -> tuple[str, str, int]:
    """Return ``(rule_id, prefix, count)`` for the next free ID.

    ``count`` is the current registry size, so the caller can print the
    post-add expected count.
    """
    # Imported lazily so the module-level ``sys.path`` tweak below runs
    # first and there is no import-not-at-top-of-file (E402) to suppress.
    sys.path.insert(0, str(_REPO_ROOT))
    from pipeline_check.core.checks.rule import discover_rules

    rules = discover_rules(_rules_fqn(provider))
    ids = [rule.id for rule, _ in rules]
    if prefix_override:
        prefix = prefix_override.upper()
    elif ids:
        prefix = Counter(rid.split("-", 1)[0] for rid in ids).most_common(1)[0][0]
    else:
        raise SystemExit(
            f"{provider}: no existing rules to infer an ID prefix from. "
            f"Pass --prefix (e.g. --prefix {provider.upper()})."
        )
    nums = [
        int(rid.split("-", 1)[1]) for rid in ids if rid.split("-", 1)[0] == prefix and rid.split("-", 1)[1].isdigit()
    ]
    next_num = max(nums) + 1 if nums else 1
    return f"{prefix}-{next_num:03d}", prefix, len(ids)


def _render(
    provider: str, rule_id: str, prefix: str, slug: str, title: str, severity: str
) -> tuple[str, str, Path, Path]:
    """Return ``(module_text, test_text, rule_path, test_path)``."""
    num3 = rule_id.split("-", 1)[1]
    file_stem = f"{prefix.lower()}{num3}_{slug}"
    class_name = f"Test{prefix}{num3}"
    module_fqn = f"{_rules_fqn(provider)}.{file_stem}"

    module = (
        _MODULE_TEMPLATE.replace("<<IMPORTS>>", _imports_block(provider))
        .replace("<<SIG>>", _signature(provider))
        .replace("<<RESOURCE>>", _resource_expr(provider))
        .replace("<<RULE_ID>>", rule_id)
        .replace("<<TITLE>>", title)
        .replace("<<SEVERITY>>", severity)
    )
    test = (
        _TEST_TEMPLATE.replace("<<MODULE_FQN>>", module_fqn)
        .replace("<<CLASS_NAME>>", class_name)
        .replace("<<RULE_ID>>", rule_id)
    )
    rule_path = _REPO_ROOT / "pipeline_check" / "core" / "checks" / provider / "rules" / f"{file_stem}.py"
    test_path = _REPO_ROOT / "tests" / provider / f"test_{slug}.py"
    return module, test, rule_path, test_path


def _checklist(provider: str, rule_id: str, count: int, rule_path: Path, test_path: Path) -> str:
    rel_rule = rule_path.relative_to(_REPO_ROOT).as_posix()
    rel_test = test_path.relative_to(_REPO_ROOT).as_posix()
    lines = [
        "",
        "This scaffold deliberately leaves the drift-gate bumps to you:",
        "",
        f"  1. Implement the detection in {rel_rule} and the two cases",
        f"     in {rel_test}.",
        f'  2. Set EXPECTED_RULE_COUNTS["{provider}"] = {count + 1} in',
        "     tests/test_rule_framework.py.",
    ]
    if provider in _PATH_DOC and provider != "cloudbuild":
        lines += [
            f"  3. Extend tests/fixtures/workflows/{provider}/insecure-* with a",
            "     positive trigger and bump EXPECTED_IDS in",
            "     tests/test_workflow_fixtures.py.",
        ]
    lines += [
        f"  4. Add a real-example pair (REQUIRED for workflow checks): "
        f"tests/fixtures/per_check/{provider}/{rule_id}.unsafe.<ext> and "
        f".safe.<ext>, plus a CheckCase in",
        "     tests/test_per_check_real_examples.py.",
        f"  5. Map {rule_id} to OWASP CICD-SEC controls in",
        "     pipeline_check/core/standards/data/owasp_cicd_top_10.py "
        "(MANDATORY -- every rule must be mapped). To hold the broad "
        "per-framework floors, mirror a sibling rule's controls in the "
        "other framework files the floor test flags.",
        "  6. Regenerate docs:",
        f"     python scripts/gen_provider_docs.py {provider}",
        "     python scripts/gen_standards_docs.py",
        "  7. Sync the registry-derived doc counts (README ranges + per-row",
        "     'N checks', docs/comparison.md, action.yml, the headline floors):",
        "     python scripts/sync_doc_claims.py",
        "  8. Add a CHANGELOG [Unreleased] entry.",
        "  9. Run the full gate:  python scripts/preflight.py",
        "",
        "  Note: the autodetect / config emitted-set assertions "
        "(test_cli.py, test_config.py) now derive the expected check set "
        "from the registry, so a new rule no longer needs an edit there.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scaffold a new rule module and test stub.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "provider",
        help=f"Provider slug. One of: {', '.join(sorted(SUPPORTED))}.",
    )
    parser.add_argument(
        "slug",
        help="Short lowercase slug for the rule, e.g. self_hosted_runner.",
    )
    parser.add_argument(
        "--severity",
        default="MEDIUM",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Rule severity (default: MEDIUM).",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Rule title. Defaults to a humanized form of the slug.",
    )
    parser.add_argument(
        "--prefix",
        default=None,
        help="Override the ID prefix (default: the provider's dominant prefix, e.g. GHA for github).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the files. Without it, the files are printed (dry run).",
    )
    args = parser.parse_args(argv)

    provider = args.provider.lower()
    if provider not in SUPPORTED:
        if provider in {"aws", "terraform", "cloudformation"}:
            parser.error(
                f"{provider} uses class-based checks, not the rule-pack "
                f"shape. Copy an existing module under "
                f"pipeline_check/core/checks/{provider}/rules/ instead."
            )
        parser.error(f"unknown provider {provider!r}. Supported: {', '.join(sorted(SUPPORTED))}.")

    slug = args.slug.lower()
    if not _SLUG_RE.match(slug):
        parser.error(
            "slug must be lowercase letters, digits, and underscores, starting with a letter (e.g. self_hosted_runner)."
        )

    title = args.title or slug.replace("_", " ").capitalize()
    rule_id, prefix, count = _next_id(provider, args.prefix)
    module, test, rule_path, test_path = _render(
        provider,
        rule_id,
        prefix,
        slug,
        title,
        args.severity,
    )

    if not args.apply:
        print("# DRY RUN. Pass --apply to write these files.\n")
        print(f"# {rule_path.relative_to(_REPO_ROOT).as_posix()}")
        print("# " + "-" * 68)
        print(module)
        print(f"# {test_path.relative_to(_REPO_ROOT).as_posix()}")
        print("# " + "-" * 68)
        print(test)
        print(_checklist(provider, rule_id, count, rule_path, test_path))
        return 0

    for path in (rule_path, test_path):
        if path.exists():
            print(f"refusing to overwrite existing file: {path}", file=sys.stderr)
            return 1

    rule_path.parent.mkdir(parents=True, exist_ok=True)
    test_dir = test_path.parent
    test_dir.mkdir(parents=True, exist_ok=True)
    # Match the sibling test packages, which are importable packages.
    init = test_dir / "__init__.py"
    if not init.exists():
        init.write_text("", encoding="utf-8")
    rule_path.write_text(module, encoding="utf-8")
    test_path.write_text(test, encoding="utf-8")
    _ruff_format([rule_path, test_path])

    print(f"created {rule_path.relative_to(_REPO_ROOT).as_posix()}")
    print(f"created {test_path.relative_to(_REPO_ROOT).as_posix()}")
    print(_checklist(provider, rule_id, count, rule_path, test_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
