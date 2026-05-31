"""Evaluate Rego policies against a parsed pipeline document by
shelling out to ``opa eval``.

The runner serializes the provider context to a JSON temp file,
invokes ``opa eval --data <policy_dir> --input <tmpfile> --format json``
with a query that collects all ``deny`` sets across matching packages,
and maps each violation back to a :class:`Finding`.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..base import Finding, Severity
from .rego_errors import OpaNotFoundError, RegoRuleError, find_opa_binary
from .rego_loader import RegoRuleMetadata


def evaluate_rego_rules(
    rules: list[RegoRuleMetadata],
    input_data: dict[str, Any],
    opa_binary: str | None = None,
) -> list[Finding]:
    """Evaluate all *rules* against *input_data* and return findings.

    One ``opa eval`` invocation covers all rules whose policy files
    share a parent directory. The query targets
    ``data.pipeline_check`` and walks the nested result tree to match
    deny-set elements back to rule metadata.
    """
    if not rules:
        return []

    opa = opa_binary or find_opa_binary()

    policy_dirs = sorted({str(Path(r.source).parent) for r in rules})
    rule_index = _build_rule_index(rules)

    all_findings: list[Finding] = []
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        )
        json.dump(input_data, tmp)
        tmp.close()

        raw_results = _invoke_opa_eval(opa, policy_dirs, tmp.name)
        all_findings = _parse_results(
            raw_results, rule_index, input_data,
        )
    finally:
        if tmp is not None:
            try:
                Path(tmp.name).unlink(missing_ok=True)
            except OSError:
                pass

    return all_findings


def _build_rule_index(
    rules: list[RegoRuleMetadata],
) -> dict[str, RegoRuleMetadata]:
    index: dict[str, RegoRuleMetadata] = {}
    for r in rules:
        index[r.rule.id] = r
        pkg = r.package_path
        if pkg:
            index[pkg.rsplit(".", 1)[-1]] = r
            index[pkg] = r
    return index


def _invoke_opa_eval(
    opa: str,
    policy_dirs: list[str],
    input_path: str,
) -> dict[str, Any]:
    cmd: list[str] = [opa, "eval"]
    for d in policy_dirs:
        cmd.extend(["--data", d])
    cmd.extend([
        "--input", input_path,
        "--format", "json",
        "data.pipeline_check",
    ])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError:
        raise OpaNotFoundError() from None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RegoRuleError(f"opa eval failed: {stderr}")

    try:
        return dict(json.loads(result.stdout))
    except (json.JSONDecodeError, TypeError) as exc:
        raise RegoRuleError(
            f"opa eval returned invalid JSON: {exc}"
        ) from exc


def _parse_results(
    raw: dict[str, Any],
    rule_index: dict[str, RegoRuleMetadata],
    input_data: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []

    result_list = raw.get("result", [])
    if not isinstance(result_list, list):
        return findings

    for entry in result_list:
        expressions = entry.get("expressions", [])
        if not isinstance(expressions, list):
            continue
        for expr in expressions:
            value = expr.get("value")
            if isinstance(value, dict):
                _walk_provider_tree(value, rule_index, input_data, findings)

    return findings


def _walk_provider_tree(
    provider_tree: dict[str, Any],
    rule_index: dict[str, RegoRuleMetadata],
    input_data: dict[str, Any],
    findings: list[Finding],
) -> None:
    for _provider_name, packages in provider_tree.items():
        if not isinstance(packages, dict):
            continue
        for pkg_name, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue
            deny_set = pkg_data.get("deny")
            if not isinstance(deny_set, list):
                continue
            meta = rule_index.get(pkg_name)
            if meta is None:
                for r_meta in rule_index.values():
                    if r_meta.package_path.endswith(f".{pkg_name}"):
                        meta = r_meta
                        break
            _process_deny_set(
                deny_set, meta, input_data, findings,
            )


def _default_resource(input_data: dict[str, Any]) -> str:
    """Best-effort resource path for a deny item that names no ``resource``.

    The doc-list providers pass a top-level ``path``. The Kubernetes path
    passes ``manifests`` (a list of ``{path, kind, name, ...}``) with no
    top-level ``path``, which otherwise defaulted every K8s rego violation
    to ``<unknown>``. Use the manifest path only when it's unambiguous (a
    single manifest, or all manifests share one path); a deny string can't
    be attributed to one of several files, so fall back to ``<unknown>``.
    """
    raw_path = input_data.get("path")
    if isinstance(raw_path, str) and raw_path:
        return raw_path
    manifests = input_data.get("manifests")
    if isinstance(manifests, list):
        paths: set[str] = set()
        for m in manifests:
            if isinstance(m, dict):
                p = m.get("path")
                if isinstance(p, str) and p:
                    paths.add(p)
        if len(paths) == 1:
            return next(iter(paths))
    return "<unknown>"


def _process_deny_set(
    deny_set: list[Any],
    meta: RegoRuleMetadata | None,
    input_data: dict[str, Any],
    findings: list[Finding],
) -> None:
    default_resource = _default_resource(input_data)

    for item in deny_set:
        if isinstance(item, str):
            msg = item
            resource = default_resource
            finding_severity = meta.rule.severity if meta else Severity.MEDIUM
        elif isinstance(item, dict):
            msg = item.get("msg", "")
            if not msg:
                continue
            resource = item.get("resource", default_resource)
            sev_override = item.get("severity")
            if sev_override and isinstance(sev_override, str):
                sev_upper = sev_override.upper()
                try:
                    finding_severity = Severity(sev_upper)
                except ValueError:
                    finding_severity = meta.rule.severity if meta else Severity.MEDIUM
            else:
                finding_severity = meta.rule.severity if meta else Severity.MEDIUM
        else:
            continue

        if meta is not None:
            finding = Finding(
                check_id=meta.rule.id,
                title=meta.rule.title,
                severity=finding_severity,
                resource=str(resource),
                description=str(msg),
                recommendation=meta.rule.recommendation,
                passed=False,
            )
            finding.cwe = list(meta.rule.cwe)
            _copy_optional_rule_meta(finding, meta)
        else:
            finding = Finding(
                check_id="REGO-000",
                title="Rego policy violation",
                severity=finding_severity,
                resource=str(resource),
                description=str(msg),
                recommendation="",
                passed=False,
            )

        findings.append(finding)


def make_passing_findings(
    rules: list[RegoRuleMetadata],
    deny_rule_ids: set[str],
    default_resource: str,
) -> list[Finding]:
    """Generate passing findings for rules that produced no denials."""
    findings: list[Finding] = []
    for meta in rules:
        if meta.rule.id not in deny_rule_ids:
            finding = Finding(
                check_id=meta.rule.id,
                title=meta.rule.title,
                severity=meta.rule.severity,
                resource=default_resource,
                description=f"{meta.rule.title}, no violations.",
                recommendation=meta.rule.recommendation,
                passed=True,
            )
            # Carry the same rule metadata the failing path attaches so a
            # passing finding round-trips through SARIF / --explain with its
            # CWE and incident references intact.
            finding.cwe = list(meta.rule.cwe)
            _copy_optional_rule_meta(finding, meta)
            findings.append(finding)
    return findings


def _copy_optional_rule_meta(finding: Finding, meta: RegoRuleMetadata) -> None:
    """Copy ``incident_refs`` / ``exploit_example`` from the rule onto a
    finding when both sides carry the field. Defensive so it never raises
    if either type omits the attribute."""
    refs = getattr(meta.rule, "incident_refs", None)
    if refs and hasattr(finding, "incident_refs"):
        finding.incident_refs = list(refs)
    example = getattr(meta.rule, "exploit_example", None)
    if example and hasattr(finding, "exploit_example"):
        finding.exploit_example = example


__all__ = [
    "evaluate_rego_rules",
    "make_passing_findings",
]
