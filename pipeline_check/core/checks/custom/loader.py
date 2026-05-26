"""Load YAML custom-rule files into ``(Rule, check_fn)`` pairs.

Files have the shape::

    rules:
      - id: ACME-001
        title: Container image must come from acme.io registry
        severity: HIGH
        provider: kubernetes
        description: |
          Container {{container.name}} pulls from {{container.image}}.
        recommendation: |
          Use acme.io/<team>/<image>:<tag>.
        for_each: $.workloads[*].containers[*]
        assert:
          regex:
            path: image
            pattern: "^acme\\.io/"

The loader returns two parallel structures:

  - per-provider :class:`CompiledCustomRule` lists for the
    orchestrators to pick up; and
  - a flat list of :class:`Rule` metadata so ``--explain`` and
    ``rules list`` can resolve the user's rule like a built-in.

A failed validation raises :class:`CustomRuleError` with a message
that points at the offending file, rule index, and field.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..._yaml_strict import safe_load_strict
from ..base import Finding, Severity
from ..rule import Rule
from .evaluator import CompiledRule, PredicateError, compile_rule_body
from .rego_loader import LoadedRegoRules, RegoRuleMetadata

# Providers that custom rules can target. AWS / Terraform / CFN /
# Dockerfile have shapes that don't fit the dict-tree DSL and are
# excluded here. Helm rules are written as ``provider: kubernetes``
# because Helm reuses the K8s rule pack.
ALLOWED_PROVIDERS: frozenset[str] = frozenset({
    "github", "gitlab", "bitbucket", "azure", "circleci", "cloudbuild",
    "kubernetes",
})

ALLOWED_SEVERITIES: frozenset[str] = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
})

# IDs must be 2–10 uppercase alphanumeric chars, dash, then 3 digits.
# Matches the built-in convention (``GHA-001``, ``K8S-007``) so the
# rest of the tool's reports / sorting / SARIF rules don't need
# special-cased parsing for custom IDs.
ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{3}$")


class CustomRuleError(ValueError):
    """Raised when a custom-rule file fails validation."""


@dataclass(frozen=True, slots=True)
class CompiledCustomRule:
    """A loaded custom rule, ready to plug into a provider orchestrator."""

    rule: Rule
    provider: str
    body: CompiledRule
    #: Source file the rule came from, for diagnostics.
    source: str


@dataclass(slots=True)
class LoadedCustomRules:
    """Aggregated load result, grouped by provider."""

    by_provider: dict[str, list[CompiledCustomRule]] = field(
        default_factory=dict,
    )
    #: Rego rules grouped by provider. Parallel to ``by_provider``.
    rego_by_provider: dict[str, list[RegoRuleMetadata]] = field(
        default_factory=dict,
    )
    #: Flat list of every loaded rule's metadata. Used by ``--explain``.
    rules: list[Rule] = field(default_factory=list)
    #: Source files actually loaded.
    sources: list[str] = field(default_factory=list)

    def merge_rego(self, rego: LoadedRegoRules) -> None:
        """Merge loaded Rego rules into this aggregate."""
        for provider, metas in rego.by_provider.items():
            self.rego_by_provider.setdefault(provider, []).extend(metas)
        self.rules.extend(rego.rules)
        self.sources.extend(rego.sources)


def load_custom_rules(
    paths: list[str] | tuple[str, ...] | None,
    builtin_ids: set[str] | None = None,
) -> LoadedCustomRules:
    """Load every YAML rule file under each entry in *paths*.

    A path may be a file or a directory. Directories are walked
    recursively for ``*.yml`` / ``*.yaml`` files. Loading is
    fail-fast: the first malformed rule aborts the load with a
    :class:`CustomRuleError` rather than silently skipping it.

    *builtin_ids* is the set of every built-in check ID; passing it
    in lets the loader reject IDs that would shadow a built-in. The
    caller (the Scanner) collects this from the rule registries
    before constructing the loader.
    """
    out = LoadedCustomRules()
    if not paths:
        return out
    builtin = builtin_ids or set()
    seen_ids: dict[str, str] = {}  # id -> source file (for collision msg)
    for raw in paths:
        for file_path in _iter_rule_files(raw):
            try:
                text = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                # Wrap into the loader's own error type so callers
                # get the same "fail-fast with a file-pointing message"
                # contract that the YAML / validation errors below
                # already obey. The bare ``OSError`` /
                # ``UnicodeDecodeError`` used to escape raw, which made
                # the cause hard to triage from the operator's POV.
                raise CustomRuleError(
                    f"{file_path}: read error: {exc}"
                ) from exc
            try:
                data = safe_load_strict(text)
            except yaml.YAMLError as exc:
                raise CustomRuleError(
                    f"{file_path}: YAML parse error: {exc}"
                ) from exc
            for rule, provider, body in _compile_file(file_path, data):
                if rule.id in builtin:
                    raise CustomRuleError(
                        f"{file_path}: rule id {rule.id!r} collides with "
                        f"a built-in check. Pick a different prefix "
                        f"(e.g. ACME-001) so custom rules don't shadow "
                        f"the built-in catalog."
                    )
                if rule.id in seen_ids:
                    raise CustomRuleError(
                        f"{file_path}: rule id {rule.id!r} is already "
                        f"defined in {seen_ids[rule.id]}."
                    )
                seen_ids[rule.id] = str(file_path)
                compiled = CompiledCustomRule(
                    rule=rule,
                    provider=provider,
                    body=body,
                    source=str(file_path),
                )
                out.by_provider.setdefault(provider, []).append(compiled)
                out.rules.append(rule)
            out.sources.append(str(file_path))
    return out


def _iter_rule_files(raw: str) -> Iterator[Path]:
    p = Path(raw)
    if not p.exists():
        raise CustomRuleError(
            f"--custom-rules path does not exist: {raw}"
        )
    if p.is_file():
        yield p
        return
    files = sorted(
        f for f in p.rglob("*")
        if f.is_file() and f.suffix.lower() in {".yml", ".yaml"}
    )
    if not files:
        raise CustomRuleError(
            f"--custom-rules path {raw}: no .yml/.yaml files found"
        )
    yield from files


def _compile_file(
    file_path: Path,
    data: Any,
) -> list[tuple[Rule, str, CompiledRule]]:
    """Validate one parsed YAML file and return its compiled rules."""
    if data is None:
        return []
    if not isinstance(data, dict):
        raise CustomRuleError(
            f"{file_path}: top-level value must be a mapping with a "
            f"'rules' key, got {type(data).__name__}"
        )
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        raise CustomRuleError(
            f"{file_path}: 'rules' must be a list, got "
            f"{type(rules_raw).__name__ if rules_raw is not None else 'missing'}"
        )
    out: list[tuple[Rule, str, CompiledRule]] = []
    for idx, raw in enumerate(rules_raw):
        if not isinstance(raw, dict):
            raise CustomRuleError(
                f"{file_path}: rules[{idx}] must be a mapping, got "
                f"{type(raw).__name__}"
            )
        rule, provider, body = _compile_one(file_path, idx, raw)
        out.append((rule, provider, body))
    return out


_REQUIRED_FIELDS = (
    "id", "title", "severity", "provider", "for_each", "assert", "description",
)


def _compile_one(
    file_path: Path,
    idx: int,
    raw: dict[str, Any],
) -> tuple[Rule, str, CompiledRule]:
    where = f"{file_path}: rules[{idx}]"
    missing = [k for k in _REQUIRED_FIELDS if k not in raw]
    if missing:
        raise CustomRuleError(
            f"{where}: missing required field(s): {', '.join(missing)}"
        )

    rule_id = _expect_str(raw, "id", where)
    if not ID_RE.match(rule_id):
        raise CustomRuleError(
            f"{where}: id {rule_id!r} must match {ID_RE.pattern} "
            f"(e.g. 'ACME-001'). Lift the prefix to your org/team "
            f"so custom IDs are unambiguous in reports."
        )

    title = _expect_str(raw, "title", where)
    severity_str = _expect_str(raw, "severity", where).upper()
    if severity_str not in ALLOWED_SEVERITIES:
        raise CustomRuleError(
            f"{where}: severity {severity_str!r} must be one of "
            f"{sorted(ALLOWED_SEVERITIES)}"
        )
    severity = Severity(severity_str)

    provider = _expect_str(raw, "provider", where).lower()
    if provider not in ALLOWED_PROVIDERS:
        raise CustomRuleError(
            f"{where}: provider {provider!r} must be one of "
            f"{sorted(ALLOWED_PROVIDERS)}. Custom rules are not "
            f"supported on this provider in this release."
        )

    for_each = _expect_str(raw, "for_each", where)
    description = _expect_str(raw, "description", where)
    assert_spec = raw["assert"]
    recommendation = raw.get("recommendation", "")
    if not isinstance(recommendation, str):
        raise CustomRuleError(
            f"{where}: recommendation must be a string"
        )

    docs_note = raw.get("docs_note", "")
    if not isinstance(docs_note, str):
        raise CustomRuleError(f"{where}: docs_note must be a string")

    cwe = _expect_string_list(raw, "cwe", where)
    owasp = _expect_string_list(raw, "owasp", where)
    esf = _expect_string_list(raw, "esf", where)

    try:
        body = compile_rule_body(for_each, assert_spec, description)
    except PredicateError as exc:
        raise CustomRuleError(f"{where}: {exc}") from exc

    rule = Rule(
        id=rule_id,
        title=title,
        severity=severity,
        owasp=tuple(owasp),
        esf=tuple(esf),
        cwe=tuple(cwe),
        recommendation=recommendation,
        docs_note=docs_note,
    )
    return rule, provider, body


def _expect_str(raw: dict[str, Any], key: str, where: str) -> str:
    val = raw.get(key)
    if not isinstance(val, str) or not val.strip():
        raise CustomRuleError(
            f"{where}: {key!r} must be a non-empty string, got "
            f"{type(val).__name__ if val is not None else 'missing'}"
        )
    return val


def _expect_string_list(
    raw: dict[str, Any],
    key: str,
    where: str,
) -> list[str]:
    val = raw.get(key, [])
    if val is None:
        return []
    if not isinstance(val, list):
        raise CustomRuleError(
            f"{where}: {key!r} must be a list of strings"
        )
    out: list[str] = []
    for i, item in enumerate(val):
        if not isinstance(item, str):
            raise CustomRuleError(
                f"{where}: {key}[{i}] must be a string, got "
                f"{type(item).__name__}"
            )
        out.append(item)
    return out


# ── Adapter: build the (path, doc) check_fn that orchestrators expect ──


def make_yaml_provider_check(
    compiled: CompiledCustomRule,
) -> Callable[[str, dict[str, Any]], Finding]:
    """Adapter for YAML providers (GHA, GitLab, Bitbucket, Azure, …).

    These providers call ``check(path, doc)``. We wrap the compiled
    body so it produces a Finding shaped like a built-in rule's.
    """

    def _check(path: str, doc: dict[str, Any]) -> Finding:
        passed, offenders = compiled.body.apply(doc)
        return _build_finding(compiled, path, passed, offenders)

    return _check


def make_kubernetes_check(
    compiled: CompiledCustomRule,
) -> Callable[[Any], Finding]:
    """Adapter for the kubernetes provider (also used by helm).

    K8s rules take a ``KubernetesContext`` and emit one summary
    Finding. Custom rules walk every manifest's synthesized view,
    collect offenders from each, and roll the lot into a single
    Finding the same way built-in K8s rules do.
    """
    from .k8s_view import manifest_view

    def _check(ctx: Any) -> Finding:
        all_offenders: list[str] = []
        for m in getattr(ctx, "manifests", []):
            view = manifest_view(m)
            ambient = {
                "kind": m.kind,
                "name": m.name,
                "namespace": m.namespace or "(no-namespace)",
                "path": m.source_template or m.path,
            }
            _, offenders = compiled.body.apply(view, ambient)
            for off in offenders:
                all_offenders.append(f"{m.kind}/{m.name}: {off}")
        passed = not all_offenders
        return _build_finding(
            compiled, "kubernetes/manifests", passed, all_offenders,
        )

    return _check


def _build_finding(
    compiled: CompiledCustomRule,
    resource: str,
    passed: bool,
    offenders: list[str],
) -> Finding:
    """Roll a list of offender description strings into one Finding."""
    rule = compiled.rule
    if passed:
        desc = f"{rule.title}, no offenders."
    else:
        head = ", ".join(offenders[:5])
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} offender(s): {head}{suffix}."
            if offenders else
            rule.title
        )
    return Finding(
        check_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        resource=resource,
        description=desc,
        recommendation=rule.recommendation,
        passed=passed,
    )


__all__ = [
    "ALLOWED_PROVIDERS",
    "ALLOWED_SEVERITIES",
    "CompiledCustomRule",
    "CustomRuleError",
    "LoadedCustomRules",
    "LoadedRegoRules",
    "RegoRuleMetadata",
    "load_custom_rules",
    "make_kubernetes_check",
    "make_yaml_provider_check",
]
