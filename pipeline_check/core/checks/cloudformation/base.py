"""CloudFormation parser, context, and base check.

Templates are either YAML (the common idiom) or JSON (the stricter
sibling). Both normalise to a flat resource list:

    [CloudFormationResource("MyRole", "AWS::IAM::Role", {"AssumeRolePolicyDocument": ...}), ...]

The YAML loader registers custom constructors for every short-form
intrinsic (``!Ref``, ``!Sub``, ``!GetAtt``, ``!Join``, ``!If``, etc.)
so they materialise as the equivalent ``Fn::`` dict. After parsing,
the document shape matches what a JSON template would have produced,
and rules operate on the same plain-dict structure regardless of the
source format.

Unresolved intrinsic values are kept as dicts like ``{"Ref": "X"}`` —
rules inspect for a literal truthy value and treat any intrinsic as
"not provably safe". This pattern mirrors cfn-lint and cfn-nag and
keeps the rules free of YAML-format branching.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck


@dataclass(frozen=True)
class CloudFormationResource:
    """A single resource extracted from a CFN template."""

    logical_id: str            # e.g. "MyCodeBuildProject"
    type: str                  # e.g. "AWS::CodeBuild::Project"
    properties: dict[str, Any] # parsed Properties block (may contain intrinsics)
    #: Resource-level attributes outside ``Properties`` — ``DeletionPolicy``,
    #: ``UpdateReplacePolicy``, ``Metadata``, ``Condition``, etc. Useful for
    #: CFN-idiomatic checks that care about lifecycle protections.
    attributes: dict[str, Any]

    @property
    def address(self) -> str:
        """Pseudo-Terraform-style address for finding.resource display."""
        return f"{self.type}.{self.logical_id}"


class CloudFormationContext:
    """Flattened, queryable view of one (or many) CFN templates."""

    def __init__(self, templates: list[tuple[str, dict[str, Any]]]) -> None:
        self._templates = templates
        self._resources: list[CloudFormationResource] = list(_iter_resources(templates))
        #: Merged ``Parameters[name].Default`` values across every template.
        #: Used by :func:`resolve_literal` to substitute ``Ref`` / ``Fn::Sub``
        #: references against the author-declared defaults. Pseudo-parameters
        #: (``AWS::Region`` et al.) are intentionally absent — they are only
        #: resolvable at stack creation and rules should skip on them.
        self._parameter_defaults: dict[str, Any] = {}
        for _path, template in templates:
            params = template.get("Parameters") or {}
            if not isinstance(params, dict):
                continue
            for name, spec in params.items():
                if not isinstance(spec, dict):
                    continue
                if "Default" in spec:
                    self._parameter_defaults[name] = spec["Default"]

    @property
    def parameter_defaults(self) -> dict[str, Any]:
        return dict(self._parameter_defaults)

    @classmethod
    def from_path(cls, path: str | Path) -> CloudFormationContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--cfn-template {root} does not exist. Pass a CloudFormation "
                f"template or a directory containing one."
            )
        if root.is_file():
            paths = [root]
        else:
            paths = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml", ".json", ".template"}
            )
        templates: list[tuple[str, dict[str, Any]]] = []
        for p in paths:
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            doc = _parse_template(text)
            if not isinstance(doc, dict):
                continue
            # Heuristic: a CFN template must have a ``Resources`` top-level
            # mapping. Anything else (cfn-lint config, SAM policies file,
            # raw data) is out of scope and skipped.
            if not isinstance(doc.get("Resources"), dict):
                continue
            templates.append((str(p), doc))
        return cls(templates)

    def resources(self, resource_type: str | None = None) -> Iterator[CloudFormationResource]:
        """Yield resources, optionally filtered by CFN ``Type``."""
        for r in self._resources:
            if resource_type is None or r.type == resource_type:
                yield r

    @property
    def files_scanned(self) -> int:
        return len(self._templates)

    @property
    def files_skipped(self) -> int:  # kept for ScanMetadata compatibility
        return 0

    @property
    def warnings(self) -> list[str]:
        return []

    def __len__(self) -> int:
        return len(self._resources)


class CloudFormationBaseCheck(BaseCheck):
    """Base class for every CloudFormation check module."""

    PROVIDER = "cloudformation"

    def __init__(self, ctx: CloudFormationContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: CloudFormationContext = ctx


# ---------------------------------------------------------------------------
# Parser — YAML loader with CFN intrinsic-tag constructors
# ---------------------------------------------------------------------------

class _CfnSafeLoader(yaml.SafeLoader):
    """SafeLoader that understands CFN's short-form intrinsics.

    Subclassed rather than modifying ``yaml.SafeLoader`` directly so
    that other YAML parsing in the codebase (workflow providers) keeps
    its strict behaviour. PyYAML looks up constructors by
    ``(loader_class, tag)`` — registering on the subclass keeps the
    effect scoped.
    """


# Short-form → ``Fn::``/``Ref`` dict, matching the JSON template shape.
_INTRINSIC_TAGS = {
    "!Ref": "Ref",
    "!Condition": "Condition",
    "!GetAtt": "Fn::GetAtt",
    "!Sub": "Fn::Sub",
    "!Join": "Fn::Join",
    "!Split": "Fn::Split",
    "!Select": "Fn::Select",
    "!FindInMap": "Fn::FindInMap",
    "!GetAZs": "Fn::GetAZs",
    "!ImportValue": "Fn::ImportValue",
    "!Base64": "Fn::Base64",
    "!Cidr": "Fn::Cidr",
    "!If": "Fn::If",
    "!Not": "Fn::Not",
    "!And": "Fn::And",
    "!Or": "Fn::Or",
    "!Equals": "Fn::Equals",
    "!Transform": "Fn::Transform",
    "!Length": "Fn::Length",
    "!ToJsonString": "Fn::ToJsonString",
    "!ForEach": "Fn::ForEach",
}


def _make_constructor(fn_key: str):
    """Build a PyYAML constructor that maps a short-form tag to ``{fn_key: value}``."""
    def _construct(loader: yaml.Loader, node: yaml.Node):
        # ``!GetAtt MyThing.Arn`` arrives as a scalar; CFN documents it
        # as a list of [LogicalId, AttributeName]. Split on the first
        # ``.`` to match the JSON-form convention.
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            if fn_key == "Fn::GetAtt" and isinstance(value, str) and "." in value:
                return {fn_key: value.split(".", 1)}
            return {fn_key: value}
        if isinstance(node, yaml.SequenceNode):
            return {fn_key: loader.construct_sequence(node, deep=True)}
        # MappingNode (rare — e.g. !Sub with variable-map form)
        return {fn_key: loader.construct_mapping(node, deep=True)}
    return _construct


for _tag, _fn in _INTRINSIC_TAGS.items():
    _CfnSafeLoader.add_constructor(_tag, _make_constructor(_fn))


def _parse_template(text: str) -> Any:
    """Parse *text* as a CFN template — JSON first (strict), YAML fallback.

    JSON templates don't contain intrinsic tags so the json path is
    both faster and safer; falling back to YAML only on failure
    avoids double-parsing the common case.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass  # fall through to YAML
    try:
        return yaml.load(text, Loader=_CfnSafeLoader)
    except yaml.YAMLError:
        return None


def _iter_resources(
    templates: list[tuple[str, dict[str, Any]]],
) -> Iterator[CloudFormationResource]:
    for _path, template in templates:
        resources = template.get("Resources") or {}
        if not isinstance(resources, dict):
            continue
        for logical_id, res in resources.items():
            if not isinstance(res, dict):
                continue
            rtype = res.get("Type")
            if not isinstance(rtype, str):
                continue
            props = res.get("Properties") or {}
            if not isinstance(props, dict):
                props = {}
            attributes = {
                k: v for k, v in res.items()
                if k not in ("Type", "Properties")
            }
            yield CloudFormationResource(
                logical_id=logical_id,
                type=rtype,
                properties=props,
                attributes=attributes,
            )


# ---------------------------------------------------------------------------
# Shared helpers used by the rule modules
# ---------------------------------------------------------------------------

def is_true(value: Any) -> bool:
    """Return True only when *value* is *provably* true.

    CFN booleans may arrive as Python ``bool``, the literal strings
    ``"true"``/``"false"``, or an unresolved intrinsic dict. A rule that
    asks "is this flag explicitly enabled?" should treat anything
    unresolved as False so the template must make the safe default
    explicit — shift-left can't wait for runtime resolution.
    """
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def is_intrinsic(value: Any) -> bool:
    """Return True when *value* is an unresolved CFN intrinsic dict."""
    if not isinstance(value, dict):
        return False
    if len(value) != 1:
        return False
    (key,) = value.keys()
    return key == "Ref" or key == "Condition" or key.startswith("Fn::")


def as_str(value: Any) -> str:
    """Return *value* rendered as a literal string, or empty for intrinsics.

    Used by rules that match on string prefixes/suffixes (image names,
    ARNs) — they should skip unresolved values rather than false-match
    on ``{"Ref": "..."}``.
    """
    return value if isinstance(value, str) else ""


_SUB_VAR_RE = __import__("re").compile(r"\$\{([A-Za-z0-9:._-]+)\}")


def resolve_literal(value: Any, parameters: dict[str, Any] | None = None) -> str | None:
    """Attempt to reduce *value* to a literal string.

    Handles the trivially-resolvable intrinsics that a static scanner
    can reason about without evaluating the stack:

    - literal ``str`` / ``bool`` / ``int`` / ``float`` → stringified
    - ``{"Ref": "ParamName"}`` → ``parameters[ParamName]`` if present
    - ``{"Fn::Sub": "no-var template"}`` → the template itself
    - ``{"Fn::Sub": "template with ${Var}"}`` → substituted if every
      ``${Var}`` resolves against *parameters* or the variable-map form
      ``{"Fn::Sub": ["template", {"Var": "value"}]}``
    - ``{"Fn::Join": [delim, [list]]}`` → joined when every list item
      resolves

    Returns ``None`` when the value is not reducible (unknown intrinsic,
    pseudo-parameter like ``AWS::Region``, or a ``Ref`` to a parameter
    with no declared ``Default``). Callers should treat ``None`` the
    same way they would treat an intrinsic today: skip, don't guess.
    """
    params = parameters or {}
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        # bool must be checked before int — bool is a subclass of int.
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, dict) or len(value) != 1:
        return None

    (key, inner), = value.items()
    if key == "Ref":
        if isinstance(inner, str) and inner in params:
            return resolve_literal(params[inner], params)
        return None
    if key == "Fn::Sub":
        return _resolve_sub(inner, params)
    if key == "Fn::Join":
        return _resolve_join(inner, params)
    # Fn::GetAtt, Fn::ImportValue, Fn::If, etc. are runtime-dependent.
    return None


def _resolve_sub(inner: Any, params: dict[str, Any]) -> str | None:
    """Resolve ``Fn::Sub`` in either string or [template, map] form."""
    if isinstance(inner, str):
        template, extra_vars = inner, {}
    elif isinstance(inner, list) and len(inner) == 2 and isinstance(inner[0], str):
        template, extra_vars = inner[0], inner[1] if isinstance(inner[1], dict) else {}
    else:
        return None

    # Pre-resolve every variable in the extra-var map; bail if any fails.
    resolved_extras: dict[str, str] = {}
    for k, v in extra_vars.items():
        r = resolve_literal(v, params)
        if r is None:
            return None
        resolved_extras[k] = r

    missing: list[str] = []

    def _sub(match):
        name = match.group(1)
        if name in resolved_extras:
            return resolved_extras[name]
        if name in params:
            r = resolve_literal(params[name], params)
            if r is not None:
                return r
        missing.append(name)
        return match.group(0)

    out = _SUB_VAR_RE.sub(_sub, template)
    if missing:
        return None
    return out


def _resolve_join(inner: Any, params: dict[str, Any]) -> str | None:
    """Resolve ``Fn::Join`` when both delimiter and list are literals."""
    if not isinstance(inner, list) or len(inner) != 2:
        return None
    delim, items = inner
    if not isinstance(delim, str) or not isinstance(items, list):
        return None
    parts: list[str] = []
    for item in items:
        part = resolve_literal(item, params)
        if part is None:
            return None
        parts.append(part)
    return delim.join(parts)
