"""ARGO-006. Literal secret values in env or parameter defaults."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name, workflow_spec

RULE = Rule(
    id="ARGO-006",
    title="Literal secret value in Argo template env or parameter default",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Mount secrets via ``env.valueFrom.secretKeyRef`` (or a "
        "``volumes:`` Secret mount) instead of writing the value "
        "into ``env.value`` or ``arguments.parameters[].value``. "
        "Workflow manifests are committed to git and cluster-readable; "
        "literal values leak through normal access paths."
    ),
    docs_note=(
        "Strong matches: AWS access keys, GitHub PATs, JWTs. Weak "
        "match: env var name suggests a secret "
        "(``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the "
        "value is a non-empty literal rather than an interpolation. "
        "Known false positives for the weak-match path: cache or "
        "partition keys (``CACHE_KEY``, ``REDIS_KEY``, "
        "``DYNAMO_PARTITION_KEY``); path variables whose name contains "
        "``_KEY_PATH`` or ``_KEY_FILE`` (``SSH_PRIVATE_KEY_PATH``); "
        "names where ``KEY`` is followed by a non-secret suffix such as "
        "``_PREFIX``, ``_INDEX``, or ``_NAME``. These are excluded by "
        "the rule logic and will not fire."
    ),
    exploit_example=(
        "# Vulnerable: the AWS access key literal lives in the\n"
        "# WorkflowTemplate manifest, committed to git and readable\n"
        "# by every namespace member with workflowtemplates: get on\n"
        "# it. ``argo logs`` echoes the value when the container\n"
        "# prints its environment; ``argo get -o yaml`` exposes it\n"
        "# directly.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "spec:\n"
        "  templates:\n"
        "    - name: upload\n"
        "      container:\n"
        "        image: aws-cli@sha256:abc123...\n"
        "        env:\n"
        "          - name: AWS_ACCESS_KEY_ID\n"
        "            value: AKIAIOSFODNN7EXAMPLE\n"
        "          - name: AWS_SECRET_ACCESS_KEY\n"
        "            value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "\n"
        "# Safe: mount the secret via ``valueFrom.secretKeyRef``.\n"
        "# The actual value lives in a Kubernetes Secret resource;\n"
        "# the template references it by name, so the manifest\n"
        "# carries no secret material.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "spec:\n"
        "  templates:\n"
        "    - name: upload\n"
        "      container:\n"
        "        image: aws-cli@sha256:abc123...\n"
        "        env:\n"
        "          - name: AWS_ACCESS_KEY_ID\n"
        "            valueFrom:\n"
        "              secretKeyRef: { name: aws-uploader, key: access_key_id }\n"
        "          - name: AWS_SECRET_ACCESS_KEY\n"
        "            valueFrom:\n"
        "              secretKeyRef: { name: aws-uploader, key: secret_access_key }"
    ),
)

_STRONG_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."),
)
# Matches env var names that contain a secret-bearing token (TOKEN, KEY, etc.)
# as a whole underscore-delimited word.  The negative lookahead prevents
# matching KEY/PRIVATE_KEY/ACCESS_KEY when they are immediately followed by a
# non-secret suffix word such as _PATH, _FILE, _DIR, _PREFIX, _SUFFIX, _INDEX,
# _NAME, _TYPE, _STORE, _RING, or _CHAIN (e.g. SSH_PRIVATE_KEY_PATH,
# S3_KEY_PREFIX).
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)s?"
    r"(?!_(?:PATH|FILE|DIR|PREFIX|SUFFIX|INDEX|NAME|TYPE|STORE|RING|CHAIN))"
    r"(?:_|$)",
    re.IGNORECASE,
)
# Names whose leading segment indicates a non-credential lookup key (cache
# keys, partition keys, checksums, etc.).  These are excluded from the
# weak-match path even when _SECRET_KEY_RE matches the trailing word.
_BENIGN_NAME_RE = re.compile(
    r"(?:^|_)(?:CACHE|PARTITION|SORT|HASH|LOOKUP|REDIS|MEMCACHE|ETAG|CHECKSUM)(?:_|$)",
    re.IGNORECASE,
)
_INTERPOLATED_RE = re.compile(r"\{\{[^}]+\}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
# Values that start with a path separator are filesystem references, not
# credentials.  Only anchor to the start of the string to avoid
# misclassifying base64-like values that happen to contain a slash
# (e.g. AWS secret access keys).
_PATH_VALUE_RE = re.compile(r"^[./]")


def _looks_like_secret(name: str, value: str) -> bool:
    v = value.strip()
    if not v or _INTERPOLATED_RE.fullmatch(v):
        return False
    for pat in _STRONG_PATTERNS:
        if pat.search(v):
            return True
    if _SECRET_KEY_RE.search(name) and not _BENIGN_NAME_RE.search(name):
        if v.lower() in {"true", "false", "none", "null", "0", "1"}:
            return False
        if len(v) < 8:
            return False
        if _PATH_VALUE_RE.search(v):
            return False
        return True
    return False


def _scan_env_list(env: Any) -> list[str]:
    if not isinstance(env, list):
        return []
    out: list[str] = []
    for item in env:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        value = item.get("value")
        if isinstance(name, str) and isinstance(value, str):
            if _looks_like_secret(name, value):
                out.append(name)
    return out


def _scan_parameters(params: Any) -> list[str]:
    if not isinstance(params, list):
        return []
    out: list[str] = []
    for p in params:
        if not isinstance(p, dict):
            continue
        name = p.get("name", "")
        for vk in ("default", "value"):
            v = p.get(vk)
            if isinstance(name, str) and isinstance(v, str):
                if _looks_like_secret(name, v):
                    out.append(f"param {name} ({vk})")
    return out


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        spec = workflow_spec(doc)
        args = spec.get("arguments")
        if isinstance(args, dict):
            for h in _scan_parameters(args.get("parameters")):
                offenders.append(f"{doc.kind}/{doc.name} arguments.{h}")
        for idx, tmpl in enumerate(iter_templates(doc)):
            inputs = tmpl.get("inputs")
            if isinstance(inputs, dict):
                for h in _scan_parameters(inputs.get("parameters")):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)} inputs.{h}"
                    )
            for container in iter_containers(tmpl):
                hits = _scan_env_list(container.get("env"))
                if hits:
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)} env: {', '.join(hits)}"
                    )
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No literal secrets in env / parameter defaults."
        if passed else
        f"{len(offenders)} literal secret-shaped value(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
