"""K8S-037. ConfigMap data carries a credential-shaped literal."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.secret_shapes import (
    SECRETISH_KEY_RE,
    aws_key_in,
)
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

#: Key suffixes that make a credential-named key a *reference* to the
#: secret (a name / endpoint / URL), not the secret value itself.
_REFERENCE_KEY_SUFFIXES = (
    "_name", "_ref", "_reference", "_url", "_uri", "_endpoint",
    "_host", "_id", "_file", "_path", "_arn",
)
_URL_VALUE_RE = re.compile(r"^\s*[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def _configmap_credential_name(key: str, value: object) -> bool:
    """Whether a ConfigMap entry looks like an embedded credential by
    key name AND value shape.

    ConfigMaps routinely carry non-secret config whose key contains a
    credential word (``token_endpoint``, ``access_token_url``,
    ``secret_name``); the value there is a URL or a reference name, not
    a credential. Require the value to not be a URL and the key to not
    be a reference-suffix pointer before flagging.
    """
    if not (isinstance(value, str) and value.strip()):
        return False
    if not SECRETISH_KEY_RE.search(key):
        return False
    if key.lower().endswith(_REFERENCE_KEY_SUFFIXES):
        return False
    if _URL_VALUE_RE.match(value):
        return False
    return True

RULE = Rule(
    id="K8S-037",
    title="ConfigMap data carries a credential-shaped literal",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Move the value out of the ConfigMap. Secrets belong in "
        "``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / "
        "ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent "
        "injection). ConfigMaps are intended for non-sensitive "
        "config and are mounted into pods without the access "
        "controls Secrets carry, the ``RoleBinding`` for "
        "``configmaps:get`` is typically far broader than the one "
        "for ``secrets:get``. A credential in a ConfigMap is "
        "effectively unprotected once any pod can read the "
        "namespace's config."
    ),
    docs_note=(
        "Companion to K8S-018 (which scans Kind: Secret). Walks "
        "ConfigMap ``data`` and ``binaryData`` for AKIA-shaped "
        "AWS keys and credential-shaped key NAMES. Even when the "
        "value is a placeholder, having ``api_key: REPLACE_ME`` "
        "in a ConfigMap is a maintenance footgun, someone will "
        "fill it in and commit. RBAC scoping for ``configmaps`` "
        "is typically much broader than ``secrets``, so any "
        "credential leak via this path reaches a wider audience."
    ),
    known_fp=(
        "ConfigMaps that legitimately carry placeholder names "
        "(``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the "
        "VALUE is a format hint rather than a credential. Rename "
        "the key to avoid the credential-shaped name.",
    ),
    exploit_example=(
        "# Vulnerable: a ConfigMap with a credential-shaped\n"
        "# value. ConfigMaps are NOT encrypted at rest in etcd\n"
        "# (Secrets are, when encryption-at-rest is configured);\n"
        "# anyone with ``configmaps/get`` reads the value.\n"
        "# ``kubectl get configmap -o yaml`` exposes it; the\n"
        "# YAML committed to git leaks it to every repo reader.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: app-config, namespace: prod }\n"
        "data:\n"
        "  database_url: postgres://app:hunter2-prod-pw@db.example.com/app\n"
        "  api_token: sk_live_abc123def456ghi789\n"
        "\n"
        "# Safe: store credentials in a Secret (encrypted at\n"
        "# rest if encryption-at-rest is enabled). Reference\n"
        "# the Secret from the Pod's env via\n"
        "# ``valueFrom.secretKeyRef``. The ConfigMap carries\n"
        "# only non-secret configuration (feature flags, log\n"
        "# levels, etc.).\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: app-config, namespace: prod }\n"
        "data:\n"
        "  log_level: info\n"
        "  feature_flag_x: \"true\"\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata: { name: app-creds, namespace: prod }\n"
        "type: Opaque\n"
        "stringData:\n"
        "  database_url: postgres://app:hunter2-prod-pw@db.example.com/app\n"
        "  api_token: sk_live_abc123def456ghi789"
    ),
)


def _binary_value_text(value: Any) -> str:
    """Decode binaryData best-effort; return ``""`` on garbage."""
    import base64
    import binascii

    if not isinstance(value, str):
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "ConfigMap":
            continue
        for field, base64_encoded in (("data", False), ("binaryData", True)):
            payload = m.data.get(field)
            if not isinstance(payload, dict):
                continue
            payload_line = _line_of(payload)
            for k, v in payload.items():
                if not isinstance(k, str):
                    continue
                view = (
                    _binary_value_text(v) if base64_encoded
                    else v if isinstance(v, str) else ""
                )
                hit = False
                if aws_key_in(view):
                    offenders.append(
                        f"ConfigMap/{m.name}.{field}.{k} (AKIA-shaped value)"
                    )
                    hit = True
                elif _configmap_credential_name(k, v):
                    offenders.append(
                        f"ConfigMap/{m.name}.{field}.{k} "
                        f"(literal credential-shaped name)"
                    )
                    hit = True
                if hit:
                    locations.append(Location(
                        path=m.path, start_line=payload_line,
                        end_line=payload_line, doc_index=m.doc_index,
                    ))
    passed = not offenders
    desc = (
        "No ConfigMap manifest carries a credential-shaped literal."
        if passed else
        f"{len(offenders)} ConfigMap entr(ies) carry literal "
        f"credentials: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
