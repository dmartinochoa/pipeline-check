"""K8S-018, ``Secret`` stringData / data carries a credential-shaped literal."""
from __future__ import annotations

import base64
import binascii
from typing import Any

from ..._primitives.secret_shapes import AWS_KEY_RE, SECRETISH_KEY_RE
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-018",
    title="Secret stringData/data carries a credential-shaped literal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "A ``Kind: Secret`` manifest committed to git defeats every "
        "secret-management story Kubernetes claims to provide, "
        "the base64 encoding in ``data`` is *not* encryption. "
        "Replace with SealedSecrets (Bitnami), ExternalSecrets / "
        "ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent "
        "injection. If the manifest must remain in git, the only "
        "acceptable contents are placeholders that are filled in by "
        "an operator at apply time."
    ),
    docs_note=(
        "Walks both ``stringData`` (plain text) and ``data`` (base64). "
        "Base64-encoded values are decoded and checked for AKIA-shaped "
        "AWS keys. Credential-shaped key NAMES with any non-empty "
        "value are flagged regardless of encoding, even if the value "
        "is the literal placeholder ``REPLACE_ME``, having the name "
        "in the manifest is a maintenance footgun."
    ),
)


def _b64_to_text(s: str) -> str:
    """Best-effort base64 decode; return ``""`` on garbage."""
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def _value_text(value: Any, *, base64_encoded: bool) -> str:
    """Normalize ``data`` (b64) and ``stringData`` (plain) to a text view."""
    if not isinstance(value, str):
        return ""
    if base64_encoded:
        return _b64_to_text(value)
    return value


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "Secret":
            continue
        for field, base64_encoded in (("stringData", False), ("data", True)):
            payload = m.data.get(field)
            if not isinstance(payload, dict):
                continue
            payload_line = _line_of(payload)
            for k, v in payload.items():
                if not isinstance(k, str):
                    continue
                view = _value_text(v, base64_encoded=base64_encoded)
                hit = False
                if AWS_KEY_RE.search(view):
                    offenders.append(
                        f"Secret/{m.name}.{field}.{k} (AKIA-shaped value)"
                    )
                    hit = True
                elif SECRETISH_KEY_RE.search(k) and isinstance(v, str) and v.strip():
                    offenders.append(
                        f"Secret/{m.name}.{field}.{k} "
                        f"(literal credential-shaped name)"
                    )
                    hit = True
                if hit:
                    # Best-available anchor: the ``stringData:`` /
                    # ``data:`` block (per-key marks aren't tracked
                    # by the loader for nested mapping keys, but the
                    # block line still puts the reader on the right
                    # screen).
                    locations.append(Location(
                        path=m.path, start_line=payload_line,
                        end_line=payload_line, doc_index=m.doc_index,
                    ))
    passed = not offenders
    desc = (
        "No Secret manifest carries a credential-shaped literal."
        if passed else
        f"{len(offenders)} secret entr(ies) carry literal credentials: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
