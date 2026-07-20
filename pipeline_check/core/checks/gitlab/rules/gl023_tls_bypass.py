"""GL-023. TLS / certificate verification bypass."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..._primitives import tls_bypass
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GL-023",
    title="TLS / certificate verification bypass",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-295",),
    recommendation=(
        "Remove TLS verification bypasses. Fix certificate issues at "
        "the source (install CA certificates, configure proper trust "
        "stores) instead of disabling verification."
    ),
    docs_note=(
        "Detects patterns that disable TLS certificate verification: "
        "`git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, "
        "`npm config set strict-ssl false`, `curl -k`, "
        "`wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and "
        "`GOINSECURE=`. Disabling TLS verification allows MITM injection "
        "of malicious packages, repositories, or build tools.\n\n"
        "Also inspects every `variables:` mapping (global, `workflow:`, "
        "and per-job) structurally: GitLab's idiomatic way to set an env "
        "var puts the name in the key (`NODE_TLS_REJECT_UNAUTHORIZED: "
        "\"0\"`), which a value-only text scan misses."
    ),
    exploit_example=(
        "# Vulnerable: ``npm config set strict-ssl false`` (or\n"
        "# ``git config http.sslverify false`` /\n"
        "# ``NODE_TLS_REJECT_UNAUTHORIZED=0``) disables TLS for\n"
        "# the rest of the job. A MITM swaps the registry's\n"
        "# tarballs in flight.\n"
        "install:\n"
        "  image: node@sha256:abc123...\n"
        "  script:\n"
        "    - npm config set strict-ssl false\n"
        "    - npm install\n"
        "\n"
        "# Safe: install the missing CA into the image trust\n"
        "# store; keep strict-ssl on.\n"
        "install:\n"
        "  image: node@sha256:abc123...\n"
        "  script:\n"
        "    - cp /etc/ssl/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "    - update-ca-certificates\n"
        "    - npm install"
    ),
)


def _fail_desc(hits: list[tls_bypass.TlsBypassFinding]) -> str:
    return (
        f"TLS verification bypass detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )


_blob_check = yaml_blob_check(
    RULE,
    scanner=tls_bypass.scan,
    pass_desc="No TLS verification bypass patterns detected.",
    fail_desc=_fail_desc,
    lowercase=False,
)


def _scalar(value: Any) -> str:
    """Render a GitLab variable value as a scalar for ``NAME=value``."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, dict):
        # Expanded form: ``VAR: { value: "0", description: "..." }``.
        inner = value.get("value")
        if isinstance(inner, (str, int, float, bool)):
            return _scalar(inner)
    return ""


def _variable_assignments(node: Any) -> Iterator[str]:
    """Yield ``NAME=value`` for every ``variables:`` mapping in *node*.

    Walks the whole document so global, ``workflow:``-level, and per-job
    ``variables:`` blocks are all covered. GitLab binds env vars by
    putting the name in the mapping key, which the value-only text blob
    never sees, so the ``NAME=value`` env-var patterns can't match
    without this reconstruction.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key == "variables" and isinstance(val, dict):
                for name, value in val.items():
                    if isinstance(name, str):
                        yield f"{name}={_scalar(value)}"
            yield from _variable_assignments(val)
    elif isinstance(node, list):
        for item in node:
            yield from _variable_assignments(item)


def check(path: str, doc: dict[str, Any]) -> Finding:
    base = _blob_check(path, doc)
    if not base.passed:
        return base
    # Structural pass over ``variables:`` mappings (the value-only blob
    # scan already ran above and passed, so this only adds detections
    # the key-carried env-var form would otherwise hide).
    hits = tls_bypass.scan("\n".join(_variable_assignments(doc)))
    if not hits:
        return base
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=_fail_desc(hits),
        recommendation=RULE.recommendation, passed=False,
    )
