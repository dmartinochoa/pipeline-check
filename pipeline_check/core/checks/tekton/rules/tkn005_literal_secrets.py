"""TKN-005. Literal secret-shaped values in step env / param defaults."""
from __future__ import annotations

import re
from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, doc_location, step_name, task_steps

RULE = Rule(
    id="TKN-005",
    title="Literal secret value in Tekton step env or param default",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Mount secrets via ``env.valueFrom.secretKeyRef`` (or a "
        "``volumes:`` Secret mount) instead of writing the value "
        "into ``env.value`` or ``params[].default``. Task manifests "
        "are committed to git and cluster-readable; literal values "
        "leak through normal access paths."
    ),
    docs_note=(
        "Strong matches: AWS access keys, GitHub PATs, JWTs. Weak "
        "match: env var name suggests a secret "
        "(``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the "
        "value is a non-empty literal rather than a "
        "``$(params.X)`` / ``valueFrom`` reference."
    ),
    exploit_example=(
        "# Vulnerable: the AWS access key literal lives in the\n"
        "# Task manifest. ``kubectl get task -o yaml`` exposes it;\n"
        "# the manifest is committed to git for any repo reader.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: upload }\n"
        "spec:\n"
        "  steps:\n"
        "    - name: upload\n"
        "      image: aws-cli@sha256:abc123...\n"
        "      env:\n"
        "        - name: AWS_ACCESS_KEY_ID\n"
        "          value: AKIAIOSFODNN7EXAMPLE\n"
        "        - name: AWS_SECRET_ACCESS_KEY\n"
        "          value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "      script: aws s3 cp ./build s3://bucket/\n"
        "\n"
        "# Safe: reference a Kubernetes Secret via\n"
        "# ``valueFrom.secretKeyRef``. The Task manifest carries\n"
        "# the secret's name, not its value; the value lives in\n"
        "# the cluster's Secret store and can rotate without a\n"
        "# Task change.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: upload }\n"
        "spec:\n"
        "  steps:\n"
        "    - name: upload\n"
        "      image: aws-cli@sha256:abc123...\n"
        "      env:\n"
        "        - name: AWS_ACCESS_KEY_ID\n"
        "          valueFrom:\n"
        "            secretKeyRef: { name: aws-uploader, key: access_key_id }\n"
        "        - name: AWS_SECRET_ACCESS_KEY\n"
        "          valueFrom:\n"
        "            secretKeyRef: { name: aws-uploader, key: secret_access_key }"
    ),
)

_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|API_KEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)s?(?:_|$)",
    re.IGNORECASE,
)
_INTERPOLATED_RE = re.compile(r"\$\(?[A-Za-z_][A-Za-z0-9_.]*\)?")


def _looks_like_secret(name: str, value: str) -> bool:
    v = value.strip()
    if not v or _INTERPOLATED_RE.fullmatch(v):
        return False
    # Strong value-shape match against the shared vendor-token catalog
    # (49 detectors: AWS / GitHub / GitLab / cloud / AI provider keys,
    # JWTs, etc.) rather than a hand-maintained subset.
    if find_secret_values([v]):
        return True
    if _SECRET_KEY_RE.search(name):
        if v.lower() in {"true", "false", "none", "null", "0", "1"}:
            return False
        if len(v) < 8:
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


def _scan_params(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    params = spec.get("params")
    if not isinstance(params, list):
        return out
    for p in params:
        if not isinstance(p, dict):
            continue
        name = p.get("name", "")
        if not isinstance(name, str):
            continue
        # ``default`` is the Task/ClusterTask param shape; ``value`` is
        # the PipelineRun/TaskRun shape. Both can carry a literal secret.
        for candidate in (p.get("default"), p.get("value")):
            if isinstance(candidate, str) and _looks_like_secret(name, candidate):
                out.append(f"param {name}")
                break
    return out


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        spec = doc.data.get("spec") or {}
        if not isinstance(spec, dict):
            spec = {}
        if doc.kind in ("Task", "ClusterTask"):
            for idx, step in enumerate(task_steps(doc)):
                hits = _scan_env_list(step.get("env"))
                if hits:
                    offenders.append(
                        f"{doc.kind}/{doc.name} {step_name(step, idx)} "
                        f"env: {', '.join(hits)}"
                    )
                    locations.append(doc_location(doc, step))
            st = spec.get("stepTemplate")
            if isinstance(st, dict):
                hits = _scan_env_list(st.get("env"))
                if hits:
                    offenders.append(
                        f"{doc.kind}/{doc.name} stepTemplate env: "
                        f"{', '.join(hits)}"
                    )
                    locations.append(doc_location(doc, st))
        for h in _scan_params(spec):
            offenders.append(f"{doc.kind}/{doc.name} {h}")
            locations.append(doc_location(doc))
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Tekton documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No literal secrets in env / param defaults."
        if passed else
        f"{len(offenders)} literal secret-shaped value(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
