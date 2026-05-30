"""HELM-016. values.yaml ships a default secret or credential."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-016",
    title="values.yaml ships a default secret or credential",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-258"),
    recommendation=(
        "Never ship a real password / token / key as a chart "
        "default. A credential baked into ``values.yaml`` installs "
        "into the cluster on a plain ``helm install`` (the rendered "
        "Secret carries it verbatim), and because the chart is "
        "committed and often published, the value leaks to every "
        "consumer and lives in git history indefinitely. Default "
        "the key to an empty string and require the operator to "
        "supply it (``--set`` / a values override / a sealed "
        "Secret), or reference an out-of-band Secret via an "
        "``existingSecret`` pattern. If a value must ship, make it a "
        "clearly-marked placeholder the chart refuses to run with."
    ),
    docs_note=(
        "Walks the chart's ``values.yaml`` and fires when a "
        "secret-named key (``password`` / ``passwd`` / "
        "``passphrase`` suffixes, or ``token`` / ``apiKey`` / "
        "``secretKey`` / ``privateKey`` / ``accessKey`` / "
        "``clientSecret``) carries a non-empty, non-placeholder "
        "literal value. Reference-style keys (``existingSecret``, "
        "``secretName``, ``*KeyRef``) are skipped, as are empty "
        "defaults, template / env interpolations (``{{ ... }}`` / "
        "``${...}``), ``<placeholder>`` forms, and common dummy "
        "values (``changeme``, ``password``, ``example`` …).\n\n"
        "Catches what the K8s render pass misses: when the value is "
        "consumed via ``{{ .Values.x | b64enc }}`` into a Secret, "
        "the secret material lives in the chart defaults, not the "
        "rendered manifest a Secret-detection rule would inspect."
    ),
    known_fp=(
        "A chart that defaults the key to an empty string (the "
        "operator must supply the real value) passes. A clearly-"
        "marked placeholder that matches the dummy-value list also "
        "passes. If a chart genuinely ships a throwaway credential "
        "for a local-only demo, suppress per chart with a rationale; "
        "production charts should default secrets to empty.",
    ),
    incident_refs=(
        "Default-credential class (CWE-798 / CWE-1392): shipped "
        "charts and images that install with a known baked-in "
        "password are a recurring breach vector, the attacker reads "
        "the published default and walks in.",
    ),
    exploit_example=(
        "# Vulnerable values.yaml: a real default password.\n"
        "auth:\n"
        "  rootPassword: S3cr3t-Pa55w0rd!\n"
        "  apiToken: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345\n"
        "\n"
        "# Attack: helm install renders these straight into a Secret\n"
        "# (often via `{{ .Values.auth.rootPassword | b64enc }}`),\n"
        "# so the cluster comes up with a password anyone who reads\n"
        "# the published chart already knows.\n"
        "\n"
        "# Safe: empty default; require the operator to supply it.\n"
        "auth:\n"
        "  rootPassword: \"\"\n"
        "  existingSecret: \"\"   # or reference a Secret out of band\n"
    ),
)


#: Key-name suffixes that hold a passphrase-style secret value.
_SECRET_SUFFIXES: tuple[str, ...] = ("password", "passwd", "passphrase")
#: Normalized key names that are secret values in their own right.
_SECRET_EXACT: frozenset[str] = frozenset({
    "token", "apitoken", "apikey", "secretkey", "privatekey",
    "accesskey", "secretaccesskey", "clientsecret", "authtoken",
})
#: Key fragments that mark a *reference* to a secret, not the value.
_REF_MARKERS: tuple[str, ...] = ("existing",)
_REF_SUFFIXES: tuple[str, ...] = ("name", "ref")
#: Lowercased values that are obviously placeholders, not real secrets.
_PLACEHOLDERS: frozenset[str] = frozenset({
    "changeme", "changethis", "change-me", "change_me", "changemeplease",
    "password", "passwd", "secret", "token", "example", "examplepassword",
    "xxx", "xxxx", "xxxxxx", "todo", "tbd", "placeholder", "none", "null",
    "na", "n/a", "redacted", "yourpassword", "your-password",
    "your_password", "setme", "set-me", "replaceme", "replace-me",
    "admin", "root", "test", "mysecret", "mypassword",
    "supersecret", "secretpassword", "<password>", "<secret>", "<token>",
})


def _is_secret_key(key: str) -> bool:
    norm = key.lower().replace("_", "").replace("-", "")
    if any(m in norm for m in _REF_MARKERS):
        return False
    if norm.endswith(_REF_SUFFIXES):
        return False
    if norm.endswith(_SECRET_SUFFIXES):
        return True
    return norm in _SECRET_EXACT


def _is_real_secret_value(value: Any, key: str) -> bool:
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < 4:
        return False
    if s.startswith(("${", "<")) or "{{" in s:
        return False
    low = s.lower()
    if low in _PLACEHOLDERS:
        return False
    if low == key.lower():
        return False
    return True


def _walk(node: Any, prefix: str, out: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                continue
            path = f"{prefix}.{k}" if prefix else k
            if _is_secret_key(k) and _is_real_secret_value(v, k):
                out.append(path)
            else:
                _walk(v, path, out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk(item, f"{prefix}[{i}]", out)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        if not chart.values:
            continue
        found: list[str] = []
        _walk(chart.values, "", found)
        for path in found:
            offenders.append(f"{chart.name}: {path}")
            locations.append(Location(
                path=chart.values_path or chart.chart_yaml_path,
            ))
    passed = not offenders
    desc = (
        "No chart values.yaml ships a default secret."
        if passed else
        f"{len(offenders)} default secret(s) in shipped values: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A baked-in credential "
        f"installs into the cluster on a plain ``helm install`` and "
        f"leaks to every chart consumer; default it to empty."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
