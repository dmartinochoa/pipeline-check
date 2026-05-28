"""PYPI-014. Custom package source in pyproject.toml uses plain HTTP."""
from __future__ import annotations

import tomllib
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile

RULE = Rule(
    id="PYPI-014",
    title="Custom package source in pyproject.toml uses plain HTTP",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-6"),
    esf=("ESF-S-TRUSTED-REG",),
    cwe=("CWE-319",),
    recommendation=(
        "Switch the source URL to HTTPS for every custom registry "
        "declared in ``pyproject.toml``. The two common shapes are:\n\n"
        "* Poetry: ``[[tool.poetry.source]]`` entries with a "
        "``url = \"http://...\"`` value.\n"
        "* uv: ``[tool.uv.sources]`` entries with an ``index = "
        "\"http://...\"`` or ``url = \"http://...\"`` value.\n"
        "* PDM: ``[[tool.pdm.source]]`` entries with a ``url = "
        "\"http://...\"`` value.\n\n"
        "Internal artifact registries (Nexus, Artifactory, devpi, "
        "private mirrors) ship with built-in HTTPS support; the "
        "switch is usually a one-line config change. After the "
        "switch, drop any ``--trusted-host`` workarounds the HTTP "
        "endpoint was hiding (see PYPI-011)."
    ),
    docs_note=(
        "Re-parses ``pyproject.toml`` and walks every custom "
        "package-source table for an HTTP URL. The Poetry, uv, "
        "and PDM source-list shapes are all covered; each one "
        "emits a separate finding per offending URL.\n\n"
        "Pairs with PYPI-003 (HTTP index URL in requirements.txt) "
        "but at the modern-resolver layer. A project that's "
        "migrated off requirements.txt to pyproject.toml + a "
        "resolver-specific source list still needs the HTTPS "
        "audit; PYPI-003 doesn't see those entries because they "
        "live in a different table."
    ),
    known_fp=(
        "Local-development mirrors running on loopback HTTP "
        "(``http://localhost:8080``) are a common workaround for "
        "offline development. The rule still fires; suppress per "
        "file with a one-line rationale naming the dev-only use. "
        "Production / CI configurations should not be suppressed.",
    ),
    incident_refs=(
        "Common MITM pattern: a CI runner installs from an "
        "internal Nexus declared in ``[[tool.poetry.source]]`` "
        "with an HTTP URL. The runner's network path is shared "
        "with other tenants (CI cluster, kubernetes namespace) "
        "that any of which can route traffic through a "
        "proxy that returns a tampered wheel. The HTTPS "
        "alternative would have caught the tampering at the "
        "TLS layer before pip ever saw the wheel content.",
    ),
    exploit_example=(
        "# Vulnerable: Poetry custom source declared over HTTP.\n"
        "# pyproject.toml\n"
        "[[tool.poetry.source]]\n"
        "name = \"corp-nexus\"\n"
        "url = \"http://nexus.corp.example/simple/\"\n"
        "priority = \"primary\"\n"
        "\n"
        "[tool.poetry.dependencies]\n"
        "internal-utils = \"^1.2.0\"\n"
        "\n"
        "# Attack: any actor on the network path between the\n"
        "# runner and ``nexus.corp.example`` can serve a tampered\n"
        "# wheel for ``internal-utils``. Poetry's fetch has no\n"
        "# TLS validation to reject the content; the wheel\n"
        "# installs.\n"
        "\n"
        "# Safe: HTTPS source.\n"
        "[[tool.poetry.source]]\n"
        "name = \"corp-nexus\"\n"
        "url = \"https://nexus.corp.example/simple/\"\n"
        "priority = \"primary\""
    ),
)


def _walk_sources(text: str) -> list[str]:
    """Return every HTTP URL declared in a Poetry / uv / PDM
    source table."""
    try:
        data: Any = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[str] = []
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return out
    # Poetry: [[tool.poetry.source]]
    poetry = tool.get("poetry")
    if isinstance(poetry, dict):
        sources = poetry.get("source")
        if isinstance(sources, list):
            for entry in sources:
                if isinstance(entry, dict):
                    url = entry.get("url")
                    if isinstance(url, str) and url.startswith("http://"):
                        out.append(url)
    # uv: [tool.uv.sources]
    uv = tool.get("uv")
    if isinstance(uv, dict):
        sources = uv.get("sources")
        if isinstance(sources, dict):
            for value in sources.values():
                if isinstance(value, dict):
                    for k in ("url", "index", "git"):
                        v = value.get(k)
                        if isinstance(v, str) and v.startswith("http://"):
                            out.append(v)
        index_url = uv.get("index-url")
        if isinstance(index_url, str) and index_url.startswith("http://"):
            out.append(index_url)
        extra = uv.get("extra-index-url")
        if isinstance(extra, list):
            for u in extra:
                if isinstance(u, str) and u.startswith("http://"):
                    out.append(u)
    # PDM: [[tool.pdm.source]]
    pdm = tool.get("pdm")
    if isinstance(pdm, dict):
        sources = pdm.get("source")
        if isinstance(sources, list):
            for entry in sources:
                if isinstance(entry, dict):
                    url = entry.get("url")
                    if isinstance(url, str) and url.startswith("http://"):
                        out.append(url)
    return out


def check(rf: RequirementsFile) -> Finding:
    if not rf.path.endswith("pyproject.toml"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "Not a pyproject.toml; custom-source HTTP audit "
                "does not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders = _walk_sources(rf.text)
    locations: list[Location] = []
    if offenders:
        line_no = 1
        for marker in ("source", "sources", "index-url"):
            if marker in rf.text:
                line_no = (
                    rf.text[:rf.text.index(marker)].count("\n") + 1
                )
                break
        locations.append(Location(
            path=rf.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No custom package sources declared over plain HTTP."
        if passed else
        f"{len(offenders)} custom package source(s) declared over "
        f"plain HTTP: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. Each URL is "
        f"vulnerable to MITM tampering on the network path."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
