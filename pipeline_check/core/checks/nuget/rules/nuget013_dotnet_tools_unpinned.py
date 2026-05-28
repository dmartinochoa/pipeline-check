"""NUGET-013. dotnet-tools.json entry lacks a version pin."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetContext

RULE = Rule(
    id="NUGET-013",
    title="dotnet-tools.json entry lacks a version pin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Add an explicit ``version`` field to every tool entry "
        "in ``.config/dotnet-tools.json``:\n\n"
        "    {\n"
        "      \"version\": 1,\n"
        "      \"isRoot\": true,\n"
        "      \"tools\": {\n"
        "        \"dotnet-ef\": {\n"
        "          \"version\": \"8.0.10\",\n"
        "          \"commands\": [\"dotnet-ef\"]\n"
        "        }\n"
        "      }\n"
        "    }\n\n"
        "Tools listed in the manifest are restored by "
        "``dotnet tool restore``, which executes the tool's "
        "binary on first invocation. Without a version pin, the "
        "command resolves to whatever ``nuget.org`` is currently "
        "publishing under the tool's name — including a "
        "poisoned patch release that runs in the developer's "
        "shell or the CI runner with whatever credentials those "
        "environments carry.\n\n"
        "Mirrors NUGET-001 (PackageReference floating version) "
        "but for the tool-manifest surface: tools execute on "
        "every developer's machine, while packages typically "
        "execute only when the application that consumes them "
        "runs."
    ),
    docs_note=(
        "Reads every ``.config/dotnet-tools.json`` (and root-"
        "level ``dotnet-tools.json``) under the scan path and "
        "walks the ``tools`` object. Fires for any entry whose "
        "value is either:\n\n"
        "* a dict without a ``version`` key, or\n"
        "* a dict with ``version`` set to an empty string\n\n"
        "Wildcard / range version specs (``\"*\"``, "
        "``\"8.0.*\"``) are also flagged because they resolve at "
        "restore time to the registry's current content."
    ),
    known_fp=(
        "Some templating projects emit a ``dotnet-tools.json`` "
        "with no version field so the user picks a tool version "
        "at first use. The rule still fires; suppress per file "
        "with a one-line rationale, or — better — fill in the "
        "version once the project's tool requirements stabilize.",
    ),
    incident_refs=(
        "Pattern of .NET tool-manifest compromise: a popular "
        "tool ships a poisoned patch release; every consumer "
        "running ``dotnet tool restore`` with a manifest that "
        "doesn't pin the version picks up the bad binary "
        "automatically. The binary's install hook runs in the "
        "developer's shell with their local credentials.",
    ),
    exploit_example=(
        "# Vulnerable: tool manifest with no version pin.\n"
        "# .config/dotnet-tools.json\n"
        "{\n"
        "  \"version\": 1,\n"
        "  \"isRoot\": true,\n"
        "  \"tools\": {\n"
        "    \"dotnet-ef\": {\n"
        "      \"commands\": [\"dotnet-ef\"]\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Risk: ``dotnet tool restore`` resolves dotnet-ef to\n"
        "# the latest version on nuget.org each time. A poisoned\n"
        "# patch release ships; every developer pulling the\n"
        "# manifest gets the malicious binary on the next\n"
        "# restore.\n"
        "\n"
        "# Safe: explicit version pin.\n"
        "{\n"
        "  \"version\": 1,\n"
        "  \"isRoot\": true,\n"
        "  \"tools\": {\n"
        "    \"dotnet-ef\": {\n"
        "      \"version\": \"8.0.10\",\n"
        "      \"commands\": [\"dotnet-ef\"]\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


_FLOATING_LITERALS: frozenset[str] = frozenset({"*"})


def _scan_tools_file(text: str) -> list[tuple[str, str]]:
    """Return ``(tool_name, problem)`` pairs for entries without a
    concrete version pin."""
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    tools = data.get("tools")
    if not isinstance(tools, dict):
        return []
    out: list[tuple[str, str]] = []
    for name, spec in tools.items():
        if not isinstance(name, str):
            continue
        if not isinstance(spec, dict):
            continue
        version = spec.get("version")
        if not isinstance(version, str) or not version.strip():
            out.append((name, "no version"))
            continue
        if version.strip() in _FLOATING_LITERALS:
            out.append((name, f"floating ({version!r})"))
            continue
        if version.strip().endswith("*"):
            out.append((name, f"floating ({version!r})"))
            continue
    return out


def _discover_tool_manifests(root: Path) -> list[Path]:
    """Walk ``root`` for ``dotnet-tools.json`` files. Looks at
    ``.config/dotnet-tools.json`` (canonical location) and any
    bare ``dotnet-tools.json`` at the root level (tool-manifest
    sometimes ships there in older templates)."""
    if not root.is_dir():
        return []
    out: list[Path] = []
    for path in root.rglob("dotnet-tools.json"):
        parts = path.parts
        if any(seg in parts for seg in ("bin", "obj", ".nuget")):
            continue
        out.append(path)
    return out


def check(ctx: NuGetContext) -> Finding:
    root = ctx.scan_root
    if root is None or not root.is_dir():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no scan root)",
            description=(
                "No NuGet scan root in scope; nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    manifests = _discover_tool_manifests(root)
    if not manifests:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(root),
            description=(
                "No dotnet-tools.json files found in the scan path."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for manifest in manifests:
        try:
            text = manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, problem in _scan_tools_file(text):
            offenders.append(f"{manifest}: {name} ({problem})")
    passed = not offenders
    desc = (
        f"Every dotnet-tools.json entry pins to an exact version "
        f"({len(manifests)} manifest(s) scanned)."
        if passed else
        f"{len(offenders)} dotnet-tools.json entry / entries are "
        f"not version-pinned: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``dotnet tool "
        f"restore`` resolves them to whatever nuget.org is "
        f"currently publishing."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=str(manifests[0]),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
