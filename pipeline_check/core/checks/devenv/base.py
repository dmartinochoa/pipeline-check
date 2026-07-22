"""Developer-environment context, JSONC loader, and shared helpers.

Parses the editor / agent / container config files that auto-execute
on repo open into a flat list of :class:`WorkspaceFile` documents.
Each carries its ``kind`` (which surface it is), the parsed object,
and the raw text (for best-effort line anchoring). Rules subclass
:class:`DevEnvBaseCheck`, dispatch on ``kind``, and use the helpers
here to pull out the auto-run command strings.

These files are JSONC, not strict JSON: VS Code, devcontainer, and
Claude Code all allow ``//`` / ``/* */`` comments and trailing commas.
:func:`loads_jsonc` strips both in a string-aware pass (a ``//`` inside
a URL survives) before handing off to ``json.loads``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..._yaml_strict import safe_load_strict
from ..base import BaseCheck, Location

# ── Document kinds ───────────────────────────────────────────────────────

KIND_VSCODE_TASKS = "vscode_tasks"
KIND_VSCODE_SETTINGS = "vscode_settings"
KIND_DEVCONTAINER = "devcontainer"
KIND_CLAUDE_SETTINGS = "claude_settings"
KIND_MCP_CONFIG = "mcp_config"
KIND_ZED_SETTINGS = "zed_settings"
KIND_CONTINUE_CONFIG = "continue_config"

#: Config kinds that carry MCP server definitions the MCP rules
#: (DEV-007 / DEV-009 / DEV-010) inspect. A dedicated ``.mcp.json`` /
#: ``.cursor/mcp.json`` / ``.vscode/mcp.json`` is all MCP; Zed's
#: ``.zed/settings.json`` mixes editor settings with a
#: ``context_servers`` block, and Continue's ``.continue/`` YAML mixes
#: editor config with an ``mcpServers`` list, but the MCP rules only
#: read the server blocks so the same helpers apply.
MCP_KINDS: tuple[str, ...] = (
    KIND_MCP_CONFIG, KIND_ZED_SETTINGS, KIND_CONTINUE_CONFIG,
)

#: Top-level object keys under which the various clients declare MCP
#: servers: ``mcpServers`` (Claude / Cursor, an object; Continue, a
#: list), ``servers`` (VS Code), ``context_servers`` (Zed).
MCP_SERVER_BLOCKS: tuple[str, ...] = ("mcpServers", "servers", "context_servers")

#: devcontainer lifecycle keys that run inside the container on
#: create / attach. ``initializeCommand`` is deliberately excluded:
#: it runs on the host before the container exists and is handled by
#: its own (higher-severity) rule.
DEVCONTAINER_LIFECYCLE_KEYS: tuple[str, ...] = (
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)


@dataclass(frozen=True, slots=True)
class WorkspaceFile:
    """One parsed developer-environment config document."""

    path: str
    kind: str
    data: dict[str, Any]
    raw: str


# ── JSONC parsing ────────────────────────────────────────────────────────


def _strip_jsonc(text: str) -> str:
    """Remove ``//`` / ``/* */`` comments and trailing commas, string-aware.

    JSON string literals use double quotes, so anything between an
    unescaped pair of ``"`` is copied verbatim, a ``//`` inside a URL
    or a ``,]`` inside a string is never touched. Comments and trailing
    commas everywhere else are dropped so ``json.loads`` accepts the
    JSONC the editors emit.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                i += 1
            i += 2  # consume the closing */
            continue
        out.append(c)
        i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(s: str) -> str:
    """Drop a ``,`` that's immediately followed by ``}`` or ``]``."""
    out: list[str] = []
    i = 0
    n = len(s)
    in_str = False
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j < n and s[j] in "}]":
                i += 1  # skip the trailing comma
                continue
        out.append(c)
        i += 1
    return "".join(out)


def loads_jsonc(text: str) -> Any:
    """Parse JSONC (JSON + comments + trailing commas). May raise."""
    return json.loads(_strip_jsonc(text))


# ── Context ──────────────────────────────────────────────────────────────


def _kind_for(path: Path) -> str | None:
    """Classify a config file by its name and parent directory."""
    name = path.name
    parent = path.parent.name
    if name == "tasks.json" and parent == ".vscode":
        return KIND_VSCODE_TASKS
    if name == "settings.json" and parent == ".vscode":
        return KIND_VSCODE_SETTINGS
    if name == "devcontainer.json" or name == ".devcontainer.json":
        return KIND_DEVCONTAINER
    if name in {"settings.json", "settings.local.json"} and parent == ".claude":
        return KIND_CLAUDE_SETTINGS
    # Zed keeps its MCP servers under a ``context_servers`` block in the
    # project-level ``.zed/settings.json`` (checked before the bare
    # ``mcp.json`` names below since it shares the ``settings.json`` name).
    if name == "settings.json" and parent == ".zed":
        return KIND_ZED_SETTINGS
    # Continue: the project-level ``.continue/config.yaml`` and any
    # ``.continue/mcpServers/<name>.yaml`` block file carry an
    # ``mcpServers`` list.
    if name in {"config.yaml", "config.yml"} and parent == ".continue":
        return KIND_CONTINUE_CONFIG
    if (
        name.endswith((".yaml", ".yml"))
        and parent == "mcpServers"
        and path.parent.parent.name == ".continue"
    ):
        return KIND_CONTINUE_CONFIG
    # MCP server configs: Claude Code (``.mcp.json`` at the repo root),
    # Cursor (``.cursor/mcp.json``), VS Code (``.vscode/mcp.json``).
    if name == ".mcp.json":
        return KIND_MCP_CONFIG
    if name == "mcp.json" and parent in {".cursor", ".vscode"}:
        return KIND_MCP_CONFIG
    return None


def _discover(root: Path) -> list[Path]:
    """Return the developer-environment config files under *root*."""
    out: list[Path] = []
    candidates = [
        root / ".vscode" / "tasks.json",
        root / ".vscode" / "settings.json",
        root / ".devcontainer.json",
        root / ".devcontainer" / "devcontainer.json",
        root / ".claude" / "settings.json",
        root / ".claude" / "settings.local.json",
        root / ".mcp.json",
        root / ".cursor" / "mcp.json",
        root / ".vscode" / "mcp.json",
        root / ".zed" / "settings.json",
        root / ".continue" / "config.yaml",
        root / ".continue" / "config.yml",
    ]
    out.extend(p for p in candidates if p.is_file())
    # devcontainer supports a per-config subfolder layout:
    # ``.devcontainer/<name>/devcontainer.json``.
    dc_dir = root / ".devcontainer"
    if dc_dir.is_dir():
        out.extend(
            p for p in sorted(dc_dir.glob("*/devcontainer.json")) if p.is_file()
        )
    # Continue drops one MCP server per file under
    # ``.continue/mcpServers/<name>.yaml``.
    mcp_dir = root / ".continue" / "mcpServers"
    if mcp_dir.is_dir():
        out.extend(
            p
            for p in sorted(mcp_dir.glob("*"))
            if p.is_file() and p.suffix in {".yaml", ".yml"}
        )
    # Stable order, de-duplicated.
    seen: set[str] = set()
    unique: list[Path] = []
    for p in out:
        key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


class DevEnvContext:
    """Loaded set of developer-environment config documents."""

    def __init__(self, files: list[WorkspaceFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> DevEnvContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--devenv-path {root} does not exist. Pass a repository "
                "root, or a .vscode/tasks.json / devcontainer.json / "
                ".claude/settings.json file directly."
            )
        if root.is_file():
            paths = [root]
        else:
            paths = _discover(root)
        files: list[WorkspaceFile] = []
        warnings: list[str] = []
        skipped = 0
        for p in paths:
            kind = _kind_for(p)
            if kind is None:
                skipped += 1
                continue
            try:
                raw = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                skipped += 1
                continue
            is_yaml = p.suffix in {".yaml", ".yml"}
            try:
                data = (
                    safe_load_strict(raw) if is_yaml else loads_jsonc(raw)
                )
            except (
                json.JSONDecodeError, ValueError, RecursionError, MemoryError,
                yaml.YAMLError,
            ):
                fmt = "YAML" if is_yaml else "JSON(C)"
                warnings.append(f"could not parse {p} as {fmt}; skipped")
                skipped += 1
                continue
            if not isinstance(data, dict):
                skipped += 1
                continue
            rel = str(p)
            files.append(WorkspaceFile(path=rel, kind=kind, data=data, raw=raw))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class DevEnvBaseCheck(BaseCheck[DevEnvContext]):
    """Base class for developer-environment rule modules."""

    PROVIDER = "devenv"

    def __init__(self, ctx: DevEnvContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: DevEnvContext = ctx


# ── Command extraction helpers ───────────────────────────────────────────


def normalize_command(value: Any) -> list[str]:
    """Flatten a command value into a list of command-line strings.

    Editor / container config commands come in three shapes:

      * a string (``"npm install"``),
      * an argv array (``["npm", "install"]``, joined with spaces), and
      * a named-command object (``{"server": "...", "db": [...]}``),
        each value of which is itself a string or argv array.

    Returns one entry per resolved command line; non-string junk is
    dropped.
    """
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        parts = [v for v in value if isinstance(v, str)]
        joined = " ".join(parts).strip()
        return [joined] if joined else []
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(normalize_command(v))
        return out
    return []


def vscode_folderopen_tasks(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(label, command_line)`` for folder-open VS Code tasks."""
    out: list[tuple[str, str]] = []
    tasks = data.get("tasks")
    if not isinstance(tasks, list):
        return out
    for idx, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        run_opts = task.get("runOptions")
        run_on = run_opts.get("runOn") if isinstance(run_opts, dict) else None
        if run_on != "folderOpen":
            continue
        label = task.get("label")
        label_s = label if isinstance(label, str) and label.strip() else f"tasks[{idx}]"
        command_parts: list[str] = []
        cmd = task.get("command")
        if isinstance(cmd, str):
            command_parts.append(cmd)
        elif isinstance(cmd, list):
            command_parts.extend(c for c in cmd if isinstance(c, str))
        args = task.get("args")
        if isinstance(args, list):
            command_parts.extend(a for a in args if isinstance(a, str))
        command_line = " ".join(command_parts).strip()
        out.append((label_s, command_line))
    return out


def devcontainer_lifecycle_commands(
    data: dict[str, Any],
) -> list[tuple[str, str]]:
    """Return ``(lifecycle_key, command_line)`` for in-container hooks."""
    out: list[tuple[str, str]] = []
    for key in DEVCONTAINER_LIFECYCLE_KEYS:
        if key not in data:
            continue
        for cmd in normalize_command(data[key]):
            out.append((key, cmd))
    return out


def devcontainer_initialize_commands(data: dict[str, Any]) -> list[str]:
    """Return the host-side ``initializeCommand`` lines, if any."""
    if "initializeCommand" not in data:
        return []
    return normalize_command(data["initializeCommand"])


def claude_command_hooks(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(event, command)`` for Claude Code ``type: command`` hooks.

    Schema: ``hooks.<Event>`` is a list of matcher groups, each with a
    ``hooks`` list of ``{type, command}`` entries. Only ``command``-type
    entries run a shell; ``prompt``-type and malformed entries are
    skipped.
    """
    out: list[tuple[str, str]] = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") != "command":
                    continue
                cmd = entry.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    out.append((str(event), cmd))
    return out


def iter_mcp_specs(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(server_name, spec)`` for every MCP server in *data*.

    Walks all top-level block names (:data:`MCP_SERVER_BLOCKS`) and
    tolerates both server-block shapes:

      * a **mapping** keyed by server name (``mcpServers`` in
        Claude / Cursor, ``servers`` in VS Code, ``context_servers``
        in Zed), where each value is the spec; and
      * a **list** of spec objects each carrying its own ``name``
        (``mcpServers`` in Continue's YAML config).

    Non-object specs are dropped; a list item with no usable ``name``
    falls back to its position (``mcpServers[0]``).
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for block_key in MCP_SERVER_BLOCKS:
        block = data.get(block_key)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, dict):
                    out.append((str(name), spec))
        elif isinstance(block, list):
            for idx, spec in enumerate(block):
                if not isinstance(spec, dict):
                    continue
                raw_name = spec.get("name")
                name = (
                    raw_name if isinstance(raw_name, str) and raw_name.strip()
                    else f"{block_key}[{idx}]"
                )
                out.append((name, spec))
    return out


def _spec_command_and_args(spec: dict[str, Any]) -> tuple[str, list[str]] | None:
    """Return ``(command, args)`` for a stdio spec, or ``None``.

    Handles the flat shape (``command`` is a string, ``args`` a sibling
    array) used by Claude / Cursor / VS Code, and Zed's nested shape
    (``command`` is an object ``{path, args, env}``).
    """
    cmd = spec.get("command")
    if isinstance(cmd, dict):  # Zed nested form
        path = cmd.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        raw_args = cmd.get("args")
        args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
        return path, args
    if isinstance(cmd, str) and cmd.strip():
        raw_args = spec.get("args")
        args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
        return cmd, args
    return None


def mcp_command_servers(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(server_name, command_line)`` for every stdio MCP server.

    An MCP config maps server names to specs. A ``command``-bearing spec
    is a *stdio* server: the editor / agent launches that command as a
    local child process when the project opens. ``url``-only specs
    (``type: http`` / ``sse``) talk to a remote endpoint and don't spawn
    a local process, so they are not returned (:func:`mcp_remote_servers`
    covers those).

    All three block names (:data:`MCP_SERVER_BLOCKS`) are accepted, and
    both the flat and Zed-nested ``command`` shapes are resolved.
    """
    out: list[tuple[str, str]] = []
    for name, spec in iter_mcp_specs(data):
        resolved = _spec_command_and_args(spec)
        if resolved is None:
            continue
        cmd, args = resolved
        out.append((name, " ".join([cmd, *args]).strip()))
    return out


def mcp_remote_servers(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(server_name, url)`` for every remote (url-bearing) MCP server.

    A ``url``-bearing spec (``type: http`` / ``sse``, or a bare ``url``)
    talks to a remote endpoint rather than spawning a local process.
    DEV-007 skips these; DEV-009 inspects their transport.
    """
    out: list[tuple[str, str]] = []
    for name, spec in iter_mcp_specs(data):
        url = spec.get("url")
        if isinstance(url, str) and url.strip():
            out.append((name, url.strip()))
    return out


def mcp_blanket_auto_approvals(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(server_name, key)`` for servers that blanket auto-approve.

    A *blanket* grant removes the human-in-the-loop confirmation for
    every tool the server exposes: ``autoApprove: true`` / ``["*"]``
    (Cursor / VS Code) or ``alwaysAllow: ["*"]`` (Cline). A specific
    named-tool allow-list (``alwaysAllow: ["read_file"]``) is a scoped,
    intentional grant and is deliberately not returned.
    """
    out: list[tuple[str, str]] = []
    for name, spec in iter_mcp_specs(data):
        for key in ("autoApprove", "alwaysAllow"):
            if _is_blanket_approval(spec.get(key)):
                out.append((name, key))
                break
    return out


def _is_blanket_approval(value: Any) -> bool:
    """True for ``True``, a bare scalar ``"*"``, or a list containing one.

    A user can write the wildcard as a scalar (``alwaysAllow: "*"``) rather
    than a one-element array; both mean "auto-approve every tool".
    """
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip() == "*"
    if isinstance(value, list):
        return any(isinstance(x, str) and x.strip() == "*" for x in value)
    return False


def line_of(raw: str, needle: str) -> int | None:
    """Best-effort 1-based line of *needle* in *raw* (None if absent)."""
    if not needle:
        return None
    idx = raw.find(needle)
    if idx < 0:
        return None
    return raw.count("\n", 0, idx) + 1


def location_for(path: str, raw: str, needle: str) -> list[Location]:
    """A single best-effort :class:`Location`, or ``[]`` if not found."""
    line = line_of(raw, needle)
    if line is None:
        return []
    return [Location(path=path, start_line=line, end_line=line)]
