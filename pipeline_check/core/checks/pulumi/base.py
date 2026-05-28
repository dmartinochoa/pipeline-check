"""Pulumi context and base check.

Static-text analysis of a Pulumi project on disk. Three document
families are loaded:

* ``Pulumi.yaml``  -- the project manifest (``name``, ``runtime``,
  ``backend.url``, ``encryptionsalt``, top-level project config).
* ``Pulumi.<stack>.yaml`` -- per-stack config files (``config:``
  block, ``secretsprovider``, ``encryptionsalt``).
* Source files in the runtime language (``__main__.py``, ``index.ts``,
  ``main.go``, ``Program.cs``, ``*.py`` / ``*.ts`` / ``*.go`` /
  ``*.cs``). The source-file family is treated as opaque text and
  audited with regex-based primitive scans (hardcoded credentials,
  wildcard IAM policies, ``StackReference`` shapes).

The text-only analysis explicitly does NOT execute the Pulumi
program or invoke the Pulumi CLI; mirrors the
no-network / no-runtime default that the rest of the IaC providers
(Terraform HCL, CloudFormation, Helm chart-supply-chain) ship with.
``--resolve-remote`` is reserved for a future extension that could
pull stack-state diffs, but the current pack is fully offline.

Parser scope
------------
* ``Pulumi.yaml`` and ``Pulumi.<stack>.yaml`` are parsed via the
  shared :func:`safe_load_yaml`. Malformed YAML lands as a warning
  on the context; the corresponding rule passes silently rather
  than failing on a parse error.
* Source files are byte-level loaded; the text is preserved on the
  :class:`PulumiSource` dataclass so individual rule modules can
  apply their own regex / lexer logic without re-reading the file.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck, safe_load_yaml

#: Project manifest filename.
PROJECT_MANIFEST = "Pulumi.yaml"
#: Per-stack manifest prefix. Pulumi stack-config files are named
#: ``Pulumi.<stack>.yaml`` (``Pulumi.dev.yaml`` /
#: ``Pulumi.prod.yaml``).
STACK_MANIFEST_PREFIX = "Pulumi."

#: Source-file extensions that map to a supported Pulumi runtime.
#: Languages absent from this set (Java, F#) are accepted by Pulumi
#: but uncommon enough that the rule pack treats their absence as a
#: deliberate scope cut rather than an oversight.
SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".ts", ".js", ".go", ".cs", ".fs", ".java",
})


# ── Dataclasses ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PulumiProject:
    """A parsed ``Pulumi.yaml`` project manifest."""

    path: str
    text: str
    name: str
    runtime: str
    #: Backend URL when explicitly configured. Pulumi defaults to the
    #: hosted ``app.pulumi.com`` service when this field is absent;
    #: rules treat the default-service case as a separate posture
    #: (safe, audited, encrypted-at-rest) from an explicit local /
    #: HTTP override.
    backend_url: str | None
    #: Full parsed body for rules needing fields beyond the
    #: structured slots above (``encryptionsalt``,
    #: ``encryptionprovider``, ``config``, ``template``).
    data: dict[str, Any] = field(default_factory=dict)
    #: ``True`` when the YAML parsed cleanly.
    parsed_ok: bool = True


@dataclass(frozen=True, slots=True)
class PulumiStack:
    """A parsed ``Pulumi.<stack>.yaml`` stack-config file."""

    path: str
    text: str
    stack_name: str
    #: ``config`` block, mapping ``<project>:<key>`` -> value. Values
    #: are either scalars (plaintext) or one-key dicts of the form
    #: ``{"secure": "<encrypted-payload>"}`` for encrypted entries.
    config: dict[str, Any] = field(default_factory=dict)
    #: ``secretsprovider`` URL when set (``passphrase`` /
    #: ``awskms://...`` / ``azurekeyvault://...`` /
    #: ``gcpkms://...`` / ``hashivault://...``).
    secrets_provider: str | None = None
    #: ``encryptionsalt`` literal when set. Presence indicates the
    #: stack uses Pulumi's passphrase-based secret encryption.
    encryption_salt: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    parsed_ok: bool = True


@dataclass(frozen=True, slots=True)
class PulumiSource:
    """A source file inside a Pulumi project root.

    The text is preserved verbatim; rule modules apply their own
    regex / lexer logic against ``text``. ``runtime`` is inferred
    from the file extension and reconciled with the project's
    ``Pulumi.yaml`` ``runtime`` setting when available; rules
    targeting a specific language check this slot before scanning.
    """

    path: str
    text: str
    #: Inferred runtime: ``"python"`` / ``"nodejs"`` / ``"go"`` /
    #: ``"dotnet"`` / ``"java"``. Falls back to ``"unknown"`` when
    #: the file extension isn't on :data:`SOURCE_EXTENSIONS`.
    runtime: str


# ── Context ───────────────────────────────────────────────────────


class PulumiContext:
    """Loaded set of Pulumi project + stack + source documents."""

    def __init__(
        self,
        projects: list[PulumiProject],
        stacks: list[PulumiStack],
        sources: list[PulumiSource],
    ) -> None:
        self.projects = projects
        self.stacks = stacks
        self.sources = sources
        self.files_scanned: int = (
            len(projects) + len(stacks) + len(sources)
        )
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> PulumiContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--pulumi-path {root} does not exist. Pass a "
                f"Pulumi.yaml file or a directory containing one."
            )
        if root.is_file():
            project_files = [root] if root.name == PROJECT_MANIFEST else []
        else:
            project_files = sorted(
                p for p in root.rglob(PROJECT_MANIFEST)
                if p.is_file()
                # Skip vendored copies / build outputs.
                and "node_modules" not in p.parts
                and ".venv" not in p.parts
                and "venv" not in p.parts
                and ".git" not in p.parts
            )

        projects: list[PulumiProject] = []
        stacks: list[PulumiStack] = []
        sources: list[PulumiSource] = []
        warnings: list[str] = []
        skipped = 0

        for project_path in project_files:
            try:
                text = project_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{project_path}: read error: {exc}")
                skipped += 1
                continue
            project = _parse_project(str(project_path), text)
            if not project.parsed_ok:
                warnings.append(
                    f"{project_path}: Pulumi.yaml parse error"
                )
                skipped += 1
                continue
            projects.append(project)

            # Per-stack manifests live in the same directory as the
            # project manifest. Glob locally to keep the load
            # bounded; a project can have many stacks but they're
            # all siblings of Pulumi.yaml by convention.
            for stack_file in project_path.parent.glob(
                f"{STACK_MANIFEST_PREFIX}*.yaml"
            ):
                if stack_file.name == PROJECT_MANIFEST:
                    continue
                try:
                    stext = stack_file.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    warnings.append(
                        f"{stack_file}: read error: {exc}"
                    )
                    skipped += 1
                    continue
                stack = _parse_stack(str(stack_file), stext)
                if not stack.parsed_ok:
                    warnings.append(
                        f"{stack_file}: Pulumi.<stack>.yaml parse error"
                    )
                    skipped += 1
                    continue
                stacks.append(stack)

            # Source files inside the project root. Skip language-
            # ecosystem dirs (node_modules, venv) and Pulumi's own
            # state cache (``.pulumi``).
            for src in _iter_source_files(project_path.parent):
                try:
                    body = src.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    warnings.append(f"{src}: read error: {exc}")
                    skipped += 1
                    continue
                sources.append(PulumiSource(
                    path=str(src), text=body,
                    runtime=_runtime_for(src),
                ))

        # If --pulumi-path pointed at a single non-Pulumi.yaml file,
        # treat it as a source file and add it to the context.
        if not project_files and root.is_file():
            try:
                body = root.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{root}: read error: {exc}")
            else:
                sources.append(PulumiSource(
                    path=str(root), text=body,
                    runtime=_runtime_for(root),
                ))

        ctx = cls(projects=projects, stacks=stacks, sources=sources)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class PulumiBaseCheck(BaseCheck[PulumiContext]):
    """Base class for Pulumi rule modules."""

    PROVIDER = "pulumi"

    def __init__(
        self, ctx: PulumiContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: PulumiContext = ctx


# ── Parsers ───────────────────────────────────────────────────────


def _parse_project(path: str, text: str) -> PulumiProject:
    try:
        data = safe_load_yaml(text)
    except Exception:
        return PulumiProject(
            path=path, text=text, name="", runtime="",
            backend_url=None, data={}, parsed_ok=False,
        )
    if not isinstance(data, dict):
        return PulumiProject(
            path=path, text=text, name="", runtime="",
            backend_url=None, data={}, parsed_ok=False,
        )
    name = data.get("name") if isinstance(data.get("name"), str) else ""
    # ``runtime`` may be a bare string (``"python"``) or a long-form
    # dict with options (``{"name": "python", "options": {...}}``).
    runtime_raw = data.get("runtime")
    runtime = ""
    if isinstance(runtime_raw, str):
        runtime = runtime_raw
    elif isinstance(runtime_raw, dict):
        rn = runtime_raw.get("name")
        if isinstance(rn, str):
            runtime = rn
    backend = data.get("backend")
    backend_url = None
    if isinstance(backend, dict):
        url = backend.get("url")
        if isinstance(url, str) and url:
            backend_url = url
    return PulumiProject(
        path=path, text=text,
        name=name or "", runtime=runtime,
        backend_url=backend_url, data=data, parsed_ok=True,
    )


def _parse_stack(path: str, text: str) -> PulumiStack:
    try:
        data = safe_load_yaml(text)
    except Exception:
        return PulumiStack(
            path=path, text=text, stack_name="", config={},
            secrets_provider=None, encryption_salt=None,
            data={}, parsed_ok=False,
        )
    if not isinstance(data, dict):
        return PulumiStack(
            path=path, text=text, stack_name="", config={},
            secrets_provider=None, encryption_salt=None,
            data={}, parsed_ok=False,
        )
    stack_name = _stack_name_from_filename(path)
    config_raw = data.get("config")
    config: dict[str, Any] = (
        config_raw if isinstance(config_raw, dict) else {}
    )
    sp_raw = data.get("secretsprovider")
    secrets_provider = sp_raw if isinstance(sp_raw, str) else None
    es_raw = data.get("encryptionsalt")
    encryption_salt = es_raw if isinstance(es_raw, str) else None
    return PulumiStack(
        path=path, text=text, stack_name=stack_name,
        config=config, secrets_provider=secrets_provider,
        encryption_salt=encryption_salt,
        data=data, parsed_ok=True,
    )


def _stack_name_from_filename(path: str) -> str:
    """Pulumi.dev.yaml -> 'dev'. Falls back to the basename when the
    convention isn't matched."""
    base = Path(path).name
    if base.startswith(STACK_MANIFEST_PREFIX) and base.endswith(".yaml"):
        return base[len(STACK_MANIFEST_PREFIX):-len(".yaml")]
    return base


def _iter_source_files(root: Path) -> Iterator[Path]:
    """Yield source files under a Pulumi project root, skipping
    language-ecosystem caches and Pulumi state."""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in SOURCE_EXTENSIONS:
            continue
        parts = p.parts
        if any(
            seg in parts
            for seg in (
                "node_modules", ".venv", "venv", ".git",
                ".pulumi", "bin", "obj", "target", "dist",
                "build", "__pycache__",
            )
        ):
            continue
        yield p


def _runtime_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in (".ts", ".js"):
        return "nodejs"
    if ext == ".go":
        return "go"
    if ext == ".cs":
        return "dotnet"
    if ext == ".fs":
        return "dotnet"
    if ext == ".java":
        return "java"
    return "unknown"


# ── Helpers exposed to rule modules ───────────────────────────────


#: Lowercased key fragments that indicate a config value should be
#: stored as a secret. Used by PULUMI-002 to flag plaintext config
#: entries whose key shape implies a credential / API token.
_SECRET_KEY_FRAGMENTS: tuple[str, ...] = (
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "private_key", "privatekey", "credential", "credentials",
    "access_key", "accesskey", "client_secret", "clientsecret",
)


def is_secret_shaped_key(key: str) -> bool:
    """Return ``True`` when ``key`` matches the curated secret-shape
    list. Case-insensitive substring match; the colon-separated
    namespace prefix (``my-project:dbPassword``) is included in the
    match so ``my-project:apiToken`` and ``apiToken`` both fire."""
    lc = key.lower()
    return any(frag in lc for frag in _SECRET_KEY_FRAGMENTS)


def is_secret_value(value: Any) -> bool:
    """Pulumi marks encrypted config entries by wrapping the value
    in ``{"secure": "<ciphertext>"}``. Plaintext entries are bare
    scalars (strings / numbers / bools). This helper returns ``True``
    only for the wrapped form."""
    return (
        isinstance(value, dict)
        and "secure" in value
        and len(value) == 1
    )
