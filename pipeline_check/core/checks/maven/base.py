"""Maven context and base check.

Loads ``pom.xml`` / ``settings.xml`` / ``build.gradle`` /
``build.gradle.kts`` documents from disk and exposes parsed
:class:`PomFile` objects to per-rule modules. Rule modules subclass-
free: each rule's ``check()`` takes a ``PomFile`` and returns a
``Finding``; the orchestrator runs every rule against every loaded
file.

Gradle files are read by a regex-based extractor
(:func:`_parse_gradle`) that emits the same ``PomFile`` shape from
``"group:artifact:version"`` coordinate strings, ``group:`` /
``name:`` / ``version:`` map-form deps, and ``maven { url ... }``
repository blocks. Existing ``MVN-NNN`` rules apply to Gradle
projects without per-rule changes. Variable substitution
(``${junitVersion}``) is left unresolved for the first cut — this
matches the limitation Gradle-scanning tools commonly accept and
keeps the parser deterministic without a full DSL evaluation.

Parser scope (POM)
------------------
The XML parser handles the four shapes the rule pack reasons about:

* ``<dependencies><dependency>...</dependency></dependencies>``,
  including ``<dependencyManagement>``.
* ``<repositories><repository>...``, ``<pluginRepositories>``,
  ``<distributionManagement>``.
* ``<settings><mirrors><mirror>...`` (when a settings.xml is passed).
* ``<properties>`` for ``${...}`` variable substitution in version
  literals.

XML parsing is intentionally tolerant. A malformed file is captured
as a warning on the context rather than raised; the goal is best-
effort static analysis over a repo tree.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from ..base import BaseCheck

#: Filenames the loader picks up. ``pom.xml`` is the canonical Maven
#: project descriptor; ``settings.xml`` is the per-user / per-CI Maven
#: config that carries ``<mirrors>`` and ``<servers>`` entries.
MANIFEST_NAMES: frozenset[str] = frozenset({"pom.xml"})
SETTINGS_NAMES: frozenset[str] = frozenset({"settings.xml"})
#: Gradle build script filenames. Both the Groovy DSL
#: (``build.gradle``) and Kotlin DSL (``build.gradle.kts``) are
#: recognized; the same regex-based extractor handles both because
#: the coordinate-string and ``maven {}`` shapes are syntactically
#: identical between the two dialects.
GRADLE_NAMES: frozenset[str] = frozenset({
    "build.gradle", "build.gradle.kts",
})

#: Default Maven 4 POM namespace. Stripped during parsing so rule code
#: can match unprefixed tag names.
_POM_NS = re.compile(r"^\{[^}]+\}")


@dataclass(frozen=True, slots=True)
class MavenDependency:
    """One declared dependency on a Maven artifact."""

    group_id: str
    artifact_id: str
    #: ``None`` when the dependency omits ``<version>`` (relies on
    #: ``<dependencyManagement>`` or a parent POM to resolve it).
    version: str | None
    scope: str = "compile"
    #: ``True`` when this dependency was declared inside
    #: ``<dependencyManagement>`` (version-management section, not a
    #: real dep). Rules that target *real* dependencies should skip
    #: managed entries; rules that audit version-management posture
    #: include them.
    managed: bool = False
    line_no: int = 1

    @property
    def coordinate(self) -> str:
        v = self.version or "<unmanaged>"
        return f"{self.group_id}:{self.artifact_id}:{v}"


@dataclass(frozen=True, slots=True)
class MavenRepository:
    """One ``<repository>`` / ``<pluginRepository>`` entry."""

    id: str
    url: str
    releases_enabled: bool = True
    snapshots_enabled: bool = False
    #: ``"warn"`` / ``"fail"`` / ``"ignore"`` / ``None`` (= default).
    #: Maven's default is ``"warn"`` (log the mismatch and continue);
    #: only ``"fail"`` is a hard checksum gate.
    checksum_policy: str | None = None
    #: Source section, so rules can distinguish runtime repos from
    #: plugin repos.
    section: str = "repositories"
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class MavenMirror:
    """One ``<mirror>`` entry from ``settings.xml``."""

    id: str
    url: str
    #: Maven's mirror-of pattern: ``central``, ``*``, ``external:*``,
    #: ``!internal,*``, etc. ``*`` and ``external:*`` are the patterns
    #: that route arbitrary external traffic through this mirror and
    #: are the supply-chain concern.
    mirror_of: str = ""
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class PomFile:
    """A parsed ``pom.xml`` (or ``settings.xml`` masquerading as one)."""

    path: str
    text: str
    #: ``True`` for a ``settings.xml`` payload (mirrors / servers /
    #: profiles); ``False`` for a project POM.
    is_settings: bool = False
    dependencies: tuple[MavenDependency, ...] = field(default_factory=tuple)
    repositories: tuple[MavenRepository, ...] = field(default_factory=tuple)
    mirrors: tuple[MavenMirror, ...] = field(default_factory=tuple)
    #: ``<properties>`` map for ``${...}`` substitution.
    properties: dict[str, str] = field(default_factory=dict)
    #: ``True`` when the XML parsed cleanly. ``False`` on malformed
    #: input; rules should short-circuit pass in that case so a
    #: parse error doesn't cascade into N false-positive findings.
    parsed_ok: bool = True


class MavenContext:
    """Loaded set of ``pom.xml`` / ``settings.xml`` documents."""

    def __init__(self, files: list[PomFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> MavenContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--maven-path {root} does not exist. Pass a pom.xml "
                "file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            names = MANIFEST_NAMES | SETTINGS_NAMES | GRADLE_NAMES
            candidates = sorted(
                p for p in root.rglob("*")
                if p.is_file()
                and p.name in names
                # Skip vendored copies / build outputs.
                and "target" not in p.parts
                and ".m2" not in p.parts
                and "build" not in p.parts
                and ".gradle" not in p.parts
            )
        files: list[PomFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            if f.name in GRADLE_NAMES:
                pf = _parse_gradle(str(f), text)
            else:
                pf = _parse_pom(str(f), text)
                if not pf.parsed_ok:
                    warnings.append(f"{f}: XML parse error")
                    skipped += 1
                    continue
            files.append(pf)
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class MavenBaseCheck(BaseCheck):
    """Base class for maven rule modules."""

    PROVIDER = "maven"

    def __init__(self, ctx: MavenContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: MavenContext = ctx


# ── Parser ─────────────────────────────────────────────────────────────


def _strip_ns(tag: str) -> str:
    return _POM_NS.sub("", tag)


def _findtext(elem: ET.Element, name: str, default: str = "") -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return default


def _find_child(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _findall_children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if _strip_ns(c.tag) == name]


def _bool_text(text: str, default: bool) -> bool:
    if not text:
        return default
    return text.strip().lower() == "true"


def _line_of(text: str, needle: str, start: int = 0) -> int:
    """1-based line of the first ``needle`` after byte offset ``start``."""
    idx = text.find(needle, start)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def _parse_pom(path: str, text: str) -> PomFile:
    """Parse a ``pom.xml`` / ``settings.xml`` body into a :class:`PomFile`.

    On a parse error returns a ``PomFile(parsed_ok=False)`` so the
    caller can skip with a warning. The text is preserved on the
    returned object so rules can run line-number lookups against the
    original source.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return PomFile(path=path, text=text, parsed_ok=False)

    root_tag = _strip_ns(root.tag)
    is_settings = root_tag == "settings"

    properties: dict[str, str] = {}
    props = _find_child(root, "properties")
    if props is not None:
        for child in props:
            key = _strip_ns(child.tag)
            value = (child.text or "").strip()
            if key:
                properties[key] = value

    dependencies: list[MavenDependency] = []
    repositories: list[MavenRepository] = []
    mirrors: list[MavenMirror] = []

    if not is_settings:
        # Top-level <dependencies>
        deps_node = _find_child(root, "dependencies")
        if deps_node is not None:
            for dep in _findall_children(deps_node, "dependency"):
                dependencies.append(_parse_dependency(dep, text, managed=False))
        # <dependencyManagement><dependencies>
        dm_node = _find_child(root, "dependencyManagement")
        if dm_node is not None:
            inner = _find_child(dm_node, "dependencies")
            if inner is not None:
                for dep in _findall_children(inner, "dependency"):
                    dependencies.append(_parse_dependency(dep, text, managed=True))
        # <repositories> and <pluginRepositories>
        for section in ("repositories", "pluginRepositories"):
            node = _find_child(root, section)
            if node is None:
                continue
            child_name = section[:-3] + "y"  # repositories -> repository
            for repo in _findall_children(node, child_name):
                repositories.append(_parse_repository(repo, text, section=section))
        # <distributionManagement> may carry <repository> + <snapshotRepository>
        dist = _find_child(root, "distributionManagement")
        if dist is not None:
            for tag in ("repository", "snapshotRepository"):
                node = _find_child(dist, tag)
                if node is not None:
                    repositories.append(
                        _parse_repository(node, text, section="distributionManagement"),
                    )

    # settings.xml: <mirrors><mirror>
    if is_settings:
        mirrors_node = _find_child(root, "mirrors")
        if mirrors_node is not None:
            for m in _findall_children(mirrors_node, "mirror"):
                mirrors.append(_parse_mirror(m, text))

    return PomFile(
        path=path,
        text=text,
        is_settings=is_settings,
        dependencies=tuple(dependencies),
        repositories=tuple(repositories),
        mirrors=tuple(mirrors),
        properties=properties,
        parsed_ok=True,
    )


def _parse_dependency(
    elem: ET.Element, text: str, *, managed: bool,
) -> MavenDependency:
    group_id = _findtext(elem, "groupId")
    artifact_id = _findtext(elem, "artifactId")
    version_raw = _findtext(elem, "version")
    version: str | None = version_raw if version_raw else None
    scope = _findtext(elem, "scope") or "compile"
    line_no = _line_of(text, f"<artifactId>{artifact_id}</artifactId>")
    return MavenDependency(
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        scope=scope,
        managed=managed,
        line_no=line_no,
    )


def _parse_repository(
    elem: ET.Element, text: str, *, section: str,
) -> MavenRepository:
    repo_id = _findtext(elem, "id")
    url = _findtext(elem, "url")
    releases = _find_child(elem, "releases")
    snapshots = _find_child(elem, "snapshots")
    releases_enabled = (
        _bool_text(_findtext(releases, "enabled"), default=True)
        if releases is not None else True
    )
    snapshots_enabled = (
        _bool_text(_findtext(snapshots, "enabled"), default=False)
        if snapshots is not None else False
    )
    # Checksum policy may be declared on either <releases> or
    # <snapshots>; rules care about the most permissive value.
    policies: list[str] = []
    for node in (releases, snapshots):
        if node is None:
            continue
        cp = _findtext(node, "checksumPolicy")
        if cp:
            policies.append(cp.strip().lower())
    checksum_policy: str | None
    if "ignore" in policies:
        checksum_policy = "ignore"
    elif "warn" in policies:
        checksum_policy = "warn"
    elif "fail" in policies:
        checksum_policy = "fail"
    else:
        checksum_policy = None
    line_no = _line_of(text, f"<id>{repo_id}</id>") if repo_id else 1
    return MavenRepository(
        id=repo_id,
        url=url,
        releases_enabled=releases_enabled,
        snapshots_enabled=snapshots_enabled,
        checksum_policy=checksum_policy,
        section=section,
        line_no=line_no,
    )


def _parse_mirror(elem: ET.Element, text: str) -> MavenMirror:
    mirror_id = _findtext(elem, "id")
    url = _findtext(elem, "url")
    mirror_of = _findtext(elem, "mirrorOf")
    line_no = _line_of(text, f"<id>{mirror_id}</id>") if mirror_id else 1
    return MavenMirror(
        id=mirror_id, url=url, mirror_of=mirror_of, line_no=line_no,
    )


# ── Gradle parser ──────────────────────────────────────────────────────


# A Maven coordinate inside a quoted string:
#   "org.apache.commons:commons-text:1.10.0"
#   'org.apache.logging.log4j:log4j-core:2.14.1'
# Captures group:artifact:version. Trailing ``:classifier`` /
# ``@type`` (sources, javadoc, war) is consumed but discarded so the
# version stays clean. The version body accepts letters, digits,
# dots, hyphens, underscores, plus ``+`` and ``[``/``]``/``(``/``)``
# / ``,`` so MVN-001 still sees the floating-range shape and flags
# it; ``${prop}`` is similarly preserved.
_GRADLE_COORD_RE = re.compile(
    r"""(?P<q>['"])
        (?P<group>[\w.+-]+)
        :
        (?P<artifact>[\w.+-]+)
        :
        (?P<version>[\w.+\-${}\[\](),]+)
        (?:[:@][\w-]+)?
        (?P=q)
    """,
    re.VERBOSE,
)

# Map-form dep declaration:
#   group: 'X', name: 'Y', version: 'Z'
#   group = "X", name = "Y", version = "Z"   (Kotlin DSL)
# All three fields are required; order-insensitive within the
# matched window. Captures group / artifact / version separately.
_GRADLE_MAP_DEP_RE = re.compile(
    r"""group\s*[:=]\s*(?P<gq>['"])(?P<group>[\w.+-]+)(?P=gq)
        \s*,?\s*
        name\s*[:=]\s*(?P<aq>['"])(?P<artifact>[\w.+-]+)(?P=aq)
        \s*,?\s*
        version\s*[:=]\s*(?P<vq>['"])(?P<version>[\w.+\-${}\[\](),]+)(?P=vq)
    """,
    re.VERBOSE,
)

# Maven repository URL inside a ``maven { ... }`` block. Three real-
# world shapes:
#   maven { url 'http://example.com/repo' }              (Groovy)
#   maven { url = 'http://example.com/repo' }
#   maven { url = uri("http://example.com/repo") }       (Kotlin DSL)
#   maven { setUrl("http://example.com/repo") }
# We match ``url[\s=]+(uri\()?(['"])URL\2\)?`` inside a ``maven``
# block; the trailing optional ``)`` from the ``uri(...)`` wrapper
# is allowed but not required.
_GRADLE_MAVEN_URL_RE = re.compile(
    r"""maven\s*[({]
        [^}]*?
        (?:url\s*=?\s*|setUrl\s*\(\s*)
        (?:uri\s*\(\s*)?
        (?P<q>['"])
        (?P<url>[^\s'"]+)
        (?P=q)
    """,
    re.VERBOSE | re.DOTALL,
)

# Single-arg ``maven("URL")`` shorthand. Some Gradle Kotlin scripts
# pass the URL directly as the function argument instead of inside a
# block.
_GRADLE_MAVEN_SHORT_RE = re.compile(
    r"""maven\s*\(\s*
        (?P<q>['"])
        (?P<url>[^\s'"]+)
        (?P=q)
        \s*\)
    """,
    re.VERBOSE,
)


def _line_at(text: str, offset: int) -> int:
    """1-based line number for a byte offset into *text*."""
    if offset < 0:
        return 1
    return text[:offset].count("\n") + 1


def _parse_gradle(path: str, text: str) -> PomFile:
    """Parse a ``build.gradle`` / ``build.gradle.kts`` body.

    Returns a :class:`PomFile` whose ``dependencies`` carry every
    matched coordinate + map-form dep (all marked ``managed=False``
    since Gradle has no direct analog of Maven's
    ``<dependencyManagement>`` lift-out — version catalogs / BOMs
    are a follow-up), and whose ``repositories`` carry every
    ``maven { url ... }`` URL found in the file. Built-in repo
    shorthand (``mavenCentral()``, ``google()``, ``gradlePluginPortal()``)
    is omitted from ``repositories`` because the rule pack doesn't
    flag them and their URLs are well-known.

    ``parsed_ok`` is always True: the regex extractor never fails,
    a file with no matches simply returns an empty PomFile.
    """
    dependencies: list[MavenDependency] = []
    repositories: list[MavenRepository] = []
    seen_coords: set[tuple[str, str, str | None]] = set()
    seen_urls: set[str] = set()

    for m in _GRADLE_COORD_RE.finditer(text):
        coord = (
            m.group("group"), m.group("artifact"), m.group("version"),
        )
        if coord in seen_coords:
            continue
        seen_coords.add(coord)
        dependencies.append(MavenDependency(
            group_id=coord[0],
            artifact_id=coord[1],
            version=coord[2],
            scope="compile",
            managed=False,
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAP_DEP_RE.finditer(text):
        coord = (
            m.group("group"), m.group("artifact"), m.group("version"),
        )
        if coord in seen_coords:
            continue
        seen_coords.add(coord)
        dependencies.append(MavenDependency(
            group_id=coord[0],
            artifact_id=coord[1],
            version=coord[2],
            scope="compile",
            managed=False,
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAVEN_URL_RE.finditer(text):
        url = m.group("url")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        repositories.append(MavenRepository(
            id="",
            url=url,
            releases_enabled=True,
            snapshots_enabled=False,
            checksum_policy=None,
            section="repositories",
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAVEN_SHORT_RE.finditer(text):
        url = m.group("url")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        repositories.append(MavenRepository(
            id="",
            url=url,
            releases_enabled=True,
            snapshots_enabled=False,
            checksum_policy=None,
            section="repositories",
            line_no=_line_at(text, m.start()),
        ))

    return PomFile(
        path=path,
        text=text,
        is_settings=False,
        dependencies=tuple(dependencies),
        repositories=tuple(repositories),
        mirrors=(),
        properties={},
        parsed_ok=True,
    )


# ── Helpers shared by multiple rule modules ────────────────────────────


def resolve_version(version: str, properties: dict[str, str]) -> str:
    """Expand a single ``${prop}`` reference using the POM's properties.

    Maven supports nested substitution, but a single level handles
    the overwhelming majority of real-world POMs and keeps the rule
    pack deterministic. Returns the unresolved literal when the
    referenced property isn't declared (so the rule sees the raw
    ``${...}`` form and can decide how to handle it).
    """
    v = version.strip()
    if not (v.startswith("${") and v.endswith("}")):
        return v
    key = v[2:-1]
    return properties.get(key, v)


def iter_real_dependencies(pom: PomFile) -> list[MavenDependency]:
    """Return every non-managed dependency entry."""
    return [d for d in pom.dependencies if not d.managed]


__all__ = [
    "GRADLE_NAMES",
    "MANIFEST_NAMES",
    "MavenBaseCheck",
    "MavenContext",
    "MavenDependency",
    "MavenMirror",
    "MavenRepository",
    "PomFile",
    "SETTINGS_NAMES",
    "iter_real_dependencies",
    "resolve_version",
]
